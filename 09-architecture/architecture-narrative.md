# Architecture Narrative (Modules 10 and 11)

- **HLD:** [`hld-diagram.svg`](hld-diagram.svg) ([PNG](hld-diagram.png)): system context, for a governance audience.
- **LLD:** [`lld-diagram.svg`](lld-diagram.svg) ([PNG](lld-diagram.png)): one workload's path from citizen request to database, at a level an engineer could build from.

Both are written as SVG code rather than exported from a drawing tool, so they diff cleanly in Git and render on GitHub.

`payments-api` in the LLD is a representative citizen-facing service from the programme scenario, not a kubernetes-goat workload: goat has no realistic path from ingress to a data store. The worked, tested NetworkPolicies are for goat's `internal-proxy` slice ([`fixed-manifests/networkpolicies.yaml`](../06-remediation/fixed-manifests/networkpolicies.yaml)); the policy names in the LLD table are their target-state equivalents.

## HLD: how to read it

Read it left to right: **how software gets in** (delivery zone), **where it runs** (production account), **where the evidence goes** (security account), and **who's outside** (internet).

| # | Flow | The security decision behind it |
|---|---|---|
| 1 | Engineers push to GitLab | People authenticate only through agency SSO (9). One identity, one place to revoke access. |
| 2 | CI builds, scans, signs and pushes to the registry | Every gate in Module 2 runs *before* an image exists in the registry. Signing uses a KMS key the runner never sees. |
| 3 | The cluster pulls approved changes from GitLab | **The key decision in the design.** CI never pushes into the cluster and holds no cluster credentials. The red dashed line is the path that *doesn't* exist. This removes the F-01 class of problem by design rather than by policing it. |
| 4 | The cluster pulls images by digest | Admission control refuses anything unsigned or from another registry. |
| 5 | Citizens → WAF + load balancer → services | One way in. No NodePorts, no public node IPs. |
| 6 | Services → data; secrets operator → vault | Data stays in private subnets; secrets are fetched at runtime and never stored in Git or images. |
| 7 | Logs and alerts → security account | Write-once storage in a separate account, so an attacker with `cluster-admin` can't erase the evidence. |
| 8 | Egress firewall → approved external APIs only | Default is no internet. Each allowed domain is a reviewed decision. |
| 9 | IdP → AWS / EKS for administrators | Short-lived roles, audited sessions; no SSH, no static keys. |

**Trust boundaries** (red): delivery zone, AWS organisation, EKS cluster, internet. **Environment boundaries** (grey): production account, security account, and non-production accounts that repeat the same pattern with separate keys and clusters. Non-production can never read production secrets or push to production registries.

## LLD: key decisions

| Area | Decision | Why |
|---|---|---|
| **Ingress** | ALB with `target-type: ip`, TLS terminated at the ALB and **re-encrypted** to the pod on 8443 using a cert-manager internal CA | Traffic inside the VPC is still encrypted end to end for a citizen-data service, without needing a mesh. |
| **Node group** | Bottlerocket AMI, IMDSv2 required with hop limit 1, no SSH, node role reduced to the worker and ECR pull-only policies; the VPC CNI gets its own IAM role (IRSA or Pod Identity), as AWS recommends | Bottlerocket is a minimal, read-only OS designed for containers, so there's less to harden for the CIS node checks (F-18). The hop limit is what stops chain C (F-09 → F-19). |
| **Pod** | PSA `restricted`, non-root, read-only filesystem, all capabilities dropped, seccomp `RuntimeDefault`, no SA token | Closes F-02, F-03, F-20, F-27 for this workload. |
| **Workload identity** | EKS **Pod Identity**: role `payments-api-prod` with exactly one permission, `rds-db:connect` for one DB user | The app needs no password at all for the database (IAM auth) and no other AWS access. |
| **Secrets** | ESO with a **per-namespace** SecretStore and role scoped to `/prod/payments/*`; mounted as files on tmpfs | Prevents cross-team secret reads (Module 5); files rotate without restarts. |
| **Encryption at rest** | Separate customer-managed KMS keys for etcd secrets, Secrets Manager, RDS, EBS and the signing key | Separate keys give separate blast radius and separate audit trails; key admins can't use keys. |
| **Network policy** | Default-deny in and out; the table on the LLD lists every allowed flow, with port and the policy name that allows it | Anything not in the table is dropped. That table *is* the review artefact for network changes. |
| **Data** | RDS: private subnets, SG allows 5432 only from the node group SG, `rds.force_ssl=1`, PITR, and a backup copy to the separate backup account in-region (a second-region copy only if residency allows, Module 12) | SG and NetworkPolicy together: SG says "which nodes", NetworkPolicy says "which pods on those nodes". |
| **Pipeline placement** | Runners in a separate CI VPC joined by Transit Gateway; the only route from the CI VPC into the workload VPC is the ECR endpoint (flow F) | The CI network has no route to the EKS API at all, which enforces flow 3 of the HLD at the network layer. |
| **Detection placement** | Falco and Fluent Bit as DaemonSets on every node; control-plane logs from EKS; GuardDuty alongside | Falco sees syscalls inside every pod on the node; audit logs see the API; GuardDuty adds AWS threat intel. All feed the security account. |
| **Admission placement** | PSA (built into the API server) plus Kyverno webhooks | PSA is built into the API server, so it keeps working if the Kyverno webhook is down or removed; changing a namespace's level needs RBAC on namespaces, which only the platform team holds. Kyverno adds the supply-chain checks PSA can't express. |

## Shared responsibility: where the line sits on EKS, AKS and GKE

On all three, the **provider** runs the control plane: API server, etcd, scheduler and controller manager, including their patching, availability, backups and the encryption of control-plane storage. On all three, **we** own everything that decides who gets in (identity mapping, RBAC), what runs (images, admission policy, Pod Security), what talks to what (NetworkPolicy, egress), secrets, workload cloud identity, whether audit logs are collected and kept, and when version upgrades happen within the support window.

The line moves in the details, and the differences matter for this programme:

| Area | EKS | AKS | GKE |
|---|---|---|---|
| Control-plane audit logs | Off until each log type is enabled (F-16) | Not collected until a diagnostic setting routes them (`kube-audit` / `kube-audit-admin`) | Admin Activity logs always on and can't be disabled; Data Access logs off by default |
| Worker node OS | Managed node groups: AWS publishes AMIs, we roll them out (EKS Auto Mode or Fargate moves node patching to AWS) | Node image auto-upgrade channel (`NodeImage` by default on new clusters) | Standard: node auto-upgrade on by default. Autopilot: Google manages nodes entirely |
| Default pod hardening | None beyond what we enforce | None beyond what we enforce | Autopilot blocks privileged pods by default; Standard doesn't |
| Secrets at rest | Envelope-encrypted by default with an AWS-owned key (1.28+); customer-managed key optional (F-23) | Encrypted at rest by the platform; KMS etcd encryption with our key optional | Encrypted at rest by default; application-layer secrets encryption with Cloud KMS optional |
| API endpoint | Public by default (F-15) | Public by default; private cluster or authorised IP ranges optional | External endpoint by default; private endpoint and authorised networks optional |
| NetworkPolicy enforcement | Must be turned on in the VPC CNI (F-12) | Policy engine chosen when the cluster is created | Enforced by Dataplane V2 |
| Control-plane SLA | Included | Only on the Standard or Premium tier; the Free tier has none | Included (higher for regional than zonal clusters) |

**Design rule that follows:** build the baseline to the *weakest* default on every row, so it holds on whichever cloud a cluster lands on. That means enforcing Pod Security ourselves even where Autopilot would, explicitly enabling and shipping audit logs on EKS and AKS, requiring a customer-managed key for secrets on all three, private endpoints everywhere, and AKS on the Standard tier for production.

## Alternatives considered and rejected

### 1. Push-based deployment with a tightly scoped CI identity (rejected)

The obvious fix for F-01 is to keep CI pushing to the cluster but with a namespace-scoped Role instead of `cluster-admin`. That's the *interim* state in [`ci-deployer-rbac.yaml`](../06-remediation/fixed-manifests/ci-deployer-rbac.yaml), and it's a big improvement.

**Why it's not the target:** it still means a system that runs untrusted code (every MR pipeline, every build dependency) has a network path and credentials to the production API server. Scoping limits the damage; it doesn't remove the path. It also leaves the cluster's actual state defined by "whatever the last pipeline did", so drift (a manual `kubectl edit` at 2 a.m.) goes unnoticed.

**GitOps pull instead:** the cluster pulls from Git, CI only writes a digest to a repo, and Argo CD reports any drift from Git. The cost is one more platform component (Argo CD) to run and secure, with its own RBAC kept tight through AppProjects. I think that cost is clearly worth it.

### 2. Separate EKS cluster for the COTS product (rejected for now)

Strongest isolation: a cluster of its own. Rejected because it doubles the platform footprint (control plane, add-ons, policies, upgrades, monitoring) for one workload. A dedicated tainted node group gives most of the isolation benefit, since the main risk is node-level escape and a separate node removes the neighbours. Revisit if the COTS product's risk acceptance is ever revoked and it still has to run.

### 3. Service mesh for in-cluster mTLS (deferred)

Covered in [Module 4 §6](../04-network-mesh/zero-trust-design.md#6-service-mesh-justified-here). In short: the Critical risks are elsewhere, the operational cost lands on a stretched team, and TLS re-encryption from the ALB covers the most sensitive flow. Explicit triggers for revisiting are listed there.

### 4. HashiCorp Vault as the secrets backend (deferred)

Covered in [Module 5 §3](../05-secrets-keys/secrets-architecture.md#3-recommendation). ESO keeps the backend swappable, so this decision can wait until AKS/GKE onboarding without rework.
