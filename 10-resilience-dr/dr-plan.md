# Resilience, Backup & Disaster Recovery (Module 12)

## 1. What we're protecting against

| Scenario | Example | Likelihood |
|---|---|---|
| Pod / node failure | Node hardware fault, OOM, bad deploy | Weekly; routine |
| Availability Zone failure | Power or network loss in one AZ | Rare, but has happened |
| **Cluster loss** | Failed upgrade, broken admission webhook that blocks all pods, accidental deletion, **compromise** (Module 3: "replace, don't clean") | Rare, and the one most teams haven't rehearsed |
| Region loss | Whole AWS region unavailable | Very rare |
| Data corruption / ransomware | Bad migration, malicious delete | Rare, high impact |

A security incident is a DR trigger. If the cluster is compromised, the safest recovery is to rebuild it from known-good sources, which only works if the rebuild has been practised.

## 2. Control plane and etcd

On EKS, **AWS runs etcd** and backs it up; we have no direct access to etcd and can't restore it ourselves. That's the managed shared-responsibility line (and it's the same on AKS and GKE). So "control-plane backup" for us means making sure we can **recreate** the control plane's *contents*, not restore its database:

| Layer | Source of truth | Backup |
|---|---|---|
| Cluster, node groups, IAM, KMS, VPC | Terraform in GitLab | Git (plus GitLab's own backup) |
| Platform add-ons and policies (Kyverno, Falco, ESO, Argo CD, NetworkPolicies, RBAC, PSA labels) | GitOps repo | Git |
| Applications | Env repo (image digests) + app repos | Git; images in ECR |
| Secrets | AWS Secrets Manager | Secrets Manager (+ replica, §4) |
| Anything created in-cluster and not in Git | Shouldn't exist (Argo CD drift detection) | **Velero** API-level backup as a safety net |

**Velero backups** (every 6 hours, 30-day retention):
- Captures cluster objects and, through CSI snapshots, persistent volumes. It's open source and works the same on AKS and GKE.
- **Secrets are excluded** from the backup (`--exclude-resources secrets`). They're re-created by ESO from Secrets Manager, so backing them up would only create a second, less protected copy of every credential.
- Stored in an S3 bucket in a **separate backup account**, encrypted with a dedicated KMS key (`backup-prod`), **Object Lock in compliance mode** (30 days) so backups can't be deleted or altered, even by an administrator or an attacker with `cluster-admin`.
- **Access:** Velero's role can *write* backups but not delete them. Restore uses a separate role, available only through break-glass with two-person approval, and every use alarms to the security team.

## 3. Stateful workloads

The design keeps state *out* of the cluster wherever possible. Databases are RDS, caches are ElastiCache. That makes the cluster itself disposable, which is what makes "rebuild instead of clean" realistic.

| Data | Protection | Restore test |
|---|---|---|
| RDS (e.g. payments DB) | Multi-AZ (synchronous standby); automated backups with **point-in-time recovery**, 35 days; daily snapshots copied by AWS Backup to the backup account (vault lock); KMS `rds-prod` | **Monthly, automated:** restore latest snapshot into an isolated account, run integrity checks (row counts, checksums on key tables, app smoke test), record restore time, destroy |
| EBS persistent volumes (any StatefulSets that remain) | Velero CSI snapshots every 6 hours; AWS Backup daily copy to backup account | **Quarterly:** as part of the cluster rebuild drill |
| ElastiCache / Redis | Treated as rebuildable cache; daily snapshot only where the app depends on warm state | Quarterly |
| ECR images | Immutable tags; replication to the backup account | Covered by rebuild drill |
| Logs and forensic evidence | Already in the security account, Object Lock | n/a |

**Why monthly restore tests:** a backup that has never been restored is an assumption, not a control. The restore time from each test is the *measured* RTO input, and it goes on the resilience dashboard next to the target.

## 4. Named RTO / RPO: `payments-api` (citizen payments)

`payments-api` is the representative citizen-facing service from the LLD (a scenario workload, not a kubernetes-goat one), chosen because it has the strictest recovery needs: money and a database.

| Failure | **RPO** | **RTO** | What the architecture needs to meet it |
|---|---|---|---|
| Pod or node | 0 | < 1 min | ≥ 3 replicas, PDB `minAvailable: 2`, readiness probes, topology spread across nodes |
| One AZ | **0** | **< 5 min** | Node group across 3 AZs with topology spread; RDS Multi-AZ (synchronous, automatic failover typically 1–2 min); ALB across AZs |
| Cluster loss (incl. compromise) | **≤ 5 min** (DB is outside the cluster and unaffected) | **≤ 2 hours** | Cluster fully reproducible from Terraform + GitOps (§5); rebuild runbook rehearsed quarterly; DB and secrets outside the cluster; DNS cut-over via Route 53 |
| Data corruption | **≤ 5 min** | **≤ 4 hours** | RDS PITR (transaction logs shipped about every 5 minutes); tested restore procedure; app able to point at a restored instance through config in Git |
| Region loss | see below | see below | |

**Region loss is a data-residency decision first, not a technical one.** Singapore has one AWS region. A cross-region standby would put citizen data outside Singapore, which some data classifications won't allow. So:
- **If residency rules allow an approved second region:** RPO ≈ 1 minute and RTO ≈ 8 hours, using a cross-region RDS read replica, ECR and Secrets Manager replication, multi-region KMS keys, and a pilot-light cluster built by Terraform on demand. Cost is roughly the replica plus storage.
- **If they don't:** resilience stops at three AZs in one region. A full-region outage is then a **documented, accepted risk** owned by the system owner, with a manual "citizens are told to use the alternative channel" business continuity plan. That's a legitimate answer, as long as it's written down and signed rather than assumed.

I'd put this choice to the panel explicitly rather than pick for them, because it depends on the classification of the payments data.

## 5. Rebuilding a cluster from scratch: what comes back from Git and what doesn't

**Fully recoverable from Git + Terraform (target state from the HLD and LLD):**
- VPC, subnets, endpoints, security groups, EKS cluster, node groups, launch templates (IMDSv2, Bottlerocket)
- IAM roles and **Pod Identity associations**. This is a reason to prefer Pod Identity over IRSA: IRSA trust policies are tied to the cluster's OIDC issuer URL, which **changes on a rebuild**, so every IRSA role's trust policy would need updating. Pod Identity associations are just recreated by Terraform against the new cluster.
- Namespaces, PSA labels, RBAC, NetworkPolicies, ResourceQuotas, Kyverno policies, Falco rules, ESO `SecretStore`s and `ExternalSecret`s, Argo CD projects and apps
- Every workload, at the exact signed digest it was running

**Lives outside the cluster, survives untouched:** RDS data, Secrets Manager values, KMS keys, ECR images, logs and evidence.

**Needs explicit handling (where rebuilds usually fail):**

| Item | Risk on rebuild | Mitigation |
|---|---|---|
| Argo CD's Git credentials | Chicken-and-egg: Argo needs them to pull everything else | Stored in Secrets Manager; Terraform bootstrap injects them as the one manual-free first step |
| Internal CA (cert-manager) private key | If the CA key lives only as a K8s Secret, a rebuild issues a new CA and ALB → pod TLS breaks | Use **AWS Private CA** (or store the CA in Secrets Manager); cert-manager issues from it |
| Load balancer DNS names | New ALBs get new hostnames | Route 53 alias records managed by ExternalDNS / Terraform, not typed by hand |
| Persistent volumes | Not in Git | Restore from Velero / AWS Backup snapshots |
| Anything changed by hand in the cluster | Lost | That's the intended outcome. Argo CD drift alerts mean it should never have been there. Anything still needed is found in the Velero backup |
| Runtime state (Kyverno reports, Falco buffers) | Lost | Not needed; history is in the log archive |

**Rebuild sequence and expected timing** (to be confirmed by the first drill):

1. `terraform apply` for cluster + node groups: ~20–25 min
2. Bootstrap: Argo CD + its Git credential: ~5 min
3. Argo CD syncs platform layer (Kyverno, Falco, ESO, policies, namespaces): ~10 min
4. Argo CD syncs applications; ESO re-creates secrets; PV restores where needed: ~15 min
5. Smoke tests, then Route 53 cut-over: ~15 min

Roughly **60–90 minutes**, inside the 2-hour RTO with margin. **After a compromise**, add one step before (5): verify every running digest's Cosign signature and compare the env repo with the last known-good commit, so we don't rebuild the attacker's changes along with everything else.

## 6. Drills

| Drill | Cadence | Pass criteria |
|---|---|---|
| RDS restore to isolated account | Monthly, automated | Integrity checks pass; restore time recorded |
| Full non-prod cluster rebuild from nothing | Quarterly | Under 2 hours; zero manual steps beyond the documented runbook |
| AZ failure simulation (cordon and drain one AZ's nodes; RDS failover) | Twice a year | No user-visible errors beyond in-flight requests |
| Combined security + DR game day ("cluster compromised, rebuild it") | Yearly | Module 3 evidence captured *and* service restored within RTO |

Each drill produces a short report. Any manual step discovered goes back into Terraform or the runbook. The goal is a rebuild boring enough that the team trusts it at 3 a.m.
