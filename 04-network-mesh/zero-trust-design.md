# Zero-Trust Networking & Service Mesh (Module 4)

## 1. Starting point

The default VPC CNI routes pod traffic but doesn't enforce `NetworkPolicy`, and the reference repo has none anyway (F-12). Every pod can reach every other pod, the node's metadata endpoint, and the internet. That flat network is the link in all three attack chains in Module 1.

## 2. Enforcement engine

| Option | For | Against |
|---|---|---|
| **VPC CNI native network policy** (eBPF agent, VPC CNI v1.14+) | AWS-supported add-on, a configuration flag on the existing CNI, no data-plane swap before go-live | Standard `NetworkPolicy` only: no FQDN rules, no L7, limited flow visibility |
| **Cilium** (chained or replacing VPC CNI) | FQDN egress, L7 policy, Hubble flow visibility, the same engine AKS and GKE use underneath | Data-plane change on live clusters right before a migration wave; another critical component to run and upgrade |
| **Calico** (policy-only on VPC CNI) | Mature, `GlobalNetworkPolicy` for cluster-wide defaults | Same extra-component cost, smaller payoff than Cilium |

**Recommendation: VPC CNI native policy now, written only against the standard `networking.k8s.io/v1` API.** It's the smallest change that closes F-12 before go-live, and standard policies run unchanged on AKS and GKE. Domain-level egress control goes in the VPC egress layer (§5), not in the CNI. Cilium becomes worth it if we later need L7 policy or a mesh replacement (§6).

## 3. Default-deny baseline

Every application namespace gets three policies at creation, from the namespace template (not from app teams):

```yaml
# 1. Deny everything in and out
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny-all }
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
# 2. Allow DNS to CoreDNS only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: allow-dns }
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } }
          podSelector: { matchLabels: { k8s-app: kube-dns } }
      ports: [{ protocol: UDP, port: 53 }, { protocol: TCP, port: 53 }]
---
# 3. Quarantine: pre-staged for incident response (Module 3, Phase 2)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: quarantine }
spec:
  podSelector: { matchLabels: { quarantine: "true" } }
  policyTypes: [Ingress, Egress]
```

Teams then add *allow* policies per flow, in their own repo next to the workload. Worked example for the `internal-proxy` slice: [`06-remediation/fixed-manifests/networkpolicies.yaml`](../06-remediation/fixed-manifests/networkpolicies.yaml).

**Rollout without breaking production:** enable the policy agent → apply allow policies built from two weeks of VPC flow logs → apply default-deny one namespace at a time, lowest-risk first, with the owning team on hand → watch for drops in the agent's logs for 48h. A rollback is deleting one policy.

## 4. Requesting and reviewing exceptions

| Flow type | Who approves | Mechanism |
|---|---|---|
| Within a namespace | Owning team | MR to the app repo; standard review |
| Cross-namespace | Both namespace owners | MR; CODEOWNERS on the policy file includes the destination team |
| To a data store (RDS, ElastiCache, Redis) | Data owner + platform | MR; must name the specific client pods by label, never `podSelector: {}` |
| To the internet | Platform security | MR adding the domain to the egress allowlist (§5) with justification and data classification; Conftest blocks `ipBlock: 0.0.0.0/0` in app repos |
| Temporary (debugging, migration) | Platform security | Same, plus an `expires` annotation; a nightly job lists expired policies and the owner gets a ticket |

The request template asks five things: source, destination, port/protocol, why, and what data crosses it. Most requests are approved in the MR within a day, so the process doesn't become a reason for teams to request wide-open rules.

## 5. Ingress and egress

**Ingress (north-south in):**
- Internet → **AWS WAF** (managed rule groups plus rate limiting) → **ALB** via the AWS Load Balancer Controller → pod IPs (`target-type: ip`). TLS 1.2+ with ACM certificates; HTTP redirects to HTTPS.
- Internal-only services use `internal` ALBs in private subnets.
- **No NodePort services** (F-10), enforced by Kyverno. Node security groups accept traffic only from the ALB security group and the control plane.
- Pod-level: the app's NetworkPolicy allows ingress only from the ALB subnets' CIDRs on the container port.

**Egress (north-south out):**
- **Default: no internet.** Default-deny already blocks it.
- Pods that need the internet (e.g. a payment provider API) get an allow policy to `0.0.0.0/0` *except* RFC 1918 and link-local ranges, and their traffic leaves through NAT → **AWS Network Firewall** with a **domain allowlist** (TLS SNI / HTTP Host inspection) per environment. That's where the domain control lives: CNI-agnostic and the same pattern in every cloud.
- **Metadata endpoint:** IMDSv2 required with hop limit 1 on every node group (stops pods reaching it at all, F-09), plus `169.254.169.254/32` in every `except` list as defence in depth.
- VPC endpoints (ECR, S3, STS, Secrets Manager, KMS, CloudWatch) so AWS API traffic never crosses the internet path.

## 6. Service mesh: justified here?

The panel brief asks for both sides. Here they are for *this* estate: about 18 EKS workloads, mostly stateless citizen-facing services, a team that containerised in a hurry, one COTS image we can't modify, and a hard go-live date.

**The case for a mesh**
- **mTLS between every service**, with identity tied to the workload rather than an IP. If the programme's standard requires encryption in transit *inside* the cluster, a mesh is the cleanest way to meet it uniformly.
- **L7 authorization:** "only the `orders` service account may call `POST /payments`", which NetworkPolicy can't express.
- Consistent telemetry (who called whom, latency, error rate) without changing application code.
- Uniform security across EKS, AKS and GKE once they exist.

**The case against, right now**
- **Operational load lands on the team least able to absorb it.** Istio upgrades, CRDs, certificate rotation and sidecar injection failures are a real support burden. The current team already has 29 findings to close.
- **The COTS image:** sidecar injection changes the pod; the vendor may treat that as unsupported, and some COTS software breaks behind a transparent proxy.
- **Latency and cost:** sidecars add per-hop latency (typically low single-digit milliseconds at p99) and CPU/memory on every pod. Bearable, but not free for spiky citizen-facing traffic.
- **The biggest risks are elsewhere.** None of the Critical findings is fixed by a mesh. RBAC, admission, privileged pods and secrets are. A mesh before those is effort spent in the wrong order.
- **Encryption in transit is partly covered already:** traffic between supported Nitro instances in the VPC is encrypted at the hardware layer by AWS, TLS terminates at the ALB and is re-established to pods for sensitive services, and data-store connections use TLS.

**Recommendation: no mesh for go-live. Decide again in two quarters** against three explicit triggers:
1. The compliance standard, once we can read it, requires workload-identity mTLS inside the cluster; or
2. East-west service-to-service calls grow to where NetworkPolicy's IP/port rules are no longer a meaningful control (rough threshold: more than about 30 services calling each other); or
3. AKS/GKE onboarding needs one uniform in-cluster encryption story across clouds.

**If a mesh is adopted:** **Istio ambient mode** (GA since Istio 1.24). It uses no sidecars: a per-node `ztunnel` gives L4 mTLS and identity, and an optional per-namespace `waypoint` proxy adds L7 policy only where needed. That removes the COTS sidecar problem and most of the per-pod overhead. (Linkerd is simpler, but its stable releases have required a commercial licence for production since 2024, which is a procurement question for a government programme.)

- `PeerAuthentication` mode `STRICT` mesh-wide; plaintext only for named exceptions during migration.
- `AuthorizationPolicy` deny-by-default per namespace; allows written against SPIFFE identities (`cluster.local/ns/<ns>/sa/<sa>`), so they only work if F-27 is fixed (one SA per workload).
- NetworkPolicy stays: the mesh controls *who may call what*, NetworkPolicy keeps controlling *what can reach what*. Defence in depth, and a fallback if the mesh fails open.
- Operational cost to plan for: an owning team, a quarterly upgrade cadence (Istio supports roughly the last three minor versions), dashboards for certificate expiry and ztunnel health, and a runbook for "mesh down".

## 7. Across EKS, AKS and GKE

| | EKS | AKS | GKE |
|---|---|---|---|
| NetworkPolicy enforcement | VPC CNI policy agent | Azure CNI powered by Cilium | Dataplane V2 (Cilium-based) |
| Policies we write | standard `networking.k8s.io/v1` | same files | same files |
| Domain egress control | AWS Network Firewall | Azure Firewall | Cloud NGFW / Secure Web Proxy |
| Metadata endpoint protection | IMDSv2 hop limit 1 | Block `169.254.169.254` via policy; Workload Identity | GKE Metadata Server (Workload Identity) |
| Ingress + WAF | ALB + AWS WAF | Application Gateway for Containers + WAF | GKE Gateway + Cloud Armor |

The policies themselves move unchanged. What changes per cloud is the egress firewall and the ingress/WAF product, both provisioned in Terraform modules per cloud behind the same interface ("allow these domains for this environment").
