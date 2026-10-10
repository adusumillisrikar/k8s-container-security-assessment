# Severity Methodology

## Why not just use CVSS

Most findings in this review are misconfigurations, not CVEs. CVSS scores a flaw in isolation. The programme needs a different answer: "how far could this go in *our* estate, and how easy is it to reach?" A privileged pod is a nuisance in a sandbox and a cluster takeover on a shared EKS node. So severity is scored on **blast radius** and **reachability**, with any adjustment written down next to the finding.

## Scoring

**Impact (I): how far it goes if exploited**

| I | Meaning | Example |
|---|---|---|
| 4 | Cluster or estate-wide: cluster-admin, node root (every pod on the node plus the node's cloud identity), control plane | `cluster-admin` binding, privileged pod with host `/` mounted |
| 3 | Several workloads, a whole namespace, or credentials that work outside the cluster | Namespace-wide secret read, node IAM role credentials |
| 2 | One workload's confidentiality, integrity or availability | Missing limits on one deployment |
| 1 | Hygiene, with no direct path to harm | Deprecated API version |

**Exploitability (E): who can reach it today**

| E | Meaning |
|---|---|
| 4 | Unauthenticated from outside the cluster (internet, load balancer, NodePort, public registry) |
| 3 | Any pod in the cluster (flat network), anyone who can read the repo or pull the image, or anyone who can trigger a CI job |
| 2 | Needs a foothold in a specific pod or namespace, or valid but limited cluster credentials |
| 1 | Needs privileged insider access or several unlikely preconditions |

**Score = I × E**

| Score | Severity |
|---|---|
| 12–16 | Critical |
| 8–11 | High |
| 4–7 | Medium |
| 1–3 | Low |

## Adjustments (one tier at most, always explained)

- **Up one tier** when a finding is a detective-control gap that would hide other Critical/High findings (e.g. no audit log), or when the exact pattern has been actively exploited in the wild recently (e.g. mutable image tags, after the 2026 Trivy and KICS Docker Hub compromises).
- **Down one tier** when a compensating control already in place materially limits the finding (e.g. AWS already encrypts the etcd volume, so missing envelope encryption is a key-custody problem more than an exposure).

## Fix window

Severity says how bad it is. Fix window says what happens before go-live. They're related but not identical, because some High findings are cheap to close and some Medium ones need a platform change.

| Window | Meaning |
|---|---|
| **P0: block go-live** | Must be fixed and evidenced before the migration wave. No risk acceptance offered. |
| **P1: fix or formally accept** | Fix before go-live, or go live with a compensating control and a signed risk acceptance from the ITSO-equivalent, with a dated plan. |
| **P2: 90 days post go-live** | Tracked in the backlog with an owner; reviewed at the monthly risk forum. |
| **P3: backlog** | Hygiene, picked up opportunistically or with the next platform upgrade. |

## Effort

Effort is in engineer-days (ed) for one engineer who knows the workload, including testing and evidence capture. It does not include change-board lead time.

## Chains matter more than single findings

Several Medium/High findings combine into a Critical path, e.g. an SSRF plus no NetworkPolicy plus pods able to reach the node's cloud credentials. The register rates each finding on its own, then lists the attack chains separately so the panel can see why some fixes are sequenced first.
