# Findings Register (Module 1)

**Scope:** `madhuakula/kubernetes-goat` at `723a0db` (manifests, Dockerfiles, app code, AWS CDK lab stack) and `bridgecrewio/terragoat` at `729f8da` (`terraform/aws/eks.tf`, `ecr.tf` only, for provisioning-level findings that kubernetes-goat doesn't contain).

**How to read it:** severity uses Impact × Exploitability ([severity-methodology.md](severity-methodology.md)). "Window" is the go-live decision: P0 block, P1 fix or formally accept, P2 within 90 days, P3 backlog. Effort is in engineer-days (ed).

**Assumption:** the goat workloads are treated as if they were programme workloads on a shared EKS cluster. That's the point of the exercise. Where a finding only exists because goat is a training lab, I say so.

**Evidence:** every finding was found by manual review first. Scanner output that confirms it is in [`evidence/`](evidence/); see the coverage note at the bottom for what scanners caught and what they missed.

**Secret handling:** the reference repo contains fake credentials. This register cites their *location* only and never reproduces a value, so this repo stays clean under a secret scan.

Location links: `kg:` = [kubernetes-goat@723a0db](https://github.com/madhuakula/kubernetes-goat/tree/723a0db478f050d173d23b4ce5044b65bce0bdd0), `tg:` = [terragoat@729f8da](https://github.com/bridgecrewio/terragoat/tree/729f8da62c6a85ce4af5ad3d123de97776d954c4).

---

## Summary

| ID | Finding | Sev | I×E | Domain | Window | Effort |
|---|---|---|---|---|---|---|
| F-01 | `cluster-admin` bound to a service account (the audit finding pattern) | **Critical** | 4×3 | RBAC | P0 | 1 ed |
| F-02 | `system-monitor`: privileged, hostPID/IPC, host `/` mounted, unauthenticated writable web shell | **Critical** | 4×3 | Pod security | P0 | 1 ed |
| F-03 | `health-check`: command injection in a privileged pod holding the container runtime socket | **Critical** | 4×3 | Pod security / AppSec | P0 | 2 ed |
| F-04 | Helm chart grants `*/*/*` ClusterRole to the `default` SA in `default` | **Critical** | 4×3 | RBAC | P0 | 0.5 ed |
| F-05 | Secrets baked into container images (ENV, deleted-but-present layer, shipped `.git`) | **High** | 3×3 | Secrets / Supply chain | P0 | 2 ed |
| F-06 | No cluster-wide admission control; the one Kyverno policy targets a namespace that doesn't exist | **High** | 4×2 | Admission control | P0 | 3 ed |
| F-07 | Privileged DaemonSet runs an attack-toolkit image on every node with a mutable tag | **High** | 4×2 | Pod security / Supply chain | P0 | 0.5 ed |
| F-08 | Namespace-wide wildcard read Role (includes Secrets) bound to a pod running a web shell | **High** | 3×3 | RBAC | P0 | 1 ed |
| F-09 | SSRF in `internal-api` reaches internal metadata service; on EKS, the node's IAM credentials | **High** | 3×3 | Workload identity / AppSec | P1 | 2 ed |
| F-10 | Flask debug mode on `0.0.0.0`, exposed on every node via NodePort | **High** | 2×4 | AppSec / Exposure | P0 | 0.5 ed |
| F-11 | Secret values committed to Git as base64 manifests; injected as env vars | **High** | 3×3 | Secrets | P1 | 2 ed |
| F-12 | No NetworkPolicy anywhere; flat pod network (and VPC CNI wouldn't enforce one today) | **High** | 3×3 | Network | P1 | 5 ed |
| F-13 | Unauthenticated Redis holding sensitive data, reachable cluster-wide | **High** | 3×3 | Data / Network | P1 | 1 ed |
| F-14 | Unauthenticated, plaintext in-cluster image registry (pull *and* push) | **High** | 3×3 | Supply chain | P1 | 1 ed |
| F-15 | EKS API endpoint public with no CIDR restriction | **High** | 4×2 | Cluster exposure | P1 | 1 ed |
| F-16 | EKS control-plane / audit logging disabled | **High** | 3×2 ↑ | Logging | P0 | 0.5 ed |
| F-17 | Image references unpinned (`latest` / no tag), personal Docker Hub namespace, no signatures | **High** | 3×2 ↑ | Supply chain | P1 | 3 ed |
| F-18 | Lab host on EOL Ubuntu 16.04, IMDS defaults, SSH key access, unverified binary download | **High** | 3×3 | Node / OS hardening | P1 | 2 ed |
| F-19 | No workload identity (no OIDC provider / IRSA / Pod Identity); pods inherit node role | Medium | 3×2 | Workload identity | P1 | 3 ed |
| F-20 | Missing pod `securityContext` baseline across all workloads | Medium | 2×2 | Pod security | P1 | 3 ed |
| F-21 | No resource limits on several workloads; no ResourceQuota / LimitRange | Medium | 2×3 | Resource governance | P1 | 2 ed |
| F-22 | Node subnets auto-assign public IPs | Medium | 3×2 | Network / Exposure | P1 | 2 ed |
| F-23 | No envelope encryption of Secrets with a customer-managed KMS key | Medium | 3×1 ↑ | Encryption | P1 | 0.5 ed |
| F-24 | Dormant fetch-and-execute script inside `batch-check` image | Medium | 3×2 | Supply chain / Runtime | P1 | 0.5 ed |
| F-25 | ECR repository: mutable tags, no scan-on-push, images pushed from a laptop | Medium | 3×2 | Supply chain | P1 | 1 ed |
| F-26 | Base image hygiene: compilers in runtime images, EOL Redis 6, unverified downloads | Medium | 2×2 | Image hygiene | P2 | 3 ed |
| F-27 | Most workloads in `default` namespace on the default SA with auto-mounted tokens | Medium | 2×3 | RBAC / Tenancy | P2 | 2 ed |
| F-28 | Access script exposes vulnerable services on all interfaces (`--address 0.0.0.0`) | Medium | 2×3 | Engineer tooling | P2 | 0.5 ed |
| F-29 | Removed Kubernetes API (`extensions/v1beta1` Ingress); Helm 2 / Tiller remnants | Low | 1×2 | Lifecycle | P3 | 0.5 ed |

↑ = raised one tier under the methodology's adjustment rule; reason given in the finding.

**Totals:** 4 Critical, 14 High, 10 Medium, 1 Low.

**Go-live view:** 10 findings are P0 (block). All of them are fixable inside the window with roughly 12 engineer-days of effort. Most of the rest are closed by four platform controls (admission policy, default-deny networking, workload identity, signed and pinned images) rather than workload-by-workload fixes. That is the argument for doing the platform work first.

---

## Attack chains

Individual ratings understate how these combine. The three chains below drive the remediation order.

**Chain A: CI job to whole cluster (the audit scenario).** F-01 → F-16. Anyone who can get a pipeline to run (any developer, or a compromised build dependency) inherits `cluster-admin`. With audit logging off, the use of that binding leaves no trace in the control-plane logs. *Broken by:* F-01 fix plus the pipeline gate in Module 2, with F-16 for detection.

**Chain B: any pod to node root to cluster.** F-12 → F-02 (or F-03) → node. Any compromised pod can reach `system-monitor`'s web shell over the flat network. That shell is root on the node with the host filesystem mounted. From there: every pod's secrets on that node, the kubelet's credentials, and the node's cloud identity (F-19). If a pod using a highly privileged SA (F-01, F-04) is scheduled on the same node, its token is readable from the host, and that's the cluster. *Broken by:* F-06 (admission blocks privileged/hostPath) and F-12 (default-deny).

**Chain C: outside to cloud credentials.** F-10 / F-09 → F-19. The NodePort exposes the same pod that hosts an SSRF-capable API. On EKS the SSRF target becomes `169.254.169.254`, and without IMDSv2 hop-limit 1 or workload identity, that returns the node role's credentials. *Broken by:* F-10, F-09, IMDSv2 hop limit 1, and F-19.

---

## Findings

### F-01: `cluster-admin` bound to a service account
- **Location:** [kg: `scenarios/insecure-rbac/setup.yaml:1-18`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/insecure-rbac/setup.yaml#L1-L18). A ClusterRoleBinding `superadmin` grants `cluster-admin` to SA `kube-system/superadmin`.
- **Severity:** Critical (I4 × E3). Impact is the whole cluster. Exploitability is E3 because, in the programme, this is the pattern found on a CI job's SA: anyone who can trigger a pipeline holds the credentials, which is a much bigger group than "cluster admins".
- **Domain:** RBAC / least privilege.
- **Risk (plain language):** A build job has the master key to the cluster. If any build is tampered with, or any developer's account is phished, the attacker can read every secret, change any workload and hide their tracks.
- **Remediation:** Delete the binding. Give the CI identity a namespace-scoped Role covering only the resources it deploys, bound per target namespace. Move cluster-scoped changes (CRDs, ClusterRoles) to a separate, manually approved platform pipeline. Prefer short-lived tokens (GitLab OIDC → AWS role → EKS access entry) over a long-lived SA token. Add the Module 2 policy gate that fails any merge introducing a binding to `cluster-admin` or `*` verbs. Worked steps: [Module 6, item 1](../06-remediation/remediation-advisory.md).
- **Effort:** 1 ed (plus testing each pipeline's deploy against the reduced role).

### F-02: `system-monitor`: privileged pod with host filesystem and an unauthenticated writable web shell
- **Location:** [kg: `scenarios/system-monitor/deployment.yaml:25-45`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/system-monitor/deployment.yaml#L25-L45) (`hostPID`, `hostIPC`, `hostPath: /` mounted read-write, `privileged: true`, `allowPrivilegeEscalation: true`); [kg: `infrastructure/system-monitor/Dockerfile:18`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/system-monitor/Dockerfile#L18) (`gotty -w bash`: browser shell, write enabled, no auth).
- **Severity:** Critical (I4 × E3). Root on the node from any pod that can reach port 8080.
- **Domain:** Pod security context.
- **Risk:** Anyone who can reach this service gets a shell that is effectively root on the server underneath, and so can read or tamper with every other application on that server.
- **Remediation:** Remove `privileged`, `hostPID`, `hostIPC` and the `hostPath` volume. If host metrics are genuinely needed, use a purpose-built read-only agent (node-exporter with only `/proc` and `/sys` read-only) in a dedicated namespace. Remove `gotty` from the image entirely; operational access goes through audited `kubectl exec` under RBAC, not a web shell. Enforce with PSA `restricted` (F-06). Corrected manifest: [`06-remediation/fixed-manifests/system-monitor.yaml`](../06-remediation/fixed-manifests/system-monitor.yaml).
- **Effort:** 1 ed.

### F-03: `health-check`: command injection in a privileged pod holding the container runtime socket
- **Location:** [kg: `infrastructure/health-check/main.go:29`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/health-check/main.go#L29) (`exec.Command("sh", "-c", "ping -c 2 "+endpoint)` with user input); [kg: `scenarios/health-check/deployment.yaml:46-97`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/health-check/deployment.yaml#L46-L97) (privileged init and main containers, host `/` mounted, containerd/docker socket linked in).
- **Severity:** Critical (I4 × E3). A single form field becomes root on the node: the injection gives code execution, and the runtime socket lets the attacker start a new privileged container on the host.
- **Domain:** Pod security / application security.
- **Risk:** Typing a crafted "server address" into this page lets someone run any command, and because the app holds the container engine's control socket, they can take over the server.
- **Remediation:** Code: never pass input to a shell. Validate the input as a hostname/IP and call `exec.Command("ping", "-c", "2", host)` with no shell. Manifest: remove all socket and `hostPath` mounts and both `privileged` flags; a ping checker needs `NET_RAW` at most. Gate: Semgrep rule for `exec.Command("sh", "-c", ...)` with concatenation in CI; admission policy denying runtime-socket `hostPath`. Corrected manifest: [`06-remediation/fixed-manifests/health-check.yaml`](../06-remediation/fixed-manifests/health-check.yaml).
- **Effort:** 2 ed (code fix, test, manifest).

### F-04: Helm chart grants `*/*/*` cluster rights to the `default` service account
- **Location:** [kg: `infrastructure/helm-tiller/pwnchart/templates/clusterrole.yaml:5-8`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/helm-tiller/pwnchart/templates/clusterrole.yaml#L5-L8) (`apiGroups/resources/verbs: ["*"]`), [`clusterrolebinding.yaml:9-12`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/helm-tiller/pwnchart/templates/clusterrolebinding.yaml#L9-L12), [`values.yaml:4-5`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/helm-tiller/pwnchart/values.yaml#L4-L5) (`namespace: default`, `name: default`).
- **Severity:** Critical (I4 × E3). If installed with defaults, every pod in `default` that doesn't name its own SA (most of them, see F-27) becomes cluster-admin-equivalent, including the pods in F-02 and F-03. The setup script doesn't install it today, so it's latent, but it sits in the repo ready to use.
- **Domain:** RBAC / ClusterRole scope creep.
- **Risk:** One install command would hand full control of the cluster to almost every application in the default area, not just to one admin tool.
- **Remediation:** Delete the chart. More generally: whoever can install a Helm chart can create ClusterRoles, so chart installs must go through the same policy gate as raw manifests (`helm template | conftest`), and the deploy identity must not have `escalate`/`bind` on RBAC resources.
- **Effort:** 0.5 ed.

### F-05: Secrets baked into container images
- **Location:** [kg: `infrastructure/users-repo/Dockerfile:4`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/users-repo/Dockerfile#L4) (`ENV API_KEY=...`); [kg: `infrastructure/hidden-in-layers/Dockerfile:5-8`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/hidden-in-layers/Dockerfile#L5-L8) (file `ADD`ed, then `rm`'d in a later layer, so it's still in the image); [kg: `infrastructure/build-code/Dockerfile:4-5`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/build-code/Dockerfile#L4-L5) (the shipped `app.tar.gz` contains `app/.git/` with 98 objects of history; verified by listing the archive).
- **Severity:** High (I3 × E3). Anyone who can pull the image can recover these. In the reference repo the images are public on Docker Hub, which would make this E4 / Critical. In the programme, with private ECR, pull rights are broad (every node role), so E3.
- **Domain:** Secrets management / image supply chain.
- **Risk:** Passwords and keys are packed inside the application's shipping container. Deleting a file in a later step doesn't remove it, and anyone who can download the image can unpack them.
- **Remediation:** Rotate every exposed credential first; assume they're compromised. Remove the secrets from the Dockerfiles; inject at runtime via the secrets design (Module 5). Use multi-stage builds that copy only the built artifact, and a `.dockerignore` that excludes `.git`. Add gitleaks on source and Trivy secret scanning on the built image as hard-fail CI gates.
- **Effort:** 2 ed (rotation is the long pole).

### F-06: No cluster-wide admission control
- **Location:** Repo-wide: no Pod Security Admission labels on any namespace (e.g. [kg: `scenarios/hunger-check/deployment.yaml:2-5`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/hunger-check/deployment.yaml#L2-L5), [`cache-store/deployment.yaml:1-4`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/cache-store/deployment.yaml#L1-L4)), no Kyverno/Gatekeeper baseline. The only policy, [kg: `scenarios/kyverno-namespace-exec-block/kyverno-block-pod-exec-by-namespace.yaml:30-36`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/kyverno-namespace-exec-block/kyverno-block-pod-exec-by-namespace.yaml#L30-L36), blocks `exec` only in a namespace called `vault`, which nothing in the repo creates.
- **Severity:** High (I4 × E2). This is the root cause that let F-02, F-03 and F-07 be admitted at all. E2 because exploiting it needs deploy rights.
- **Domain:** Admission control / configuration baseline.
- **Risk:** The cluster accepts any application configuration, however dangerous. The one safety rule that exists protects an area that doesn't exist, which gives false comfort in an audit.
- **Remediation:** Two layers. (1) PSA labels on every namespace: `enforce: restricted` for application namespaces, `baseline` with a documented exception list for platform namespaces; built into Kubernetes, so it works the same on EKS, AKS and GKE. (2) Kyverno for what PSA can't express: image signature verification, registry allowlist, no `cluster-admin` bindings, no `:latest`, required limits. Roll out in `Audit` mode for one week, fix violations, then switch to `Enforce`. Policies in [`02-pipeline-supply-chain/policies/`](../02-pipeline-supply-chain/policies/).
- **Effort:** 3 ed (platform), plus per-team fix-up absorbed by F-20.

### F-07: Privileged DaemonSet runs an attack-toolkit image on every node
- **Location:** [kg: `scenarios/docker-bench-security/deployment.yaml:27-72`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/docker-bench-security/deployment.yaml#L27-L72): `hostPID/IPC/Network`, `runAsUser: 0`, privileged, host `/etc`, `/var/lib` and runtime sockets mounted, running `madhuakula/hacker-container` with `sleep infinity` and `imagePullPolicy: Always`.
- **Severity:** High (I4 × E2). Using it directly needs `exec` rights. The quieter risk is supply chain: whoever controls that Docker Hub tag gets privileged code on every node at the next pull. That is exactly how the 2026 Trivy and KICS compromises landed.
- **Domain:** Pod security / supply chain.
- **Risk:** A standing, fully privileged toolkit sits on every server, and its contents can be changed from outside at any time.
- **Remediation:** Remove it. Run CIS checks as an on-demand Job (kube-bench) from a digest-pinned, signature-verified image, then delete it. Admission policy: DaemonSets with `privileged`/host namespaces only in an allowlisted platform namespace.
- **Effort:** 0.5 ed.

### F-08: Wildcard read Role (includes Secrets) bound to a pod running a web shell
- **Location:** [kg: `scenarios/hunger-check/deployment.yaml:8-30`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/hunger-check/deployment.yaml#L8-L30) (Role `secret-reader`: `resources: ["*"]`, `get/list/watch`, bound to `big-monolith-sa`); used by the Deployment at `:69`; image runs `gotty -w bash` ([kg: `infrastructure/hunger-check/Dockerfile:17`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/hunger-check/Dockerfile#L17)).
- **Severity:** High (I3 × E3). Anyone reaching the web shell can list every Secret in `big-monolith` using the pod's own token.
- **Domain:** RBAC.
- **Risk:** The app has permission to read every password in its area, and it exposes an open terminal, so anyone who finds the terminal gets all of them.
- **Remediation:** Replace `*` with the specific resources the app reads (most apps need none). If one secret is needed, mount that one secret; don't grant API read. Set `automountServiceAccountToken: false` unless the app calls the API. Remove `gotty`. Policy gate: deny Roles with `resources: ["*"]` or `secrets` + `list`.
- **Effort:** 1 ed.

### F-09: SSRF in `internal-api` reaches internal metadata service
- **Location:** [kg: `infrastructure/internal-api/code/server.js:20-22`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/internal-api/code/server.js#L20-L22): `spawnSync('curl', [endpoint, '-H', headers, '-X', method])` with fully user-controlled URL, headers and method. Target: `metadata-db`, which serves base64 secrets ([kg: `infrastructure/metadata-db/metadata/latest/secrets/`](https://github.com/madhuakula/kubernetes-goat/tree/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/metadata-db/metadata/latest/secrets)).
- **Severity:** High (I3 × E3). In goat the target is a mock; on EKS the same request to `169.254.169.254` returns the node IAM role's temporary credentials, unless IMDSv2 with hop limit 1 is enforced, and nothing in the reviewed code sets that.
- **Domain:** Workload identity boundary / application security.
- **Risk:** The app will fetch any web address it's given, including internal addresses that hand out cloud credentials, and then show the result to the requester.
- **Remediation:** App: allowlist destination hosts, block link-local and private ranges, no user-supplied headers. Platform: IMDSv2 required with hop limit 1 on all node groups (launch template `http_tokens = "required"`, `http_put_response_hop_limit = 1`); egress NetworkPolicy denying `169.254.169.254/32` from app namespaces; workload identity (F-19) so the node role holds almost nothing.
- **Effort:** 2 ed.

### F-10: Flask debug mode exposed on every node via NodePort
- **Location:** [kg: `infrastructure/info-app/app.py:11`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/info-app/app.py#L11) (`debug=True`, `host='0.0.0.0'`); [kg: `scenarios/internal-proxy/deployment.yaml:54-67`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/internal-proxy/deployment.yaml#L54-L67) (`type: NodePort`, `nodePort: 30003`).
- **Severity:** High (I2 × E4). NodePort listens on every node; with public node IPs (F-22) and a permissive node security group, it's internet-reachable. The Werkzeug debugger offers code execution once its PIN is derived, and the PIN inputs are discoverable from inside the pod (and the pod shares a network namespace with the SSRF in F-09).
- **Domain:** Exposure / application security.
- **Risk:** A developer debugging mode is switched on in production and reachable on a public port on every server.
- **Remediation:** `debug=False`; run under a production WSGI server (gunicorn). Service type `ClusterIP`; publish via the AWS Load Balancer Controller ingress behind WAF if it needs to be external at all. Policy: deny `NodePort` services outside an allowlist.
- **Effort:** 0.5 ed.

### F-11: Secret values committed to Git; injected as environment variables
- **Location:** [kg: `scenarios/hunger-check/deployment.yaml:37-53`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/hunger-check/deployment.yaml#L37-L53) (two `Secret` objects with values in Git), [kg: `scenarios/system-monitor/deployment.yaml:1-8`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/system-monitor/deployment.yaml#L1-L8); env-var injection at [`system-monitor/deployment.yaml:47-52`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/system-monitor/deployment.yaml#L47-L52).
- **Severity:** High (I3 × E3). Base64 is encoding, not encryption: anyone with repo read access (and its full history) has the values.
- **Domain:** Secrets management.
- **Risk:** Passwords are stored in the code repository in a form anyone can decode, and stay in the history even after they're removed.
- **Remediation:** Rotate. Move values to the central secrets store (Module 5, External Secrets Operator + AWS Secrets Manager); Git holds only an `ExternalSecret` reference. Prefer mounted files over env vars: env vars leak via `/proc/<pid>/environ` (readable from any `hostPID` pod, see F-02), crash dumps and child processes, and can't rotate without a restart. gitleaks as a hard-fail pre-merge gate. Purge history only if the repo has been shared outside the team; rotation is the real fix.
- **Effort:** 2 ed.

### F-12: No NetworkPolicy; flat pod network
- **Location:** Repo-wide: zero `NetworkPolicy` objects. Scenario context: EKS default VPC CNI with no policy enforcement enabled.
- **Severity:** High (I3 × E3). Any pod can reach Redis (F-13), the registry (F-14), the metadata service (F-09) and the node-root web shell (F-02). This is the link that turns single bugs into chains A–C.
- **Domain:** Network segmentation.
- **Risk:** Inside the cluster, every application can talk to every other one. One compromised app can reach all the others.
- **Remediation:** Turn on enforcement. On EKS, VPC CNI has native NetworkPolicy support since v1.14 (`enableNetworkPolicy: "true"` on the add-on); otherwise Cilium or Calico. Then default-deny ingress and egress per namespace, allow DNS, add explicit allows per flow. Roll out namespace by namespace with flow logs first so nothing breaks unexpectedly. Design in [Module 4](../04-network-mesh/zero-trust-design.md); manifests in [`fixed-manifests/networkpolicies.yaml`](../06-remediation/fixed-manifests/networkpolicies.yaml).
- **Effort:** 5 ed for the platform and first namespaces; then about 0.5 ed per workload.

### F-13: Unauthenticated Redis holding sensitive data
- **Location:** [kg: `scenarios/cache-store/deployment.yaml:1-39`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/cache-store/deployment.yaml#L1-L39) (namespace `secure-middleware`, port 6379, no auth); [kg: `infrastructure/cache-store/start-redis.sh:11`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/cache-store/start-redis.sh#L11) (`redis-server` with no `requirepass`/ACL, no TLS); seeded with a secret at [`data.redis:1`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/cache-store/data.redis#L1).
- **Severity:** High (I3 × E3).
- **Domain:** Data protection / network.
- **Risk:** The data store is named "secure" but has no password, and any application in the cluster can read and change everything in it.
- **Remediation:** Redis ACLs with a per-client user and password from the secrets store; TLS; NetworkPolicy allowing 6379 only from named client pods. For citizen data, prefer a managed service (ElastiCache with in-transit and at-rest encryption, AUTH). Upgrade off Redis 6 (F-26).
- **Effort:** 1 ed.

### F-14: Unauthenticated, plaintext in-cluster image registry
- **Location:** [kg: `infrastructure/poor-registry/config.yml:10-13`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/poor-registry/config.yml#L10-L13) (no `auth`, no `tls`); service at [kg: `scenarios/poor-registry/deployment.yaml:24-34`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/poor-registry/deployment.yaml#L24-L34).
- **Severity:** High (I3 × E3). Pull gives every image's layers (and any secrets in them, F-05). Push lets anyone replace an image that other workloads then run.
- **Domain:** Supply chain.
- **Risk:** Any app in the cluster can download or replace the software packages that other apps run.
- **Remediation:** Decommission. All images come from ECR (or ACR/Artifact Registry later) with IAM-scoped pull, push only from CI, immutable tags, and signature verification at admission (F-17), so even a poisoned image wouldn't be admitted.
- **Effort:** 1 ed (migrate any images still in use).

### F-15: EKS API endpoint public with no CIDR restriction
- **Location:** [tg: `terraform/aws/eks.tf:122-125`](https://github.com/bridgecrewio/terragoat/blob/729f8da62c6a85ce4af5ad3d123de97776d954c4/terraform/aws/eks.tf#L122-L125). `vpc_config` sets `endpoint_private_access = true` but leaves `endpoint_public_access` at its default (`true`) and `public_access_cidrs` at its default (`0.0.0.0/0`).
- **Severity:** High (I4 × E2). Needs valid credentials, but any leaked kubeconfig or token works from anywhere on the internet, and the endpoint is exposed to credential stuffing and to any future API server vulnerability.
- **Domain:** Cluster / API server exposure.
- **Risk:** The cluster's control panel is reachable from the whole internet. A stolen login works from anywhere.
- **Remediation:** `endpoint_public_access = false`; access via the private endpoint from GitLab runners in the VPC and from admin bastions / SSM. If public access must stay during migration, restrict `public_access_cidrs` to the agency egress ranges and time-box it. Authentication via EKS access entries mapped to the agency IdP, not static IAM users.
- **Effort:** 1 ed (plus confirming runner connectivity).

### F-16: EKS control-plane and audit logging disabled
- **Location:** [tg: `terraform/aws/eks.tf:118-141`](https://github.com/bridgecrewio/terragoat/blob/729f8da62c6a85ce4af5ad3d123de97776d954c4/terraform/aws/eks.tf#L118-L141). No `enabled_cluster_log_types`, so `api`, `audit`, `authenticator`, `controllerManager` and `scheduler` logs are all off.
- **Severity:** High (I3 × E2, raised one tier). Raised because it's a detective gap that hides Critical findings: without the audit log, use of the F-01 binding, secret reads (F-08) and RBAC changes are invisible, and incident response (Module 3) has nothing to work from.
- **Domain:** Logging and monitoring.
- **Risk:** If someone misuses the cluster, there is no record of who did what, so we can't detect it, investigate it, or prove what happened to an auditor.
- **Remediation:** `enabled_cluster_log_types = ["api","audit","authenticator","controllerManager","scheduler"]`. Ship from CloudWatch to the landing zone's central log archive account (the newer landing-zone tier already has this pattern), KMS-encrypted, with retention set by the records policy. Alert on: new `cluster-admin` bindings, `secrets` list from non-controller identities, `exec` into production pods, anonymous requests.
- **Effort:** 0.5 ed (Terraform) plus log-routing set-up shared with Module 3.

### F-17: Unpinned image references, personal namespace, no signatures
- **Location:** Every manifest. Examples: no tag (implicit `latest`) at [kg: `scenarios/system-monitor/deployment.yaml:34`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/system-monitor/deployment.yaml#L34), [`build-code/deployment.yaml:17`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/build-code/deployment.yaml#L17); `busybox:latest` on privileged init containers at [`health-check/deployment.yaml:17`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/health-check/deployment.yaml#L17); `tag: latest` + `pullPolicy: Always` at [`metadata-db/values.yaml:7-10`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/metadata-db/values.yaml#L7-L10). All application images come from a personal Docker Hub namespace.
- **Severity:** High (I3 × E2, raised one tier). Raised because mutable-tag repointing is how the March and April 2026 Trivy and KICS Docker Hub compromises reached users. Several of these images run privileged, so a repointed tag means host-level code execution.
- **Domain:** Image provenance / supply chain.
- **Risk:** We don't control exactly which version of the software runs. Whoever controls the upstream account can swap it, and the cluster will run the new version on the next restart.
- **Remediation:** Mirror required third-party images into ECR through CI (scan, then sign). Reference images by digest (`image@sha256:...`), with the tag kept as a comment for humans. Cosign-sign in CI; Kyverno `verifyImages` at admission; registry allowlist. Renovate to keep digests current so pinning doesn't become a patching problem.
- **Effort:** 3 ed (pipeline + policy), then automatic.

### F-18: Lab host provisioning: EOL OS, IMDS defaults, SSH, unverified downloads
- **Location:** [kg: `platforms/aws-setup/aws-kind-ec2-cdk/aws_kind_ec2_cdk/aws_kind_ec2_cdk_stack.py:26`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/platforms/aws-setup/aws-kind-ec2-cdk/aws_kind_ec2_cdk/aws_kind_ec2_cdk_stack.py#L26) (Ubuntu 16.04 AMI from 2021; standard support ended April 2021); `:56-59` and `:98-105` (SSH on 22 with a key pair; no `require_imdsv2`, no SSM); [`.env:6`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/platforms/aws-setup/aws-kind-ec2-cdk/.env#L6) suggests `0.0.0.0/0` for the allowlist; [`user_data.sh:4-10`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/platforms/aws-setup/aws-kind-ec2-cdk/user_data.sh#L4-L10) downloads a binary with no checksum and runs setup as root.
- **Severity:** High (I3 × E3; E4 if the `.env` suggestion is followed).
- **Domain:** Node / OS hardening.
- **Risk:** The server runs an operating system that stopped getting security fixes years ago, and is reached by SSH key, which is hard to audit or revoke.
- **Remediation:** For EKS nodes: EKS-optimised Amazon Linux 2023 or Bottlerocket AMIs via managed node groups, replaced (not patched) on a monthly cadence; IMDSv2 required, hop limit 1; no SSH, use SSM Session Manager with session logging; CIS benchmark checked by kube-bench in the pipeline and on a schedule. For any lab host: same rules, plus checksum-verify every download.
- **Effort:** 2 ed.

### F-19: No workload identity; pods inherit the node role
- **Location:** [tg: `terraform/aws/eks.tf`](https://github.com/bridgecrewio/terragoat/blob/729f8da62c6a85ce4af5ad3d123de97776d954c4/terraform/aws/eks.tf#L118-L141) defines no `aws_iam_openid_connect_provider` and no Pod Identity association; no kubernetes-goat workload has an IAM-annotated SA.
- **Severity:** Medium (I3 × E2). Any pod that reaches IMDS (or has host access, F-02) acts with the node role's permissions (ECR pull, VPC CNI ENI management, plus whatever else teams have attached over time).
- **Domain:** Workload identity boundary.
- **Risk:** All applications on a server share one cloud identity, so any of them can act with the combined permissions of all of them.
- **Remediation:** EKS Pod Identity (or IRSA) with one IAM role per workload SA, least-privilege policies, and a node role trimmed to the AWS-managed minimum. Equivalent patterns: AKS Workload Identity, GKE Workload Identity Federation, so the design ports (Module 5).
- **Effort:** 3 ed (platform), about 0.5 ed per workload.

### F-20: Missing pod `securityContext` baseline
- **Location:** All application Deployments, e.g. [kg: `scenarios/build-code/deployment.yaml:14-23`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/build-code/deployment.yaml#L14-L23), [`internal-proxy/deployment.yaml:16-39`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/internal-proxy/deployment.yaml#L16-L39), [`cache-store/deployment.yaml:33-39`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/cache-store/deployment.yaml#L33-L39). None set `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]` or `seccompProfile: RuntimeDefault`. No AppArmor profile anywhere.
- **Severity:** Medium (I2 × E2). Not exploitable on its own, but it is what makes an app bug into a container escape.
- **Domain:** Pod security context.
- **Risk:** Applications run as the all-powerful user inside their containers with no guardrails, so any bug in them gives an attacker more room to move.
- **Remediation:** A standard securityContext block in every workload (template in [`fixed-manifests/`](../06-remediation/fixed-manifests/)), enforced by PSA `restricted` (F-06). Images need to run as a non-root UID, which is a Dockerfile change in most cases.
- **Effort:** 3 ed across all workloads.

### F-21: Resource governance gaps
- **Location:** [kg: `scenarios/hunger-check/deployment.yaml:73-79`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/hunger-check/deployment.yaml#L73-L79) (limits commented out; image ships `stress-ng`); no requests or limits in [`cache-store`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/cache-store/deployment.yaml#L35-L39), [`batch-check`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/batch-check/job.yaml#L10-L12), [`hidden-in-layers`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/hidden-in-layers/deployment.yaml#L10-L12); limits without requests elsewhere (e.g. `system-monitor`); no `ResourceQuota`, `LimitRange` or `PodDisruptionBudget` in any namespace; all single replica.
- **Severity:** Medium (I2 × E3). One runaway or abused pod can starve its node, and the citizen-facing services sharing that node degrade.
- **Domain:** Resource governance / availability.
- **Risk:** One misbehaving app can use up a server's memory or CPU and slow down or crash the public services running next to it.
- **Remediation:** Requests and memory limits on every container (CPU limits optional; requests matter more for scheduling). Per-namespace `LimitRange` defaults and `ResourceQuota`. PDBs and two or more replicas for citizen-facing services. Kyverno `require-requests-limits` policy.
- **Effort:** 2 ed.

### F-22: Node subnets auto-assign public IPs
- **Location:** [tg: `terraform/aws/eks.tf:66`](https://github.com/bridgecrewio/terragoat/blob/729f8da62c6a85ce4af5ad3d123de97776d954c4/terraform/aws/eks.tf#L66) and [`:94`](https://github.com/bridgecrewio/terragoat/blob/729f8da62c6a85ce4af5ad3d123de97776d954c4/terraform/aws/eks.tf#L94) (`map_public_ip_on_launch = true`); no private subnets or NAT defined.
- **Severity:** Medium (I3 × E2). Nodes become directly addressable; NodePort services (F-10) are one security-group rule away from the internet.
- **Domain:** Network exposure.
- **Risk:** The servers running the applications get public internet addresses when they don't need them.
- **Remediation:** Nodes in private subnets only; internet egress through NAT and an egress firewall (or proxy) with an allowlist; ingress only through ALB in public subnets. Follow the EKS Blueprints VPC layout.
- **Effort:** 2 ed (cluster subnets can't be swapped in place on older EKS versions; may need a new node group).

### F-23: No envelope encryption of Secrets with a customer-managed key
- **Location:** [tg: `terraform/aws/eks.tf:118-141`](https://github.com/bridgecrewio/terragoat/blob/729f8da62c6a85ce4af5ad3d123de97776d954c4/terraform/aws/eks.tf#L118-L141): no `encryption_config { resources = ["secrets"] provider { key_arn = ... } }`.
- **Severity:** Medium (I3 × E1, raised one tier). On its own the technical risk is low: AWS already encrypts the etcd volumes, and reaching etcd needs AWS-side access. Raised because government baselines expect customer-controlled keys for secrets at rest, and because it's cheap to fix: EKS supports enabling it on an existing cluster. Honest framing for the panel: this is mainly a key-custody and audit finding, not an exposure.
- **Domain:** Encryption at rest.
- **Risk:** Secrets in the cluster's database are protected by Amazon's key, not ours, so we can't independently control or audit access to them.
- **Remediation:** Customer-managed KMS key with rotation, key policy limited to the EKS service role and break-glass admin, CloudTrail on key use. Note: once enabled it can't be disabled, so record that in the change.
- **Effort:** 0.5 ed.

### F-24: Dormant fetch-and-execute script inside `batch-check` image
- **Location:** [kg: `infrastructure/batch-check/Dockerfile:5-6`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/batch-check/Dockerfile#L5-L6) writes `/usr/bin/system-startup`, which downloads from an external URL and pipes to `sh`; the image runs as a Job with no provenance ([kg: `scenarios/batch-check/job.yaml:10-12`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/batch-check/job.yaml#L10-L12)). This mirrors how cryptominers are typically hidden in public images. (In goat it's inert: the call is commented out and the URL now returns a 404.)
- **Severity:** Medium (I3 × E2).
- **Domain:** Supply chain / runtime detection.
- **Risk:** The package contains a hidden "download and run whatever is at this address" command. Whoever controls that address decides what runs in our cluster.
- **Remediation:** Only admit images built by our CI from reviewed Dockerfiles (signature verification, F-17). Scan image history for `curl|sh` patterns. Runtime: Falco rules for "network tool launched in container" and "binary executed from download" (Module 3). Egress default-deny (F-12) stops the download even if the script runs.
- **Effort:** 0.5 ed.

### F-25: ECR repository: mutable tags, no scan-on-push, laptop pushes
- **Location:** [tg: `terraform/aws/ecr.tf:1-3`](https://github.com/bridgecrewio/terragoat/blob/729f8da62c6a85ce4af5ad3d123de97776d954c4/terraform/aws/ecr.tf#L1-L3) (`image_tag_mutability = "MUTABLE"`, no `image_scanning_configuration`, no KMS); [`:17-26`](https://github.com/bridgecrewio/terragoat/blob/729f8da62c6a85ce4af5ad3d123de97776d954c4/terraform/aws/ecr.tf#L17-L26) (image built and pushed via `local-exec` from whoever runs Terraform).
- **Severity:** Medium (I3 × E2).
- **Domain:** Supply chain.
- **Risk:** Image versions can be silently overwritten, aren't checked for known vulnerabilities, and can be published from any engineer's laptop instead of the controlled build system.
- **Remediation:** `IMMUTABLE` tags, enhanced scanning (Inspector), KMS encryption, a repository policy allowing push only from the CI role, lifecycle policy. Remove the `local-exec` build; images are built only in CI.
- **Effort:** 1 ed.

### F-26: Base image hygiene
- **Location:** `golang:latest` as the *runtime* image ([kg: `infrastructure/health-check/Dockerfile:1`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/health-check/Dockerfile#L1), also `metadata-db`); `redis:6-alpine` (Redis 6 is end-of-life) ([`cache-store/Dockerfile:1`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/cache-store/Dockerfile#L1)); floating `node:alpine`, `python:alpine`, `alpine:latest`; `gotty 2.0.0-alpha.3` (unmaintained alpha) and Hugo 0.84.0 downloaded with no checksum ([`system-monitor/Dockerfile:13`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/system-monitor/Dockerfile#L13), [`goat-home/Dockerfile:14`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/goat-home/Dockerfile#L14)); `curl`/`wget` added to runtime images.
- **Severity:** Medium (I2 × E2).
- **Domain:** Image hygiene.
- **Risk:** The containers carry far more software than the app needs (compilers, download tools, outdated components), which gives an attacker more to work with and more known vulnerabilities to exploit.
- **Remediation:** Multi-stage builds onto distroless or minimal base images pinned by digest; a small set of approved base images rebuilt weekly by the platform team; checksum-verify every downloaded binary; Trivy hard-fail on fixable Critical/High CVEs.
- **Effort:** 3 ed.

### F-27: Workloads in `default` on the default SA with auto-mounted tokens
- **Location:** `build-code`, `health-check`, `internal-proxy`, `system-monitor`, `poor-registry`, `kubernetes-goat-home`, `batch-check`, `hidden-in-layers`, `docker-bench-security` all deploy to `default` (e.g. [kg: `scenarios/system-monitor/deployment.yaml:15`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/system-monitor/deployment.yaml#L15)) with no `serviceAccountName` and no `automountServiceAccountToken: false`.
- **Severity:** Medium (I2 × E3). Every one of them holds a usable API token. It becomes Critical in combination with F-04.
- **Domain:** RBAC / tenancy.
- **Risk:** Unrelated apps share one area and one identity, so a permission given for one of them is silently given to all of them.
- **Remediation:** Namespace per application or team, with PSA labels, quota and default-deny. A dedicated SA per workload, with `automountServiceAccountToken: false` unless the app calls the Kubernetes API. Policy: deny workloads in `default`.
- **Effort:** 2 ed.

### F-28: Access script exposes vulnerable services on all interfaces
- **Location:** [kg: `access-kubernetes-goat.sh:54-168`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/access-kubernetes-goat.sh#L54-L168): every `kubectl port-forward` uses `--address 0.0.0.0`, so services (including two web shells) listen on the engineer's LAN interface. The setup scripts also offer `--insecure-skip-tls-verify`.
- **Severity:** Medium (I2 × E3). Tooling, not production, but it's a common real-world pattern: port-forwards that turn an engineer's laptop on café Wi-Fi into a door into the cluster.
- **Domain:** Engineer tooling / access.
- **Risk:** A helper script opens the cluster's internal apps to anyone on the same Wi-Fi as the engineer running it.
- **Remediation:** Bind to `127.0.0.1` (the default). Never skip TLS verification. Production access via the private endpoint with SSO, not port-forwards.
- **Effort:** 0.5 ed.

### F-29: Removed Kubernetes API and Helm 2 / Tiller remnants
- **Location:** [kg: `scenarios/metadata-db/templates/ingress.yaml:4`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/metadata-db/templates/ingress.yaml#L4) (`extensions/v1beta1`, removed in Kubernetes 1.22); [kg: `infrastructure/helm-tiller/Dockerfile`](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/infrastructure/helm-tiller/Dockerfile) (Helm 2.16.7, kubectl 1.18.3).
- **Severity:** Low (I1 × E2).
- **Domain:** Lifecycle management.
- **Risk:** Parts of the setup are written for Kubernetes versions that no longer exist, a sign they aren't maintained and a blocker for upgrades.
- **Remediation:** `networking.k8s.io/v1` Ingress; delete Helm 2 artifacts; add `kubeconform` / `pluto` to CI to catch removed APIs before an EKS upgrade does.
- **Effort:** 0.5 ed.

---

## Coverage note: manual review vs scanners

See [`evidence/README.md`](evidence/README.md) for scanner versions, digests, how they were run, and a per-finding cross-reference.
