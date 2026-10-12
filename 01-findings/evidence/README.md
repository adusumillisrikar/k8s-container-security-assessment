# Scanner Evidence

Everything here was produced by two scripts in [`tools/`](../../tools/). Anyone can re-run them against the same pinned commits and get the same results.

| Script | What it does |
|---|---|
| [`tools/run-scans.sh`](../../tools/run-scans.sh) | Runs Conftest, Checkov, kube-score, Trivy and the Kyverno CLI against kubernetes-goat `723a0db`, terragoat `729f8da` (`eks.tf`, `ecr.tf`), and this repo's fixed manifests |
| [`tools/psa-rbac-test.sh`](../../tools/psa-rbac-test.sh) | Creates a throwaway local kind cluster, checks the Module 6 claims live (Pod Security and RBAC before/after), then deletes the cluster |
| [`tools/validate-falco.sh`](../../tools/validate-falco.sh) | Validates the custom Falco rules (Module 3) with Falco 0.45.0 and the signature-verified k8saudit/json plugins, offline |

Run on 2026-10-12.

## How the tools were run (and why that way)

The 2026 Trivy and KICS Docker Hub compromises showed that a security scanner is itself supply-chain risk. So:

| Control | How |
|---|---|
| Image pinned by digest | No tags anywhere; digests below |
| Release cooldown | Only versions at least ~2 weeks old at time of use. The malicious Trivy tags were live for about 3 days, so a cooldown alone would have avoided them |
| No network | `--network none`: a compromised scanner can't download a payload or send anything out |
| Nothing to steal | Inputs (public repos + this repo) mounted read-only; no Docker socket, kubeconfig, cloud or Git credentials mounted |
| Container hardening | `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, tmpfs `/tmp` |
| Live test isolation | kind API on 127.0.0.1 only; every goat image reference replaced with `registry.invalid/...` before applying, so **no goat image was ever pulled or run**; cluster deleted after |

| Tool | Version | Image digest |
|---|---|---|
| Conftest | v0.70.1 | `openpolicyagent/conftest@sha256:82f23e0e1f3faf2f3798f4b1974676c1aed96b05c6656ec6820435c31867c532` |
| Checkov | 3.3.19 | `bridgecrew/checkov@sha256:d3e96adafdb315ca82e792ca8708c01adae85292800fb064c8b309b3d0cb7b80` |
| kube-score | v1.20.0 | `zegl/kube-score@sha256:ac4c43ad560af905d66f6bf57b0937c591332e6dbf2167c31193a13b4695ab97` |
| Trivy | 0.74.0 | `aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969` |
| Kyverno CLI | v1.19.1 | `ghcr.io/kyverno/kyverno-cli@sha256:ced7b2be0b04250cabfe695f15307f69eb715fe23234816388af4f3812915b2a` |
| kind | v0.32.0, Kubernetes v1.36.1 | kind's default node image |
| Falco | 0.45.0 | `falcosecurity/falco@sha256:788f1129c542171813083d4afc61b16730a47dde8c23d9c39370acef996349b6` |
| falcoctl | 0.14.2 | `falcosecurity/falcoctl@sha256:90ba9627886e8f26b746fa52465d755b28ee49b76eb1d047a0fefd8cadb21907` (plugin signatures verified on install) |

## Headline results

| # | Test | Result | File |
|---|---|---|---|
| 1 | **Would the pipeline gate have stopped the audit finding?** Conftest org policy against goat's `scenarios/insecure-rbac/setup.yaml` | **Yes.** `FAIL ... [F-01] ClusterRoleBinding/superadmin binds cluster-admin` | [conftest-insecure-rbac.txt](conftest-insecure-rbac.txt) |
| 2 | Would Checkov alone have stopped it? | **No.** Zero failures on that file. Checkov's RBAC checks inspect Role *contents*; `cluster-admin` is built in and never appears in the manifest | [checkov-goat-k8s.txt](checkov-goat-k8s.txt) |
| 3 | Would Trivy alone have stopped it? | **Only if the gate fails on Medium.** Flagged as `KSV-0111 (MEDIUM)`; a common "fail on High/Critical" gate lets it through | [trivy-goat-summary.txt](trivy-goat-summary.txt) |
| 4 | Admission control: Kyverno policies vs goat | 13 violations including the `cluster-admin` binding, privileged/host access, NodePort, default namespace, registry, limits | [kyverno-goat.txt](kyverno-goat.txt) |
| 5 | Admission control: Kyverno vs fixed manifests | **0 failures**, 9 passes | [kyverno-fixed.txt](kyverno-fixed.txt) |
| 6 | Conftest vs all goat manifests | 60 hard failures, 48 warnings across F-01, F-02, F-03, F-04/08, F-10, F-11, F-17, F-20, F-27 | [conftest-goat.txt](conftest-goat.txt) |
| 7 | Conftest vs fixed manifests | **374/374 passed, 0 warnings** | [conftest-fixed.txt](conftest-fixed.txt) |
| 8 | Live Pod Security: fixed manifests in `restricted` namespaces | Admitted (pods created; `ErrImagePull` only because images are placeholders). Confirms the unprivileged-ping fix for health-check passes `restricted` | [psa-rbac-live-test.txt](psa-rbac-live-test.txt) |
| 9 | Live Pod Security: goat's original deployments in the same namespaces | Warning on apply; **pods refused** (`FailedCreate ... violates PodSecurity "restricted:latest"`) | [psa-rbac-live-test.txt](psa-rbac-live-test.txt) |
| 10 | Live RBAC: F-01 before/after | Before: superadmin SA has `*.*`. After: CI identity can patch Deployments in its own namespace only; can't read Secrets, `exec`, or create ClusterRoleBindings | [psa-rbac-live-test.txt](psa-rbac-live-test.txt) |
| 11 | Checkov vs terragoat EKS/ECR | 11 failures, confirming F-15, F-16, F-22, F-23, F-25, plus two items the manual review missed (now F-30, F-31) | [checkov-terragoat.txt](checkov-terragoat.txt) |
| 12 | Custom Falco rules (Module 3) through Falco's own validator, with the `k8saudit` plugin loaded | `falco-rules-custom.yaml: Ok`. All 5 rules (3 syscall, 2 audit-log) load without errors or warnings | [falco-rules-validation.txt](falco-rules-validation.txt) |

## What testing changed in the submission

Testing found real problems in my own work. They've been fixed, and they're listed here because that's the point of testing:

1. **The Kyverno `cluster-admin` policy was being silently skipped.** Kyverno doesn't allow subject-based exclusions in background-scan mode, and it skips the whole policy instead of failing. It's now admission-only (`background: false`), with the Falco audit rule covering existing bindings. Without the test, the most important admission rule in the pack wouldn't have worked.
2. **A wrong Checkov check ID in the pipeline.** I'd assumed `CKV_K8S_155` covered `cluster-admin` bindings; it covers webhook-configuration permissions. Replaced with `CKV_K8S_49` (wildcard roles) and `CKV2_K8S_5` (secret read), and the pipeline now relies on Conftest for the binding itself, as result 2 shows it must.
3. **Two missed findings.** Checkov caught VPC flow logs disabled and an unrestricted default security group in terragoat's `eks.tf`, which the manual review hadn't listed. Added as F-30 and F-31.
4. **The image-signature policy** was moved to its own file (`verify-images.yaml`), because it needs registry access and can't be tested offline. It's documented, not claimed as tested.
5. **Note for later:** Kyverno 1.19 marks `kyverno.io/v1 ClusterPolicy` as deprecated in favour of CEL-based `ValidatingPolicy`. The policies work today; migrating them is a planned upgrade item, not a go-live blocker.

## Coverage: manual review vs scanners

✓ = found · ◐ = partly (some aspects, or at a severity that wouldn't block) · ✗ = not found · n/a = not scanned by that tool

| Finding | Manual | Conftest (ours) | Checkov | Trivy | Kyverno / PSA |
|---|---|---|---|---|---|
| F-01 cluster-admin binding | ✓ | ✓ | ✗ | ◐ Medium | ✓ |
| F-02 privileged + host access + web shell | ✓ | ✓ | ✓ | ✓ | ✓ (web shell: ✗ all) |
| F-03 command injection + runtime socket | ✓ | ◐ socket only | ◐ socket only | ◐ hostPath only | ✓ (injection: ✗ all) |
| F-04 wildcard ClusterRole chart | ✓ | ✓ | n/a | ✓ | n/a |
| F-05 secrets in images | ✓ | ✗ | ✗ | ◐ ENV only | ✗ |
| F-06 no admission control | ✓ | ✗ | ✗ | ✗ | n/a |
| F-07 privileged toolkit DaemonSet | ✓ | ✓ | ✓ | ✓ | ✓ |
| F-08 wildcard Role + secrets | ✓ | ✓ | ✓ | ✓ | n/a |
| F-09 SSRF | ✓ | ✗ | ✗ | ✗ | ✗ |
| F-10 Flask debug + NodePort | ✓ | ◐ NodePort | ✗ | ✗ | ◐ NodePort |
| F-11 Secrets in Git, env vars | ✓ | ✓ | ✓ | ✗ | n/a |
| F-12 no NetworkPolicy | ✓ | ✗ | ✓ | ✗ | n/a |
| F-13 unauthenticated Redis | ✓ | ✗ | ✗ | ✗ | ✗ |
| F-14 unauthenticated registry | ✓ | ✗ | ✗ | ✗ | ◐ registry allowlist |
| F-15 public EKS endpoint | ✓ | n/a | ✓ | n/a | n/a |
| F-16 control-plane logging off | ✓ | n/a | ✓ | n/a | n/a |
| F-17 unpinned images | ✓ | ✓ | ✓ | ◐ | ✓ |
| F-18 lab host (EOL OS, IMDS, SSH) | ✓ | n/a | n/a | n/a | n/a |
| F-19 no workload identity | ✓ | ✗ | ✗ | ✗ | n/a |
| F-20 missing securityContext | ✓ | ◐ warn | ✓ | ✓ | ✓ |
| F-21 resource governance | ✓ | ◐ warn | ✓ | ✓ | ✓ |
| F-22 public IPs on node subnets | ✓ | n/a | ✓ | n/a | n/a |
| F-23 no envelope encryption | ✓ | n/a | ✓ | n/a | n/a |
| F-24 dormant fetch-and-execute script | ✓ | ✗ | ✗ | ✗ | ✗ |
| F-25 ECR mutable / no scan / laptop push | ✓ | n/a | ◐ not laptop push | n/a | n/a |
| F-26 base image hygiene | ✓ | ✗ | ✗ | ◐ USER, tags | ✗ |
| F-27 default namespace / SA tokens | ✓ | ✓ | ✓ | ✓ | ✓ |
| F-28 access script on 0.0.0.0 | ✓ | n/a | n/a | n/a | n/a |
| F-29 removed APIs, Helm 2 | ✓ | ✗ | ✗ | ✗ | ✗ |
| F-30 VPC flow logs off | **✗** | n/a | ✓ | n/a | n/a |
| F-31 default SG unrestricted | **✗** | n/a | ✓ | n/a | n/a |

**What this shows:**
- **Scanners are good at configuration and bad at intent.** They reliably catch privileged pods, missing limits and public endpoints. None of them found the SSRF, the command injection, the unauthenticated Redis and registry, the secret hidden in a deleted image layer, the `.git` history shipped inside an image, or the dormant download-and-run script. Those are among the highest-impact findings, and they came from reading the code.
- **Trivy's secret scanner found none of the planted secrets** (in Dockerfiles, Secret manifests, the Redis seed file or the metadata service files). They don't match its known credential patterns; only the `ENV API_KEY` line was caught, and by a Dockerfile misconfiguration check, not the secret scanner. Secret detection needs organisation-specific rules (gitleaks custom patterns) on top of the defaults.
- **The audit finding is the clearest case:** the generic catalogues either miss it (Checkov) or under-rate it (Trivy). That's why the pipeline has an organisation-owned Conftest policy written for our own incidents.
- **Manual review missed two things Checkov caught (F-30, F-31).** Using both is the point.
