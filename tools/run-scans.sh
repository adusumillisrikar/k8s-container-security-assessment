#!/usr/bin/env bash
# Reproduces the scanner evidence in 01-findings/evidence/.
#
# Usage: tools/run-scans.sh <kubernetes-goat checkout @723a0db> <terragoat snippets dir> <output dir>
#
# Every scanner is treated as untrusted (see README, "done safely"):
#   - image pinned by digest (no tags), versions at least ~2 weeks old at time of use
#   - --network none: nothing can be downloaded or sent anywhere
#   - --read-only root filesystem, all capabilities dropped, no-new-privileges
#   - inputs mounted read-only; the only writable mount is the output directory
#   - no Docker socket, kubeconfig, cloud or Git credentials mounted
set -euo pipefail

GOAT=${1:?kubernetes-goat checkout}
TG=${2:?terragoat snippets dir}
OUT=${3:?output dir}
REPO=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$OUT"

CONFTEST=docker.io/openpolicyagent/conftest@sha256:82f23e0e1f3faf2f3798f4b1974676c1aed96b05c6656ec6820435c31867c532   # v0.70.1
CHECKOV=docker.io/bridgecrew/checkov@sha256:d3e96adafdb315ca82e792ca8708c01adae85292800fb064c8b309b3d0cb7b80          # 3.3.19
KUBESCORE=docker.io/zegl/kube-score@sha256:ac4c43ad560af905d66f6bf57b0937c591332e6dbf2167c31193a13b4695ab97          # v1.20.0
TRIVY=docker.io/aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969                 # 0.74.0
KYVERNO=ghcr.io/kyverno/kyverno-cli@sha256:ced7b2be0b04250cabfe695f15307f69eb715fe23234816388af4f3812915b2a          # v1.19.1

# Docker on Windows (Git Bash) needs mixed-style paths and no MSYS path rewriting.
p() { if command -v cygpath >/dev/null; then cygpath -m "$1"; else echo "$1"; fi; }
export MSYS_NO_PATHCONV=1

sandbox=(docker run --rm --network none --read-only --cap-drop ALL
         --security-opt no-new-privileges --tmpfs /tmp:rw,size=512m
         -v "$(p "$GOAT"):/goat:ro" -v "$(p "$TG"):/tg:ro" -v "$(p "$REPO"):/repo:ro"
         -v "$(p "$OUT"):/out")

# Plain manifests only (Helm templates are rendered separately in a real pipeline).
MANIFESTS=$(cd "$GOAT" && ls scenarios/*/*.yaml | grep -v -e kube-bench-security -e kyverno-namespace-exec-block)
FIXED=$(cd "$REPO" && ls 06-remediation/fixed-manifests/*.yaml)

echo "== 1. Conftest: org policy vs kubernetes-goat manifests"
"${sandbox[@]}" -w /goat "$CONFTEST" test --no-color --policy /repo/02-pipeline-supply-chain/policies/conftest \
  $MANIFESTS > "$OUT/conftest-goat.txt" 2>&1 || true

echo "== 2. Conftest: the audit-finding manifest on its own (the F-01 demo)"
"${sandbox[@]}" -w /goat "$CONFTEST" test --no-color --policy /repo/02-pipeline-supply-chain/policies/conftest \
  scenarios/insecure-rbac/setup.yaml > "$OUT/conftest-insecure-rbac.txt" 2>&1 || true

echo "== 3. Conftest: fixed manifests (expect no deny)"
"${sandbox[@]}" -w /repo "$CONFTEST" test --no-color --policy /repo/02-pipeline-supply-chain/policies/conftest \
  $FIXED > "$OUT/conftest-fixed.txt" 2>&1 || true

echo "== 4. Checkov: Kubernetes manifests + terragoat EKS/ECR Terraform"
"${sandbox[@]}" -e HOME=/tmp -e CHECKOV_RUN_SCA_PACKAGE_SCAN_V2=false "$CHECKOV" \
  -d /goat/scenarios --framework kubernetes --skip-download --compact --quiet \
  -o cli -o json --output-file-path /out/checkov-goat-k8s.txt,/out/checkov-goat-k8s.json > /dev/null 2>&1 || true
"${sandbox[@]}" -e HOME=/tmp "$CHECKOV" \
  -d /tg --framework terraform --skip-download --compact --quiet \
  -o cli -o json --output-file-path /out/checkov-terragoat.txt,/out/checkov-terragoat.json > /dev/null 2>&1 || true

echo "== 5. kube-score: reliability/security hygiene"
"${sandbox[@]}" -w /goat "$KUBESCORE" score --output-format ci $MANIFESTS > "$OUT/kube-score-goat.txt" 2>&1 || true

echo "== 6. Trivy: misconfiguration + secrets (offline, embedded checks)"
"${sandbox[@]}" -e HOME=/tmp -e TRIVY_CACHE_DIR=/tmp/trivy "$TRIVY" fs --offline-scan --skip-db-update --skip-check-update \
  --scanners misconfig,secret --format table /goat > "$OUT/trivy-goat.txt" 2>&1 || true

echo "== 7. Kyverno CLI: admission policies vs goat and fixed manifests (verifyImages excluded: needs a registry)"
"${sandbox[@]}" -e HOME=/tmp -w /goat "$KYVERNO" apply \
  /repo/02-pipeline-supply-chain/policies/kyverno/cluster-guardrails.yaml \
  --resource scenarios/system-monitor/deployment.yaml --resource scenarios/health-check/deployment.yaml \
  --resource scenarios/insecure-rbac/setup.yaml --resource scenarios/internal-proxy/deployment.yaml \
  --policy-report --remove-color > "$OUT/kyverno-goat.txt" 2>&1 || true
"${sandbox[@]}" -e HOME=/tmp -w /repo "$KYVERNO" apply \
  /repo/02-pipeline-supply-chain/policies/kyverno/cluster-guardrails.yaml \
  $(for f in $FIXED; do printf -- '--resource %s ' "$f"; done) \
  --policy-report --remove-color > "$OUT/kyverno-fixed.txt" 2>&1 || true

echo "done -> $OUT"
