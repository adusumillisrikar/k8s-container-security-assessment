#!/usr/bin/env bash
# The two checks that need network access, kept apart from run-scans.sh (which is fully offline).
#   - kubeconform downloads Kubernetes JSON schemas (and CRD schemas from datreeio/CRDs-catalog)
#   - Semgrep downloads its registry rule packs
# Both run with read-only inputs, all capabilities dropped and no credentials mounted;
# Semgrep telemetry is off.
#
# Usage: tools/run-online-checks.sh <kubernetes-goat checkout @723a0db> <output dir>
set -euo pipefail
export MSYS_NO_PATHCONV=1
GOAT=${1:?kubernetes-goat checkout}
OUT=${2:?output dir}
REPO=$(cd "$(dirname "$0")/.." && pwd)
p() { if command -v cygpath >/dev/null; then cygpath -m "$1"; else echo "$1"; fi; }
mkdir -p "$OUT"
KUBECONFORM=ghcr.io/yannh/kubeconform@sha256:faffaf43f95aa6425306e1ab8d6fcad72acb9049158f38e574c085ea1ec0f64e   # v0.8.0
SEMGREP=docker.io/semgrep/semgrep@sha256:32e459968daabe7ab86968184a29109b9564aa00392401156f9788452b42786b       # 1.178.0

echo "== kubeconform: fixed manifests + Kyverno policies vs Kubernetes 1.36.0"
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges -v "$(p "$REPO"):/repo:ro" "$KUBECONFORM" \
  -strict -summary -output text -kubernetes-version 1.36.0 -schema-location default \
  -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
  /repo/06-remediation/fixed-manifests /repo/02-pipeline-supply-chain/policies/kyverno | tee "$OUT/kubeconform-fixed.txt"

echo "== Semgrep registry packs vs goat application code"
docker run --rm --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,exec,size=1g -e HOME=/tmp \
  -e SEMGREP_SEND_METRICS=off -v "$(p "$GOAT"):/goat:ro" -v "$(p "$OUT"):/out" -w /goat "$SEMGREP" \
  semgrep scan --metrics=off --config p/ci --config p/command-injection --config p/flask --config p/nodejs \
  --json --output /out/semgrep-goat.json infrastructure || true
echo "done -> $OUT"
