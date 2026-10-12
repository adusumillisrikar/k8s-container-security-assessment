#!/usr/bin/env bash
# Validates 03-runtime-security/falco-rules-custom.yaml with Falco's own rule validator.
# The k8saudit + json plugins are installed by the official falcoctl image, which
# verifies their signatures, into a throwaway Docker volume. Validation runs offline.
set -euo pipefail
export MSYS_NO_PATHCONV=1
REPO=$(cd "$(dirname "$0")/.." && pwd)
p() { if command -v cygpath >/dev/null; then cygpath -m "$1"; else echo "$1"; fi; }
FALCO=docker.io/falcosecurity/falco@sha256:788f1129c542171813083d4afc61b16730a47dde8c23d9c39370acef996349b6       # 0.45.0
FALCOCTL=docker.io/falcosecurity/falcoctl@sha256:90ba9627886e8f26b746fa52465d755b28ee49b76eb1d047a0fefd8cadb21907 # 0.14.2
VOL=falco-validate-plugins

docker volume create "$VOL" >/dev/null
trap 'docker volume rm -f "$VOL" >/dev/null' EXIT
docker run --rm --user 0 --cap-drop ALL --cap-add DAC_OVERRIDE --security-opt no-new-privileges \
  --tmpfs /etc/falcoctl -v "$VOL:/plugins" "$FALCOCTL" \
  artifact install k8saudit json --plugins-dir /plugins --rulesfiles-dir /tmp --allowed-types plugin >/dev/null
docker run --rm --entrypoint falco "$FALCO" --version | head -1
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp \
  -v "$VOL:/plugins:ro" -v "$(p "$REPO/tools/falco"):/cfg:ro" -v "$(p "$REPO/03-runtime-security"):/rules:ro" \
  --entrypoint falco "$FALCO" -c /cfg/validate-config.yaml \
  -V /etc/falco/falco_rules.yaml -V /rules/falco-rules-custom.yaml 2>&1 | grep -v -e '^\s*$' -e 'System info:'
