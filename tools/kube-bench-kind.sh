#!/usr/bin/env bash
# Runs kube-bench (CIS Kubernetes Benchmark 1.12) on a clean, throwaway kind cluster
# and saves the report. Demonstrates the method only: a kind node is not an EKS node,
# so the results describe kind's kubeadm defaults, not the target state.
#
# Usage: tools/kube-bench-kind.sh <output file>
set -uo pipefail
OUTFILE=${1:?output file}
REPO=$(cd "$(dirname "$0")/.." && pwd)
m() { if command -v cygpath >/dev/null; then cygpath -m "$1"; else echo "$1"; fi; }
CLUSTER=assess-bench
K="kubectl --context kind-$CLUSTER"

kind create cluster --name "$CLUSTER" --wait 120s >/dev/null 2>&1
trap 'kind delete cluster --name "$CLUSTER" >/dev/null 2>&1' EXIT

$K apply -f "$(m "$REPO/tools/kube-bench/job.yaml")" >/dev/null
$K wait --for=condition=complete job/kube-bench --timeout=180s >/dev/null 2>&1 \
  || $K wait --for=condition=failed job/kube-bench --timeout=5s >/dev/null 2>&1
{
  echo "# kube-bench v0.16.0, --benchmark cis-1.12, on a throwaway kind cluster ($($K version 2>/dev/null | grep Server))"
  echo "# Method demonstration only: kind's kubeadm defaults, not an EKS node and not the target state."
  echo
  $K logs job/kube-bench
} > "$OUTFILE" 2>&1
grep -E "^== Summary total ==" -A4 "$OUTFILE"
