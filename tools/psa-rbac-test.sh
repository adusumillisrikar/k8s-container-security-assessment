#!/usr/bin/env bash
# Live check of the Module 6 remediation claims on a throwaway kind cluster.
#
# Usage: tools/psa-rbac-test.sh <kubernetes-goat checkout @723a0db> <output file>
#
# Safety: goat image references are replaced with an unresolvable registry
# (registry.invalid) before anything is applied, so no goat image is ever pulled.
# The kind API server listens on 127.0.0.1 only, and the cluster is deleted at the end.
set -uo pipefail

GOAT=${1:?kubernetes-goat checkout}
OUTFILE=${2:?output file}
REPO=$(cd "$(dirname "$0")/.." && pwd)
m() { if command -v cygpath >/dev/null; then cygpath -m "$1"; else echo "$1"; fi; }
FIXED=$(m "$REPO/06-remediation/fixed-manifests")
G=$(m "$GOAT")
WORK=$(mktemp -d)
CLUSTER=assess-psa
K="kubectl --context kind-$CLUSTER"

exec > >(tee >(sed -e "s|$(m "$REPO")/|<repo>/|g" -e "s|$G/|<kubernetes-goat>/|g" > "$OUTFILE")) 2>&1

kind create cluster --name "$CLUSTER" --wait 120s >/dev/null 2>&1
trap 'kind delete cluster --name "$CLUSTER" >/dev/null 2>&1; rm -rf "$WORK"' EXIT
echo "Cluster: $($K version 2>/dev/null | grep Server)"

for f in system-monitor health-check; do
  sed -E 's#image: .*#image: registry.invalid/not-pulled:0#' "$GOAT/scenarios/$f/deployment.yaml" \
    | grep -v "^  namespace: default" > "$WORK/goat-$f.yaml"
done
W=$(m "$WORK")

echo; echo "################ TEST 1: Pod Security Admission (Module 6, items 2 and 3)"
echo "## 1a. Apply the fixed manifests (ExternalSecret CRD isn't installed, so that one object errors)"
$K apply -f "$FIXED/namespaces.yaml" -f "$FIXED/health-check.yaml" -f "$FIXED/system-monitor.yaml"
echo; echo "## 1b. Apply kubernetes-goat's original deployments into the same restricted namespaces"
$K apply -n system-monitor -f "$W/goat-system-monitor.yaml"
$K apply -n health-check -f "$W/goat-health-check.yaml"
sleep 12
echo; echo "## 1c. Pods that were admitted (ErrImagePull is expected: images are placeholders)"
$K get pods -n health-check --no-headers; $K get pods -n system-monitor --no-headers
echo; echo "## 1d. ReplicaSet FailedCreate events for the goat deployments"
for ns in health-check system-monitor; do
  $K get events -n $ns --field-selector reason=FailedCreate -o custom-columns=OBJ:.involvedObject.name,MSG:.message --no-headers | head -1
done
echo; echo "## 1e. Evidence query from remediation-advisory.md (expect empty)"
$K get pods -A -o json | jq -r '.items[] | select(.metadata.namespace!="platform-node-agents" and .metadata.namespace!="kube-system") | select(.spec.hostPID or .spec.hostIPC or .spec.hostNetwork or ([.spec.containers[].securityContext.privileged] | any) or ([.spec.volumes[]?.hostPath] | any)) | .metadata.namespace+"/"+.metadata.name'
echo "(control, kube-system included, proves the query detects host access:)"
$K get pods -A -o json | jq -r '.items[] | select(.spec.hostPID or .spec.hostNetwork or ([.spec.volumes[]?.hostPath] | any)) | .metadata.namespace+"/"+.metadata.name' | head -3

echo; echo "################ TEST 2: RBAC before/after (Module 6, item 1)"
echo "## 2a. BEFORE: kubernetes-goat scenarios/insecure-rbac/setup.yaml"
$K apply -f "$G/scenarios/insecure-rbac/setup.yaml"
$K auth can-i --list --as=system:serviceaccount:kube-system:superadmin | head -3
echo; echo "## 2b. FIX: namespace-scoped ci-deployer Role; remove the binding"
$K apply -f "$FIXED/ci-deployer-rbac.yaml"
$K delete clusterrolebinding superadmin
$K delete serviceaccount superadmin -n kube-system
echo; echo "## 2c. AFTER"
$K auth can-i --list --as=system:serviceaccount:kube-system:superadmin | head -4
as_ci="--as=ci --as-group=ci-deploy:internal-proxy"
printf 'CI create clusterrolebindings:      %s\n' "$($K auth can-i create clusterrolebindings $as_ci 2>/dev/null)"
printf 'CI get secrets (own ns):            %s\n' "$($K auth can-i get secrets -n internal-proxy $as_ci)"
printf 'CI exec into pods (own ns):         %s\n' "$($K auth can-i create pods/exec -n internal-proxy $as_ci)"
printf 'CI patch deployments (own ns):      %s\n' "$($K auth can-i patch deployments -n internal-proxy $as_ci)"
printf 'CI patch deployments (other ns):    %s\n' "$($K auth can-i patch deployments -n system-monitor $as_ci)"
echo; echo "## 2d. Remaining cluster-admin bindings (kubeadm:cluster-admins is kind/kubeadm-specific; EKS doesn't create it)"
$K get clusterrolebindings,rolebindings -A -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name'
