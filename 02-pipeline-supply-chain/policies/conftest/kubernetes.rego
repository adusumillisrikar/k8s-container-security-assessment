# Pre-merge guardrails for Kubernetes manifests (run with Conftest in CI).
#
# `deny` = hard fail, blocks the merge request.
# `warn` = soft fail, reported in the MR but does not block.
#
# Each rule names the finding it prevents, so a failing pipeline links
# straight back to the reasoning in 01-findings/findings-register.md.

package main

import rego.v1

# ---------------------------------------------------------------- helpers

workload_kinds := {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}

pod_spec := input.spec if input.kind == "Pod"

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

pod_spec := input.spec.template.spec if {
	workload_kinds[input.kind]
	not input.kind in {"Pod", "CronJob"}
}

all_containers contains c if some c in pod_spec.containers

all_containers contains c if some c in pod_spec.initContainers

name := sprintf("%s/%s", [input.kind, input.metadata.name])

runtime_sockets := {
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/run/containerd/containerd.sock",
	"/var/run/crio/crio.sock",
}

# ------------------------------------------------- RBAC (F-01, F-04, F-08)

# F-01: the audit finding. Nothing reaches cluster-admin through a merge request.
deny contains msg if {
	input.kind in {"ClusterRoleBinding", "RoleBinding"}
	input.roleRef.kind == "ClusterRole"
	input.roleRef.name == "cluster-admin"
	msg := sprintf("[F-01] %s binds cluster-admin. Use a namespace-scoped Role; cluster-scoped changes go through the platform pipeline.", [name])
}

# F-04 / F-08: wildcard rules are cluster-admin by another name.
deny contains msg if {
	input.kind in {"ClusterRole", "Role"}
	some rule in input.rules
	some field in ["apiGroups", "resources", "verbs"]
	"*" in rule[field]
	msg := sprintf("[F-04/F-08] %s uses '*' in %s. List the exact resources and verbs needed.", [name, field])
}

# Privilege-escalation verbs on RBAC objects let a holder mint their own admin.
deny contains msg if {
	input.kind in {"ClusterRole", "Role"}
	some rule in input.rules
	some verb in rule.verbs
	verb in {"escalate", "bind", "impersonate"}
	msg := sprintf("[F-04] %s grants '%s', which allows privilege escalation.", [name, verb])
}

# F-08: listing secrets across a namespace is rarely needed by an application.
warn contains msg if {
	input.kind in {"ClusterRole", "Role"}
	some rule in input.rules
	"secrets" in rule.resources
	some verb in rule.verbs
	verb in {"list", "watch"}
	msg := sprintf("[F-08] %s can list/watch secrets. Mount the specific secret instead.", [name])
}

# ------------------------------------------- Pod security (F-02, F-03, F-07)

deny contains msg if {
	some c in all_containers
	c.securityContext.privileged == true
	msg := sprintf("[F-02] %s container '%s' is privileged.", [name, c.name])
}

deny contains msg if {
	some field in ["hostPID", "hostIPC", "hostNetwork"]
	pod_spec[field] == true
	msg := sprintf("[F-02] %s sets %s.", [name, field])
}

deny contains msg if {
	some v in pod_spec.volumes
	v.hostPath.path in runtime_sockets
	msg := sprintf("[F-03] %s mounts the container runtime socket %s.", [name, v.hostPath.path])
}

deny contains msg if {
	some v in pod_spec.volumes
	v.hostPath
	not v.hostPath.path in runtime_sockets
	msg := sprintf("[F-02] %s mounts hostPath %s.", [name, v.hostPath.path])
}

deny contains msg if {
	some c in all_containers
	c.securityContext.allowPrivilegeEscalation == true
	msg := sprintf("[F-20] %s container '%s' allows privilege escalation.", [name, c.name])
}

# F-20: soft-fail for now, hard-fail after the ratchet date (see pipeline-design.md).
warn contains msg if {
	some c in all_containers
	not c.securityContext.runAsNonRoot
	not pod_spec.securityContext.runAsNonRoot
	msg := sprintf("[F-20] %s container '%s' does not set runAsNonRoot.", [name, c.name])
}

warn contains msg if {
	some c in all_containers
	not c.securityContext.readOnlyRootFilesystem
	msg := sprintf("[F-20] %s container '%s' does not set readOnlyRootFilesystem.", [name, c.name])
}

# ------------------------------------------------------ Images (F-17)

deny contains msg if {
	some c in all_containers
	not contains(c.image, "@sha256:")
	msg := sprintf("[F-17] %s container '%s' image '%s' is not pinned by digest.", [name, c.name, c.image])
}

# ----------------------------------------------- Exposure (F-10, F-27)

deny contains msg if {
	input.kind == "Service"
	input.spec.type == "NodePort"
	msg := sprintf("[F-10] %s is a NodePort. Use ClusterIP behind the ingress controller.", [name])
}

deny contains msg if {
	workload_kinds[input.kind]
	object.get(input.metadata, "namespace", "default") == "default"
	msg := sprintf("[F-27] %s deploys to the default namespace.", [name])
}

# ------------------------------------------ Internet egress (F-12)

# Internet egress is a reviewed exception (egress firewall allowlist), not something
# an app repo can grant itself. Platform security approves it by annotating the policy.
deny contains msg if {
	input.kind == "NetworkPolicy"
	some rule in input.spec.egress
	some peer in rule.to
	peer.ipBlock.cidr in {"0.0.0.0/0", "::/0"}
	not input.metadata.annotations["security.platform/egress-approval"]
	msg := sprintf("[F-12] %s allows egress to the whole internet. Request it through the egress allowlist; platform security adds the approval annotation.", [name])
}

# ------------------------------------------- Secrets in Git (F-11)

deny contains msg if {
	input.kind == "Secret"
	count(object.get(input, "data", {})) + count(object.get(input, "stringData", {})) > 0
	msg := sprintf("[F-11] %s has values committed to Git. Use an ExternalSecret.", [name])
}

# ------------------------------------------ Resources (F-21)

warn contains msg if {
	some c in all_containers
	not c.resources.limits.memory
	msg := sprintf("[F-21] %s container '%s' has no memory limit.", [name, c.name])
}

warn contains msg if {
	some c in all_containers
	not c.resources.requests
	msg := sprintf("[F-21] %s container '%s' has no resource requests.", [name, c.name])
}
