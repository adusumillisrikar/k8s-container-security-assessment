# Runtime Security, Detection & Incident Response (Module 3)

The pipeline (Module 2) and admission (Kyverno/PSA) reduce what gets *into* the cluster. They do nothing about a zero-day in an approved image, a stolen credential, or a COTS container we can't patch (Module 7). Runtime detection is what tells us when prevention has failed.

## 1. Approach

| Layer | Tool | Why |
|---|---|---|
| Node / container syscalls | **Falco** (DaemonSet, modern eBPF probe) | Open source, CNCF graduated, same rules on EKS, AKS and GKE. Sees process, file and network activity inside every container without changing the workloads. |
| Kubernetes API activity | **EKS audit log → Falco `k8saudit-eks` plugin** + SIEM correlation | Catches control-plane abuse (new `cluster-admin` binding, secret listing, `exec` into production) that syscall monitoring can't see. Requires F-16 to be fixed. |
| Cloud account | **GuardDuty** (EKS Protection, Runtime Monitoring) | Managed AWS-native second opinion, plus threat intel on IPs/domains, at low effort. AWS-only, so it complements Falco rather than replacing it. On AKS/GKE the equivalents are Defender for Containers and GKE Threat Detection. |
| Enforcement (later) | Tetragon or Falco Talon | Kill-on-detect is powerful but risky for citizen-facing services. Not in phase 1: detect and respond first, automate response once rules have a low false-positive record. |

**Why not GuardDuty alone?** It would be the fastest start on EKS, but the requirement is that this doesn't get rebuilt when Azure/GCP clusters arrive. Falco gives one rule set, one alert format and one runbook across all three clouds; the cloud-native tools add cloud-specific context on top.

## 2. Rule categories that matter most for this workload mix

The estate is mostly citizen-facing web services (internet-exposed, unpredictable traffic), plus CI-driven deployments and an unpatchable COTS image. Priority order:

| # | Category | Example rules | Why it ranks here | Findings it covers |
|---|---|---|---|---|
| 1 | **Container escape and privilege** | Falco defaults: *Detect release_agent File Container Escapes*, *Linux Kernel Module Injection Detected*, *PTRACE attached to process*; from Falco's optional rule sets: privileged container launched, namespace change (`setns`) | Escape turns one bad pod into the node and its cloud identity. Highest blast radius. | F-02, F-03, F-07 |
| 2 | **Interactive shells and unexpected exec** | Terminal shell in container; `kubectl exec` into production namespace (audit) | Web services shouldn't spawn shells. Very high signal, very low noise. | F-02, F-08 |
| 3 | **Credential access** | Read of SA token by a process other than the app; connection to `169.254.169.254` from an app pod; read of `/etc/shadow` or cloud CLI config | This is how a pod foothold becomes cluster or cloud access. | F-09, F-19 |
| 4 | **Drift and droppers** | *Drop and execute new binary in container*; `curl`/`wget` piped to a shell; known miner pool ports or domains | Catches the batch-check pattern and most commodity payloads. | F-24, F-26 |
| 5 | **Control-plane abuse** (audit) | New `cluster-admin`/wildcard binding; `list secrets` by a non-controller identity; anonymous requests; new `MutatingWebhookConfiguration` | The audit-finding scenario. Also attacker persistence. | F-01, F-04 |
| 6 | **Unexpected egress** | Outbound connection to a destination outside the namespace's allowlist | Exfiltration and command-and-control. Partially prevented by default-deny (Module 4); this detects attempts. | F-12 |

Custom rules for categories 3, 4 and 5 that aren't in the Falco defaults are in [`falco-rules-custom.yaml`](falco-rules-custom.yaml).

## 3. Telemetry: what, where, how long

| Source | Collected by | Destination |
|---|---|---|
| Falco events | Falco → Falcosidekick | SIEM (all), paging tool (Critical only) |
| EKS audit / authenticator logs | EKS control-plane logging → CloudWatch | Subscription → central **log archive account** (S3, Object Lock, KMS), and the SIEM |
| Container stdout/stderr | Fluent Bit DaemonSet | CloudWatch → log archive |
| VPC flow logs, DNS query logs | VPC / Route 53 Resolver | Log archive + SIEM |
| CloudTrail (incl. node and pod role usage) | Org trail | Log archive + SIEM |
| GuardDuty findings | Security Hub | SIEM |

The log archive sits in a separate security account that cluster admins can't write to or delete from. An attacker with `cluster-admin` (F-01) can delete Falco from the cluster but can't erase what was already shipped. The newer landing zone tier already centralises logging; the older VPC-per-environment tier needs the same subscription filters added as part of onboarding. Retention follows the programme's records schedule; I'd assume at least 1 year searchable and longer in archive until told otherwise.

**Falco's own health is monitored:** a missing heartbeat from any node's Falco pod raises an alert. "Detection quietly turned off" is itself a detection.

## 4. Managing alert fatigue

Alert fatigue is how runtime detection fails in practice. Rules:

1. **Two-week audit-only baseline** per namespace before any rule pages anyone. Tune from real traffic, not guesses.
2. **Three tiers:** *Critical* (escape, credential access, `cluster-admin` binding) pages on-call 24×7. *High* opens a ticket for next business day. *Everything else* goes to the SIEM for hunting and trend dashboards only.
3. **Every paging rule has a runbook and an owner.** No runbook, no page.
4. **Exceptions as code:** Falco `exceptions` blocks in Git with a ticket reference and an expiry, reviewed like any other change. No ad-hoc silencing in the console.
5. **Per-rule metrics, reviewed weekly:** fires per week, % actioned, % closed as benign. A rule that's >90% benign for a month gets tuned or downgraded.
6. **Deduplicate and enrich in Falcosidekick:** one alert per pod per rule per window, enriched with namespace owner, image digest and the Module 1 finding ID where relevant.

## 5. Incident scenario: confirmed container escape attempt

**Setup:** Falco fires *Terminal shell in container* on pod `payments-api-7f9c…` in namespace `citizen-payments` on node `ip-10-20-3-41`, then *Drop and execute new binary in container*, then *Detect release_agent File Container Escapes* (a known cgroups escape technique). The pod's hardening should make that escape fail, but GuardDuty then reports the node's role calling `sts:GetCallerIdentity` from an unusual IP, so we have to assume it may have succeeded.

**Roles:** Incident Commander (IC, platform security lead), Technical Lead (platform engineer), Comms (service delivery manager), Scribe. Contact list and out-of-band channel (not hosted on the affected cluster) are pre-agreed.

### Phase 1: Detect and triage (T+0 to T+15 min)
- On-call acknowledges the page and confirms it's not a known test or exception.
- Scope fast: same image on other pods? Same rule on other nodes? Any audit-log activity from this pod's SA or the node's role in the last 24h?
- Declare an incident, severity *High → Critical* if escape is confirmed. IC opens the timeline.

### Phase 2: Contain without destroying evidence (T+15 to T+45 min)

The instinct is to `kubectl delete pod`. That destroys the memory, the process tree and the container's writable layer, which is most of the evidence. Instead:

| Step | Action | Why it preserves evidence |
|---|---|---|
| 1 | **Capture volatile evidence first** (§6), unless active exfiltration is visible in flow logs. If it is, isolate first and capture second. | Order matters: isolation changes the process's behaviour. The IC makes that call explicitly and logs it. |
| 2 | **Orphan and isolate the pod.** Remove its `app` label and add `quarantine=true`. The ReplicaSet releases it and starts a clean replacement, and the Service and every app-specific allow policy stop selecting it. NetworkPolicies only ever *add* permissions, so isolation comes from nothing allowing it: the namespace-wide allows (DNS) exclude `quarantine=true` pods, and the pre-staged `quarantine` policy makes the deny explicit. Depending on the CNI, connections already open may survive, which step 4 covers. | Pod keeps running for analysis. Service continues on the clean replica. One label change; no `exec` into the container. |
| 3 | **Cordon the node** (`kubectl cordon`), don't drain. | No new workloads land on a possibly compromised host. Draining would kill the evidence. |
| 4 | **Isolate the node at the network layer:** swap its ENI security group to a pre-built *forensics* SG that allows only the forensic workstation's range. | Contains anything already running at host level, which pod-level policy can't. |
| 5 | **Cut credentials:** revoke active sessions on the node IAM role (or the pod's own role, once Pod Identity is in place, F-19); rotate every secret the pod's SA could read; disable the pod's SA by removing its RoleBindings. | The attacker's stolen tokens stop working even if they've copied them elsewhere. |

### Phase 3: Eradicate (T+1h to T+1 day)
- Establish the entry point from the evidence: application vulnerability? leaked credential? malicious image?
- Hunt for persistence in the audit log since first activity: new SAs, RoleBindings, CronJobs, DaemonSets, webhook configurations, images pushed to ECR, IAM changes in CloudTrail.
- Fix the root cause: patch and rebuild the image through the normal pipeline (no hotfix that bypasses the gates), add the missing policy or detection.
- **Replace, don't clean:** terminate the node (after evidence capture) and let the node group replace it. Assume anything on that node, including other pods' secrets, is compromised and rotate accordingly.

### Phase 4: Recover (T+1 day onward)
- Redeploy from Git at a known-good, signed digest; Argo CD shows drift if anything else changed.
- Raise Falco sensitivity on that namespace for 30 days.
- Close the incident when: root cause fixed, credentials rotated, no recurrence for 72 hours, and evidence archived.

### Phase 5: Learn (within 5 working days)
Blameless post-incident review. Output: timeline, root cause, what detection worked and what didn't, actions with owners and dates. Each action goes into the findings register or the pipeline gates, so the review leads to a change.

## 6. Forensic evidence: what, how, and without tipping off the attacker

**Principle:** collect from *outside* the container wherever possible. An attacker with a shell in the pod sees new processes inside the pod's PID namespace (an `exec`'d shell, a debug tool). They don't see node-level or cloud-level collection.

| Evidence | How | Visible to attacker in the pod? |
|---|---|---|
| Pod spec, events, owner references, SA, image digest | `kubectl get pod -o yaml`, `kubectl get events` | No |
| Falco events, audit log slice, CloudTrail, VPC flow logs, DNS logs | Already shipped to the log archive; query from the SIEM | No |
| Container memory and process state | **Kubelet checkpoint API** (`ContainerCheckpoint`, beta and on by default since Kubernetes 1.30) creates a CRIU checkpoint of the running container without stopping it. Needs runtime support (CRI-O, or containerd 2.x); confirm on the node AMI as part of IR readiness, and fall back to node memory capture if absent. | No (pauses the container briefly) |
| Container filesystem changes | From the node via SSM: `crictl inspect` to find the container's overlay upper dir, then tar and hash it | No |
| Process tree, open sockets, loaded binaries | From the node: read `/proc/<host-pid>/` for the container's processes | No |
| Node disk | EBS snapshot of the node's volumes | No |
| Node memory | AVML via SSM Run Command, written straight to the forensic bucket | Only if the attacker already has *host* access, in which case they'd see the process. Accepted; done after the pod checkpoint. |

On Bottlerocket nodes, node-level collection runs through Bottlerocket's admin container, enabled only for the incident and logged through SSM.

**Chain of custody:** every artefact is SHA-256 hashed at collection, written to a forensic S3 bucket in the security account (Object Lock in compliance mode, KMS key restricted to the IR role), and logged in the incident timeline with collector, time and hash.

**What we avoid:** `kubectl exec` into the pod, killing processes, restarting the pod, or changing anything inside the container before capture. Each of those either alerts the attacker or destroys evidence.

## 7. Communicating with the ITSO-equivalent

**During the incident:** short, factual and on a fixed schedule, over the out-of-band channel.

- **First notice** within the programme's mandated reporting window for the severity (I'd plan for within 1 hour of confirming a Critical): what was detected, the affected service, whether citizen data might be involved, and what we've done so far. Unknowns are stated as unknowns.
- **Situation reports** every 2–4 hours (agreed at first notice), same five headings every time:
  1. What we know now (and what changed since the last update)
  2. What we don't know yet
  3. What we're doing next
  4. **Decisions needed from you** (e.g. "approve taking payments offline for 30 minutes to replace nodes")
  5. Time of next update
- No speculation about attribution or root cause until it's evidenced. Wrong early statements are hard to retract.

**After the incident: the post-incident report.** Written for a governance audience:
- One-paragraph summary: what happened, impact, current status.
- Impact: services affected, duration, whether citizen data was accessed (and the evidence for that conclusion).
- Timeline (from the scribe's log).
- Root cause, and the contributing factors (usually several findings in combination, like the chains in Module 1).
- What worked and what didn't, including detection time and containment time.
- Actions: owner, date, and the risk each one reduces.
- Residual risk, and whether any risk acceptance needs to be revisited.

The difference between the two: during the incident the ITSO needs *decisions and confidence that it's under control*; afterwards they need *assurance that it won't recur and evidence for the auditors*.
