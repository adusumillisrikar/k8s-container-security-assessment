# Remediation Advisory Pack (Module 6)

For delivery engineers. You don't need a security background to follow this. Each item explains what's wrong in plain terms, gives the steps or the corrected code, and says exactly what evidence closes it.

The three items are the top Critical findings from the [findings register](../01-findings/findings-register.md): **F-01**, **F-02** and **F-03**. They're the three that each give an attacker the whole cluster or a whole server from a single starting point. (F-04 is also Critical but isn't deployed today; deleting the chart closes it.)

A few words used below:
- **Cluster:** the group of servers (nodes) that run all our containers.
- **Node:** one of those servers.
- **Service account (SA):** the identity a pod or a pipeline uses to talk to the cluster, like a user account for software.
- **RBAC:** the rules for what each identity is allowed to do.

---

## 1. F-01: The CI job's identity can do anything in the cluster

### What's wrong, in plain terms

The account our CI pipeline uses to deploy has `cluster-admin`, the master key. It can read every password stored in the cluster, change or delete any application, and create new admin accounts for itself.

That matters because a lot of code runs in CI: every developer's branch, every build tool, and every third-party package those tools download. If any one of those is malicious or compromised, it runs with the master key. It's like giving the building's master key to the courier desk because couriers sometimes need to drop things on the third floor.

### Fix it

**Step 1: Find out what the pipeline actually deploys.** Look at the deploy job's manifests (or Helm chart). Write down the kinds of objects it creates (typically Deployments, Services, ConfigMaps, Ingresses) and the namespaces it deploys to.

**Step 2: Create a limited Role in each target namespace.** Use [`fixed-manifests/ci-deployer-rbac.yaml`](fixed-manifests/ci-deployer-rbac.yaml) as the template. It allows create/update on exactly those object types in exactly one namespace. It deliberately does **not** allow reading Secrets, changing permissions (RBAC), touching anything cluster-wide, or `exec` into pods.

**Step 3: Give CI a short-lived identity instead of a stored token.** The GitLab job gets a temporary AWS role through OIDC (no stored keys), and an EKS access entry maps that role to the group in the RoleBinding. The command is in the comment at the top of the template. Ask the platform team to create the access entry; it's a one-line change in their Terraform.

**Step 4: Test in staging.** Run the pipeline against staging. If a deploy fails with `forbidden`, the error names the missing permission. Add *only that verb on that resource* to the Role, and note why in the MR.

**Step 5: Remove the old binding** once staging deploys work:

```bash
kubectl delete clusterrolebinding superadmin
kubectl delete serviceaccount superadmin -n kube-system
```

**Step 6: Stop it from coming back.** This is automatic once the Module 2 pipeline gate and the Kyverno policy are on; you don't need to do anything. Any MR that adds a `cluster-admin` binding fails, with a message pointing to this page.

### Evidence that it's fixed

| Check | Command | Expected result |
|---|---|---|
| No `cluster-admin` bindings except platform break-glass | `kubectl get clusterrolebindings,rolebindings -A -o json \| jq -r '.items[] \| select(.roleRef.name=="cluster-admin") \| .metadata.name'` | Only platform-owned bindings: the built-in `cluster-admin` (for `system:masters`) and, on EKS, `eks:addon-cluster-admin` (EKS's own add-on manager). Nothing bound to a CI or workload identity |
| The old account has no rights | `kubectl auth can-i --list --as=system:serviceaccount:kube-system:superadmin` | Only the default discovery permissions |
| CI can deploy but can't escalate | `kubectl auth can-i create clusterrolebindings --as=ci --as-group=ci-deploy:internal-proxy` | `no` |
| CI can't read secrets | `kubectl auth can-i get secrets -n internal-proxy --as=ci --as-group=ci-deploy:internal-proxy` | `no` |
| The gate blocks a regression | Open a test MR that re-adds the binding | Pipeline fails at `conftest-policy` with `[F-01]` |
| Admission blocks it too | `kubectl create clusterrolebinding test --clusterrole=cluster-admin --serviceaccount=default:default` | Rejected by Kyverno `disallow-cluster-admin-bindings` |
| Detection works | Same command with break-glass credentials in a test cluster | Falco `Binding To cluster-admin Created` alert reaches the SIEM |

Attach the command outputs and the failed-pipeline link to the change ticket.

---

## 2. F-02: The "system-monitor" app has root on the server, and an open web terminal

### What's wrong, in plain terms

This app's configuration switches off the walls between a container and the server it runs on:

- `privileged: true` gives it full root powers on the server.
- `hostPID` and `hostIPC` let it see and interfere with every other program on the server.
- The `hostPath: /` volume mounts the **entire server's disk** inside the app, writable.

On top of that, the image runs a **web-based terminal** (`gotty`) with no password. Anyone who can reach the app's port gets a command line with all those powers. From there they can read the passwords and data of every other app on that server, and steal the server's cloud credentials.

### Fix it

**Step 1: Work out what the app really needs.** It's called a "system monitor", so ask: does it need host-level metrics (CPU, memory, disk of the *server*)? If yes, that's what the platform's `node-exporter` already provides, read-only, in the `platform-node-agents` namespace. Use that data instead of running your own privileged pod.

**Step 2: Remove the web terminal from the image.** In `infrastructure/system-monitor/Dockerfile`, delete the gotty download and change `CMD` to start the actual monitoring app. If people need to debug, they use `kubectl exec`, which is permission-controlled and recorded in the audit log.

**Step 3: Apply the corrected manifest** [`fixed-manifests/system-monitor.yaml`](fixed-manifests/system-monitor.yaml). Compared with the original, it:
- removes `privileged`, `hostPID`, `hostIPC` and the host disk mount;
- runs as a normal user (`runAsNonRoot`, UID 10001) with a read-only filesystem and all Linux capabilities dropped;
- moves it into its own namespace with `pod-security.kubernetes.io/enforce: restricted`, so the cluster itself refuses any future change that brings back privileged mode, host access or running as root;
- gets its secret from the secrets store as a mounted file, instead of from a value committed to Git;
- pins the image by digest from our own registry.

**Step 4: Rotate the `goatvault` key.** It was committed to Git and was readable by anyone with a shell on the node, so treat it as known to an attacker.

**Step 5: Rebuild and deploy through the pipeline**, then check the evidence below.

### Evidence that it's fixed

| Check | Command | Expected result |
|---|---|---|
| No privileged or host-access pods outside the platform namespace | `kubectl get pods -A -o json \| jq -r '.items[] \| select(.metadata.namespace!="platform-node-agents" and .metadata.namespace!="kube-system") \| select(.spec.hostPID or .spec.hostIPC or .spec.hostNetwork or ([.spec.containers[].securityContext.privileged] \| any) or ([.spec.volumes[]?.hostPath] \| any)) \| .metadata.namespace+"/"+.metadata.name'` | Empty |
| Namespace enforces the restricted level | `kubectl get ns system-monitor -L pod-security.kubernetes.io/enforce` | `restricted` |
| The cluster refuses to run the old config | `kubectl apply -f <original deployment.yaml> -n system-monitor`, then `kubectl get events -n system-monitor` | Apply prints `Warning: would violate PodSecurity "restricted:latest": host namespaces, privileged, hostPath volumes...`; no pod starts, and the ReplicaSet shows `FailedCreate ... forbidden: violates PodSecurity`. (PSA blocks *pods*; the Deployment object itself is accepted, which is why Kyverno also checks at the Deployment level.) |
| No web terminal in the image | `trivy image --list-all-pkgs <image>` (or check the Dockerfile in the MR) | No `gotty` |
| Old key no longer works | Try the old key against its service | Rejected |

---

## 3. F-03: Typing into the "health-check" page can take over the server

### What's wrong, in plain terms

The health-check page asks for a server address and pings it. The code builds a command by gluing the user's text onto `ping -c 2 ` and hands the whole string to a shell. A shell treats characters like `;` and `|` as "and then run this too". So typing `8.8.8.8; cat /etc/passwd` runs both commands. That's called **command injection**, and it means anyone who can reach the page can run any command they like.

The container also runs **privileged**, which switches off the walls between it and the server: it can reach the server's devices and, for example, mount the server's disk. The configuration also tries to hand it the container engine's control socket. Either way, a text box becomes control of the server.

### Fix it

**Step 1: Fix the code.** Don't use a shell; check that the input is really a hostname or IP. Replace the POST handler in `infrastructure/health-check/main.go`:

```go
import (
	"context"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// A hostname: letters, digits, dots and hyphens, not starting with a hyphen.
var hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)

app.Post("/", func(c *fiber.Ctx) error {
	endpoint := strings.TrimSpace(c.FormValue("endpoint"))

	// 1. Accept only an IP address or a plain hostname. Anything else is refused.
	if net.ParseIP(endpoint) == nil && !hostnamePattern.MatchString(endpoint) {
		return c.Status(fiber.StatusBadRequest).Render("index", fiber.Map{
			"Title":  "Ping Your Servers",
			"Output": "Please enter a valid hostname or IP address.",
		})
	}

	// 2. Run ping directly, with no shell in between. The input is passed as a single
	//    argument, so characters like ; | $( ) are just characters, not commands.
	ctx, cancel := context.WithTimeout(c.Context(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ping", "-c", "2", "--", endpoint).CombinedOutput()

	result := string(output)
	if err != nil && result == "" {
		result = "Ping failed."
	}
	return c.Render("index", fiber.Map{"Title": "Ping Your Servers", "Output": result})
})
```

Two changes do the work: input validation (step 1 in the code) and no shell (step 2). Either one alone would stop this attack; we do both because the next developer might undo one of them.

**Step 2: Remove the server access from the deployment.** Apply [`fixed-manifests/health-check.yaml`](fixed-manifests/health-check.yaml). It:
- removes the container engine socket mounts and the host disk mount;
- removes the privileged init container and the privileged flag;
- drops all Linux capabilities. Ping normally needs a special network permission (`NET_RAW`); instead the pod turns on Linux's built-in unprivileged ping through a safe setting (`net.ipv4.ping_group_range`), so it can still ping with no extra powers;
- runs as a normal user on port 8080 (the Service still exposes port 80).

**Step 3: Rebuild the image from a smaller base.** The Dockerfile uses `golang:latest` (the whole Go compiler) as the runtime image. Use a multi-stage build: compile in `golang`, then copy only the binary into a minimal image that has `ping` and nothing else. Less software in the image means less for an attacker to use.

**Step 4: Deploy through the pipeline.** Semgrep in the pipeline now flags `exec.Command("sh", "-c", ...)` with user input, so the bug can't quietly come back.

### Evidence that it's fixed

| Check | How | Expected result |
|---|---|---|
| Injection no longer works | In staging, submit `127.0.0.1; id` in the form | "Please enter a valid hostname or IP address." and no `uid=` output |
| Normal use still works | Submit `8.8.8.8` (or an internal host) | Ping output |
| No socket or host mounts | `kubectl get deploy health-check -n health-check -o yaml \| grep -E 'hostPath\|sock\|privileged'` | No output |
| The cluster refuses to run the old config | `kubectl apply -f <original deployment.yaml> -n health-check`, then check events | PodSecurity warning on apply; ReplicaSet `FailedCreate ... violates PodSecurity "restricted:latest"`; no pod starts |
| The pipeline catches a regression | Test MR putting back `exec.Command("sh", "-c", ...)` | `semgrep-sast` job fails |
| Unit test in the repo | A test that posts `;id`, `$(id)`, `\|id` and `-c 1000` and expects HTTP 400 | Passes in CI |

---

## After all three

Re-run the Module 1 scanners against the fixed manifests and attach the clean results (see [`../01-findings/evidence/`](../01-findings/evidence/)). Then mark F-01, F-02 and F-03 as *Closed: verified* in the register, with links to the change tickets.
