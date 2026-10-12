# Compensating Controls for the COTS Container (Module 7)

## 1. The assumed gap

The brief doesn't name the product, so here's a concrete, realistic assumption. Everything below is built against it.

> **`cots-casemgmt:4.2`**, a vendor case-management product shipped as a container image, used by a citizen-facing service.
> - Built on **CentOS 7**, end-of-life since June 2024, so OS packages get no more fixes. Trivy reports a set of Critical and High CVEs in OS packages (e.g. glibc, openssl) with no fixed version available in that base.
> - **Runs as root** (UID 0) and **needs a writable root filesystem**, because it writes to its install directory at runtime.
> - Phones home to a **vendor licence server** over HTTPS.
> - The vendor won't rebuild the image on a supported base without a paid support contract.

So it **cannot** meet PSA `restricted` (F-20), will **always fail** the Trivy hard-fail gate (F-26), and runs root inside the container. Those are the gaps being compensated for. Everything else (privileged, host access, secrets in Git) is still mandatory and has no exception.

## 2. Compensating controls

Each control comes from a design already in this pack, not a one-off. They're layered so that no single one is relied on.

### Control 1: Admission: a narrow, explicit exception (Modules 2 and 6, F-06)

- Dedicated namespace `cots-casemgmt` at PSA **`baseline`**, not `restricted`. Baseline still blocks privileged mode, host namespaces, `hostPath` and dangerous capabilities. What it relaxes is running as root and the extra hardening `restricted` requires (dropping all capabilities, no privilege escalation, seccomp), so the namespace's own Kyverno policy puts back every one of those the product can live with:
- A Kyverno policy scoped to this namespace only:
  - **only one image allowed: the exact vendor digest** we received, mirrored into our ECR, scanned, and **signed by us** after review. We can't make the vendor sign; we can make sure nothing else runs in its place.
  - `capabilities.drop: [ALL]`, adding back only what the vendor's documentation says it needs (typically `CHOWN`, `SETUID`, `SETGID`), with each one justified in the exception record;
  - `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`;
  - writable paths limited to named `emptyDir` volumes where the vendor allows it, so the rest of the filesystem can be read-only if the product tolerates it (to be tested).
- **User namespaces (`hostUsers: false`):** root inside the container maps to an unprivileged UID on the node. That directly reduces what "runs as root" means if the container is broken out of. It's on by default from Kubernetes 1.33, but needs a recent kernel and containerd 2.x on the node AMI, so it's **to validate on our node image** before we rely on it. If it works, it's the strongest single control here.
- The pipeline's Trivy gate gets a **recorded exception** for this image digest only: finding IDs listed, owner named, 90-day expiry. A *new* Critical CVE not on the list still fails the build.

### Control 2: Network: tight containment (Module 4, F-12)

- **Dedicated, tainted node group** (`workload=cots:NoSchedule`) so the COTS pods never share a node with citizen-facing services or platform components. A container escape lands on a node that holds nothing else worth stealing. The node role has the minimum AWS policy and no extra permissions.
- **Default-deny NetworkPolicy**, then exactly:
  - ingress from the internal ALB subnets on the app port only;
  - egress to its database (RDS, TLS) on 5432 only;
  - egress to the vendor licence server on 443 only: `0.0.0.0/0` except private and link-local ranges (carrying the platform-security approval annotation the pipeline requires), so it leaves via **AWS Network Firewall** with **one domain allowlisted** (the licence host). Nothing else on the internet is reachable.
- **IMDSv2 hop limit 1** on that node group, so the container can't reach node credentials.
- If it's internet-facing: **AWS WAF** in front, with managed rule groups and, where a CVE is web-exploitable, a specific rule as a **virtual patch**.

### Control 3: Runtime: a strict behavioural baseline (Module 3)

The vendor image never changes between vendor releases, so its normal behaviour is very predictable. That makes runtime detection for it *more* reliable than for our own fast-moving services.

- Falco rules scoped to `k8s.ns.name = cots-casemgmt`, all at **Critical**:
  - any shell spawned (`sh`, `bash`), any package manager, any `curl`/`wget`;
  - any binary executed that isn't in the image (drop-and-execute);
  - any outbound connection not to the DB or the licence host (backstop for the firewall);
  - writes outside the known writable directories.
- Because false positives here are close to zero after the two-week baseline, this is the one namespace where I'd recommend **automated response in phase 1**: on drop-and-execute, remove the pod's `app` label and add `quarantine=true` (Module 3, Phase 2). The ReplicaSet starts a clean pod from the signed image, and the bad one, now selected by no allow policy, is kept for forensics.

### Control 4: Data and identity (Module 5)

- Its own `SecretStore` and IAM role; DB credentials from Secrets Manager, mounted as files, rotated every 30 days. If the product can't re-read files, Reloader does a rolling restart.
- DB user has least privilege on its own schema only. Database activity streaming or audit logging is turned on for that DB.

### Control 5: Vulnerability tracking

- The vendor image's SBOM goes into Dependency-Track like every other image.
- Daily check against the **CISA Known Exploited Vulnerabilities** catalogue. If any CVE in this image appears on KEV, that **reopens the risk acceptance immediately**, not at the next quarterly review.

## 3. Residual risk

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** (no controls: root, EOL base, unpatched CVEs, shared nodes, flat network) | Likely | Major: container compromise → node → neighbouring citizen services | **High** |
| **Residual** (controls 1–5 in place) | Unlikely: exploitation needs a reachable vulnerable code path through WAF and a 3-flow network allowlist, and the exploit's next step is detected | Moderate: blast radius limited to the COTS service and its own database | **Medium** |

**What's still not covered, stated plainly:** a remote code execution vulnerability in the COTS application itself, reached through its legitimate ingress path, would still give an attacker the application's own data. The controls limit where they can go next and make sure we see it; they don't stop the first step. That is the risk being accepted.

**Who accepts it:** the **system owner** (the business owner of the service using the COTS product), with the **ITSO-equivalent endorsing**. Not the platform team and not security. The people who benefit from running the product, and who could fund the support contract, own the decision to run it with known gaps. Security's role is to state the risk accurately and recommend.

**Conditions on the acceptance:**
- valid for **6 months**, reviewed quarterly at the risk forum;
- automatically reopened if: a CVE in the image is added to CISA KEV; Falco fires a Critical in the namespace; or the vendor ships a new major version;
- controls 1–3 must be verified in place (evidence attached) before go-live, or the acceptance doesn't take effect.

## 4. Time-bound plan

| When | State | Actions |
|---|---|---|
| **Before go-live** | Interim | Controls 1–5 implemented and evidenced. User-namespace test on the node AMI. Risk acceptance signed. |
| **0–3 months** | Interim, monitored | Get a **quote for the vendor support contract** and put it next to the running cost of these controls (dedicated node group, firewall rule upkeep, exception reviews, risk of an incident) so the system owner makes a funding decision with real numbers. Ask the vendor for their roadmap to a supported base image and non-root support. |
| **3–6 months** | Decision | One of: (a) support contract signed → vendor rebuilds on a supported base, non-root; (b) vendor offers a SaaS version → evaluate migrating; (c) licence permits us to rebuild the image ourselves on a supported base → do it in our pipeline; (d) none of these → replace the product, plan tabled at the 6-month review. |
| **Target state** | | Image on a supported base, runs as non-root, passes the standard pipeline gates with no exception, namespace back to PSA `restricted`, dedicated node group retired. |

The point of the plan: the exception is a funded, dated path to removing it, not a permanent state.
