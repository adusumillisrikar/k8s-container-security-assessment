# Compliance Mapping (Module 9)

## 1. Approach

The programme's internal compliance clauses aren't available, so this shows the **method** I'd apply once they are. The method doesn't depend on knowing the clause numbers in advance. It works from the control *domain* down, so when the real standard arrives, it's a lookup-and-confirm exercise rather than a re-analysis.

For each finding:

1. **Domain:** which of the five control domains the finding falls in. Some findings touch two; pick the primary one and note the other.
2. **Control objective:** what a reasonable government standard in that domain would require, in plain words. That's the hook the real clause will attach to.
3. **Public anchors:** the equivalent controls in public frameworks (CIS Amazon EKS Benchmark, NIST SP 800-53 Rev. 5). Government standards usually derive from these, so they predict where the real clause will sit, and they give auditors a reference they already recognise.
4. **Test:** how compliance is checked. Automated wherever possible.
5. **Evidence:** what's produced, where it's kept, how often it's refreshed.
6. **Status and exception path:** compliant, non-compliant with a remediation date, or exception with compensating controls and a named risk owner.

**Two landing zone tiers, two evidence models.** The newer tier has continuous compliance monitoring (AWS Config and Security Hub), so most evidence below is a standing control result that's refreshed automatically. The older VPC-per-environment tier doesn't, so the same checks run as a scheduled pipeline job that writes a dated evidence file to the log archive. Same tests, same evidence format, different collection. When the older tier is migrated, the scheduled job is retired.

> CIS references use the CIS Amazon EKS Benchmark v1.x numbering, and Security Hub references use AWS Foundational Security Best Practices control IDs. Both should be confirmed against the versions the programme has adopted.

## 2. Five findings mapped

### F-01: `cluster-admin` bound to a CI service account

| | |
|---|---|
| **Domain** | **Access control** (secondary: secure development lifecycle, since the binding arrived through the delivery pipeline) |
| **Control objective** | Privileged access is limited to named, approved roles; non-human identities get least privilege; privileged grants are reviewed periodically. |
| **Public anchors** | CIS EKS 4.1.1 (cluster-admin only where required), 4.1.3 (minimise wildcards); NIST 800-53 AC-6 (least privilege), AC-6(5) (privileged accounts), AC-2(7) (privileged role management) |
| **Test** | (a) Daily scheduled query of all RoleBindings/ClusterRoleBindings for `cluster-admin` or `*` rules, compared with an approved list. (b) Conftest gate result on every MR. (c) Kyverno policy report showing zero violations. |
| **Evidence** | Daily JSON export of bindings plus diff against approved list (log archive, 1 year); pipeline gate history; Kyverno `PolicyReport`; quarterly access review sign-off by the platform owner. |
| **Status** | Non-compliant → remediate before go-live (P0). No exception offered: there's no business need that a namespace-scoped Role can't meet. |

### F-23: Secrets not envelope-encrypted with a customer-managed key

| | |
|---|---|
| **Domain** | **Encryption** |
| **Control objective** | Sensitive data at rest is encrypted with keys the agency controls; key use is logged; keys are rotated. |
| **Public anchors** | CIS EKS 5.3.1 (Secrets encrypted with KMS CMK); NIST 800-53 SC-28 (protection at rest), SC-12 (key management); Security Hub `EKS.3` |
| **Test** | Security Hub `EKS.3` (newer tier, continuous); `aws eks describe-cluster --query cluster.encryptionConfig` in the scheduled job (older tier); KMS key rotation enabled; CloudTrail shows `Decrypt` calls only from the EKS service role. |
| **Evidence** | Security Hub finding history or dated `describe-cluster` output; KMS key policy export; key rotation status. |
| **Status** | Non-compliant → remediate before go-live (cheap). Worth noting in the evidence pack: before the fix, data was still encrypted at rest with AWS-managed keys, so the gap was *key custody*, not plaintext data. That matters if the auditor asks whether there was an exposure. |

### F-16: Control-plane and audit logging disabled

| | |
|---|---|
| **Domain** | **Logging and monitoring** |
| **Control objective** | Security-relevant events (authentication, privilege use, configuration change) are logged, protected from tampering, retained per policy and monitored. |
| **Public anchors** | CIS EKS 2.1.1 (enable audit logs); NIST 800-53 AU-2 (event logging), AU-9 (protection of audit information), AU-6 (review and analysis), SI-4 (system monitoring); Security Hub `EKS.8` |
| **Test** | Security Hub `EKS.8` / `describe-cluster` shows all five log types enabled; the log archive bucket has Object Lock on and no delete permission for cluster admins; a weekly synthetic test (create and delete a test RoleBinding in a sandbox namespace) confirms the event reaches the SIEM and the alert fires. |
| **Evidence** | Config/`describe-cluster` output; bucket policy and Object Lock configuration; synthetic-test results (dated) showing end-to-end detection. |
| **Status** | Non-compliant → remediate before go-live (P0). The synthetic test is the important piece of evidence: it proves the logging is *used*, not just switched on. |

### F-06 / F-20: No admission control or pod security baseline

| | |
|---|---|
| **Domain** | **Configuration baseline** |
| **Control objective** | Systems are configured to an approved hardened baseline; deviations are prevented or detected; exceptions are documented and approved. |
| **Public anchors** | CIS EKS 4.2.x (minimise privileged containers, host PID/IPC/network, privilege escalation, root containers); NIST 800-53 CM-6 (configuration settings), CM-7 (least functionality), CM-2 (baseline configuration) |
| **Test** | `kubectl get ns -L pod-security.kubernetes.io/enforce` shows every app namespace at `restricted`, with platform namespaces at a documented level; Kyverno `PolicyReport`s show zero `fail` results outside approved exceptions; monthly kube-bench run. |
| **Evidence** | Namespace label export (scheduled); Kyverno policy reports; exception register (Module 7 COTS entry) with approver and expiry; kube-bench report. |
| **Status** | Non-compliant → remediate before go-live. **Exception** for `cots-casemgmt` (PSA `baseline` instead of `restricted`) with compensating controls documented in Module 7, owned by the system owner and endorsed by the ITSO. This is the worked example of how an exception enters the compliance record. |

### F-17: Unpinned, unsigned images from an uncontrolled registry

| | |
|---|---|
| **Domain** | **Secure development lifecycle** (secondary: configuration baseline) |
| **Control objective** | Software deployed to production comes from controlled sources, is verified for integrity, and has a known composition. |
| **Public anchors** | CIS EKS 5.1.1 (image vulnerability scanning), 5.1.4 (minimise container registries to approved ones); NIST 800-53 SR-4 (provenance), SR-11 (component authenticity), SA-11 (developer testing), SI-7 (software integrity), CM-14 (signed components) |
| **Test** | Kyverno `verify-image-signatures` and `restrict-image-registries` policy reports; a query of all running pods' images confirms every one is a digest from programme ECR with a valid signature (`cosign verify`); Dependency-Track shows an SBOM for every running digest. |
| **Evidence** | Policy reports; dated output of the running-images verification job; Dependency-Track project list; pipeline logs showing the sign/attest step per release. |
| **Status** | Non-compliant → P1. Remediate before go-live where the pipeline is ready; otherwise exception with the registry allowlist enforced in the meantime, closing within 60 days. |

## 3. Exceptions: what a justified one looks like

Every exception in the compliance record has the same fields, so a governance board can compare them:

| Field | Example (COTS, F-06/F-20) |
|---|---|
| Finding / control | F-06, F-20 / configuration baseline: PSA `restricted` |
| What's not met | Container runs as root, writable root filesystem |
| Why it can't be met now | Vendor image; rebuild requires a paid support contract |
| Compensating controls | Module 7, controls 1–5, with evidence links |
| Residual risk | Medium (Module 7 §3) |
| Risk owner | System owner, Case Management service |
| Endorsed by | ITSO-equivalent |
| Expiry | 6 months from go-live; reopened on any KEV-listed CVE or Critical runtime alert |
| Exit plan | Module 7 §4 |

## 4. When the real standard arrives

1. Take each clause and tag it with one of the five domains.
2. For each finding already mapped here, find the clause in its domain that matches the control objective. Usually it's one or two.
3. Where the clause is stricter than the public anchor (e.g. a specific retention period or approval level), update the test and evidence rows. The finding status may change.
4. Where a clause has no matching test yet, that's a new gap. Add it to the register using the same severity method.

The evidence collection doesn't change in that process, because it was built around the domains rather than the clause numbers. That's the reason for working this way round.
