# cis-rhel-9 — verification coverage matrix

Profile authored from `CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0_xccdf.xml`
(sparc-validate#169). Principle: **verify the technical state wherever the host can
answer it; never accept a human attestation as proof of a checkable fact.**

Unlike the AWS profiles, this is a **host-OS** profile (`supports: platform: os`) —
the overwhelming majority of CIS RHEL-9 controls are directly assertable against a
running host via stock inspec-core resources, so verification is the default and
attestation is the narrow exception.

## Disposition

| Disposition | Count | Meaning |
|---|---|---|
| `implemented` (verified) | **277** | Direct host assertion via inspec resources / command audits |
| `alternative` — operational attestation | 19 | Site-architecture / governance / point-in-time facts not stably assertable |
| `alternative` — policy attestation | 1 | Consumer access-policy map (5.1.7) |

| CIS section | Verified | Attest | Primary verification mechanism |
|---|---|---|---|
| §1 initial setup | 74 | 3 | `kernel_module`, `mount`, `package`, `selinux`, `kernel_parameter`, `file` perms, `command` (grubby / `update-crypto-policies` / `CURRENT.pol` greps) |
| §2 services | 38 | 1 | `service`, `package`, `command` (chrony / cron perms via `file`/`directory`) |
| §3 network | 17 | 1 | `kernel_parameter` (sysctl), `service`, `command` |
| §4 firewall | 6 | 2 | `package`, `command` (`nft list ruleset`) — conditional per active back-end |
| §5 access/auth | 68 | 3 | `sshd_config`, `login_defs`, `command` (sudoers / faillock / pwquality / pwhistory / pam) |
| §6 logging & audit | 53 | 9 | `package`, `service`, `directory`/`file` perms, `command` (journald / rsyslog / `auditd` rules.d / aide / grubby) |
| §7 system maintenance | 21 | 1 | `file` perms (`be_more_permissive_than`), `command` (passwd/shadow/group integrity audits → empty offender lists) |

## Conditional applicability (14 controls → N/A when precondition unmet)

These are verified when applicable and render **Not Applicable** (`impact 0.0` +
`only_if`, the InSpec-7-safe two-statement form — `impact(<ternary>)` crashes the
InSpec 7 AST analyzer) when the precondition is absent:

- **§1.8.2–1.8.10 (GDM, 9):** `only_if { package('gdm').installed? }`. On the headless
  SPARC ASG (GDM removed per 1.8.1) these are N/A.
- **§4.2.2 firewalld loopback:** `only_if { service('firewalld').running? }`.
- **§4.3.1–4.3.4 nftables (4):** `only_if { !service('firewalld').running? }`.
  §4.2 (firewalld) and §4.3 (nftables) are mutually exclusive — exactly one path is
  active, the other is N/A.

## Attestation — why (not fabricated checks)

The 20 `alternative` controls are facts the host cannot stably assert; each carries a
skip-with-rationale + `attestation_category`. None is a checkable fact dressed as an
attestation.

**Policy (1):**
- **5.1.7 sshd access** — the `AllowUsers`/`AllowGroups`/`DenyUsers`/`DenyGroups` map
  is consumer access policy; there is no fixed correct value to assert.

**Operational (19) — site-architecture / governance / point-in-time:**
- **1.1.1.9** unused-fs-module catch-all — the explicit modules are verified (1.1.1.1–8);
  this residual has no fixed allowlist to assert.
- **1.2.1.4 / 1.2.2.1** repository sources & patch currency — site mirrors / patch
  cadence; a point-in-time `dnf check-update` is not a stable control assertion.
- **2.1.22** approved listening services — consumer-specific service inventory (the
  *technical* listening surface is verified via the §2.1 service-state checks).
- **3.1.1** IPv6 status — the CIS item only requires the posture be *identified/documented*,
  not a fixed state.
- **4.1.2** single firewall utility — front-end choice (firewalld vs nftables vs iptables);
  §4.2/§4.3 are guarded N/A on the non-chosen path.
- **4.2.1** firewalld permitted services/ports — consumer workload policy.
- **5.4.2.4** root-access control — IAM governance (console/break-glass, MFA on bastion);
  verified surface is covered by 5.2.7 (su) + 5.1.20 (PermitRootLogin).
- **5.4.2.5** root PATH integrity — only resolvable in an interactive root session,
  unavailable to the unprivileged scanner.
- **6.2.1.2 / 6.2.1.4** journald file-access & single-logging-system — deployment-specific
  logging architecture (journald-only vs rsyslog-primary).
- **6.2.2.1.1–6.2.2.1.3** systemd-journal-upload (send) — only applicable when forwarding
  to a central journald collector; site-specific.
- **6.2.3.3 / 6.2.3.5 / 6.2.3.6 / 6.2.3.8** rsyslog forward / routing rules / remote host /
  logrotate — depend on the chosen pipeline and org retention policy.
- **7.1.13** SUID/SGID review — the binary inventory is host-specific; no approved baseline
  to assert generically.

Where automation later becomes feasible (e.g., a fixed approved-service list, a known
remote log host), these can be promoted to `implemented` in a follow-up.

## Privilege note (exec)

A subset of the verified checks read root-only state and require the scanner to run with
adequate privilege (root or the relevant capability), or they will error rather than FAIL:
`nft list ruleset` (§4, CAP_NET_ADMIN), `grubby` (§1.4/§6.3.1), `/etc/shadow`-reading
audits (§7.2), and the audit-tool/`/var/log/audit` perm checks (§6.3.4). Provision the
scan principal accordingly before relying on results.

## Validation status

Statically validated on `risksentinel/sparc-auditor:v0.1.1` (amd64): `check` → **Valid,
297 controls, no offenses**; `json` → exit 0, all 297 serialize, **no library-load errors**.

✅ **`exec_validated` — exec'd `-t local://` (as root) against a live RHEL-9.6 (aarch64)
host (2026-06-05).** All 297 controls ran: **126 passed / 141 failed / 30 skipped, and
ZERO errored.** The zero-error result is the signal that matters: every control's
resource logic (the `command`/`file`/`mount`/`auditd`/`grubby`/`nft`/`/etc/shadow`
audits) executed cleanly against a real host — no `NoMethodError`/resource-API crashes,
which `check`/`json` cannot catch. The 141 failures are *real findings* on an
unhardened honeypot (expected — the host is not CIS-hardened), not profile defects.

Caveats:
- **267 controls** exercised their resource logic (the 126 passed + 141 failed).
- **30 skipped** = the 20 attestation controls (by design) + ~10 conditional controls
  whose `only_if` was false on this host — the §1.8 GDM controls (headless, GDM removed)
  and the non-chosen firewall path (§4.2/§4.3). Those would exercise their logic on a
  host with GDM / the alternate firewall back-end; they are N/A here, not unvalidated.
- Privilege: the run was as **root** (SSM `AWS-RunShellScript` default), so the
  root-only audits (auditd/`/etc/shadow`/`nft`/`grubby`) executed rather than erroring.
