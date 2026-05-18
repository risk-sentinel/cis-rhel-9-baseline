# Red Hat Enterprise Linux 9 CIS Baseline

InSpec / CINC Auditor profile validating a Red Hat Enterprise Linux 9 host against **CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0**.

## Status

🚧 **Scaffolding only.** This repository was provisioned ahead of profile content extraction. The XCCDF source is currently in `risk-sentinel/sparc-validate` (`benchmarks/xccdf/CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0_xccdf.xml`); profile generation via `tools/xccdf_to_inspec/scaffold.py` is upcoming.

Track scaffolding work in [sparc-validate#122](https://github.com/risk-sentinel/sparc-validate/issues/122) (Phase 1 — extract / publish each CIS profile to its own repo).

## Scope (planned)

- **Red Hat Enterprise Linux 9.x.** All minor versions covered under the v2.0.0 benchmark.
- **Profile levels:** Level 1 Server, Level 2 Server, Level 1 Workstation, Level 2 Workstation (XCCDF-selectable).
- **Transport:** host-side (`-t ssh://`, `-t local://`); not AWS-API-bound. The cinc-auditor runner needs network reach to the target RHEL host and credentials per consumer policy.

## Repository conventions (per Risk Sentinel standard)

- Profile name + benchmark version pinned in the repo name (`cis-rhel-9-v2.0.0`); future benchmark versions land in their own repo.
- Apache-2.0 license; CODEOWNERS = owner-only merge with admin bypass per the org branch-protection model.
- Profile content (controls, libraries, inspec.yml, inputs.yml) lands via the Phase 1 extraction work, not pushed to this repo directly until then.
