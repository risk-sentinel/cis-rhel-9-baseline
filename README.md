# cis-rhel-9-baseline

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_cis-rhel-9-baseline)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_cis-rhel-9-baseline)

InSpec / CINC Auditor profile validating a **Red Hat Enterprise Linux 9** host
against the **CIS RHEL 9 Benchmark v2.0.0** — 298 controls across filesystem,
services, network, logging and auditing, access control, and system maintenance.

The largest profile in the estate by control count.

---

## Where this runs

**On the RHEL host.** It reads real system state — package database, systemd
units, sysctl values, file permissions, PAM and SSH configuration:

```bash
# on the host
cinc-auditor exec . -t local:// --input-file inputs/mine.yml

# remotely, over SSH
cinc-auditor exec . -t ssh://user@host --input-file inputs/mine.yml
```

Root, or an account able to read the audit and PAM configuration.

### SSM-managed hosts

**There is no `ssm://` transport.** The auditor image carries train's `local`,
`ssh`, `winrm`, `aws`, `habitat`, `kubernetes` and `rest` transports and no SSM
plugin, so a host reachable only through Systems Manager — no inbound SSH, which
is the usual hardened posture — is scanned by running the profile *on the
instance* and keeping `-t local://`:

```bash
aws ssm send-command \
  --instance-ids i-0123456789abcdef0 \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["cd /opt/cis-rhel-9-baseline && cinc-auditor exec . -t local:// --input-file inputs/mine.yml --reporter json:/tmp/results.json"]'
```

Run it as root, then retrieve `/tmp/results.json` and feed it to the same
conversion steps the CI templates use. This is the path the profile was
exec-validated on.

Because the scan runs on the instance either way, `target_uri` defaults to
`local://`; set `ssh://user@host` only when the runner reaches the host over SSH.

---

## Quickstart

```bash
git clone https://github.com/risk-sentinel/cis-rhel-9-baseline
cd cis-rhel-9-baseline

cp inputs/example.yml inputs/mine.yml     # then edit — see Inputs below
cinc-auditor vendor . --overwrite

cinc-auditor exec . -t local:// \
  --input-file inputs/mine.yml \
  --reporter cli json:results.json
```

### What a first run looks like

**Validated against a live RHEL 9.6 host: 297 controls executed, zero errored.**
That is the meaningful measurement for this profile — it says the whole thing is
exec-correct against the platform it targets, which for 298 controls is the
thing worth knowing.

A run on a **non-RHEL** Linux host produces 298 controls and 456 results with
zero control source-code errors, but a pass/fail split that means nothing: the
controls execute and report against a system they were not written for. If you
are seeing a large number of unexpected failures, check that you are actually on
RHEL 9 before treating them as findings.

---

## Inputs

Fully documented in [`inputs/example.yml`](inputs/example.yml). Only nine, for
298 controls — because most of CIS RHEL is "is this setting correct", which has
one right answer.

| Group | Inputs |
|---|---|
| **Posture axes** | `host_lifecycle`, `log_pipeline`, `network_firewall`, `access_model`, `platform_class` |
| **Off-box logging** | `cloudwatch_audit_log_group`, `cloudwatch_audit_stream`, `cloudwatch_max_ingestion_lag` |
| **Image provenance** | `approved_ami_owners` |

**The five posture axes are fail-closed by design.** They route a control to the
evidence that actually applies to your host — an ephemeral cloud instance
evidences patching through its image pipeline, not through on-host package
state; a host behind security groups with no inbound SSH does not need the same
SSH hardening as one reachable interactively.

Every default is the **strictest** branch. Leaving an axis unset enforces the
full on-host requirement rather than accepting an off-host equivalent. That is
deliberate: an unset axis should over-assess, never under-assess. A default that
quietly excused a control would be far worse than one that produces a finding you
then scope correctly.

Each axis also accepts `auto`, which detects where it can.

---

## Controls

298 controls following the CIS RHEL 9 v2.0.0 sections:

| Section | Assesses |
|---|---|
| 1 | initial setup — filesystem modules, partitions, boot, SELinux, banners |
| 2 | services — inetd, special-purpose services, client packages |
| 3 | network — kernel parameters, firewall, wireless |
| 4 | access control — SSH, PAM, sudo, password quality and aging |
| 5 | logging and auditing — auditd rules, journald, logrotate, log shipping |
| 6 | system maintenance — file permissions, user and group settings |

---

## Producing evidence

A `--reporter cli` run tells you the answer. It does not produce something an
assessor can trace back to what was assessed, when, by whom, or from which
scanner output. For that, use the CI templates — the whole pipeline, in YAML
with no helper scripts behind it:

**GitHub**

```yaml
jobs:
  evidence:
    uses: risk-sentinel/cis-rhel-9-baseline/.github/workflows/exec-evidence.yml@main
    with:
      target: my-rhel-host
      boundary: my-boundary
      aws_region: us-east-1
      profile_name: cis-rhel-9-v2.0.0
      profile_version: "0.2.0"
      inputs_file: inputs/mine.yml
      # target_uri defaults to local://, which is correct when the job runs on
      # the host. Set ssh://user@host only when the runner reaches it over SSH.
```

**GitLab**

```yaml
include:
  - project: risk-sentinel/cis-rhel-9-baseline
    ref: v0.1.3
    file: /ci/gitlab/exec-evidence.yml
    inputs:
      target: my-rhel-host
      boundary: my-boundary
      aws_region: us-east-1
      profile_name: cis-rhel-9-v2.0.0
      profile_version: "0.2.0"
      inputs_file: inputs/mine.yml
```

`target`, `boundary`, `aws_region`, `profile_name` and `profile_version` are
required and have no defaults. A missing one is rejected before the job starts —
GitHub refuses the `workflow_call`, GitLab refuses the `include` — rather than
running against the wrong account or filing the results under the wrong label.
`inputs_file` defaults to `inputs/example.yml`, which runs with example values,
so set it to your own copy. See [docs/ci-templates.md](docs/ci-templates.md) for
the full contract, including which secrets are genuinely optional.

An `include:` brings YAML and nothing else, which is why the logic lives in the
YAML rather than in a script an including project would never receive. The
templates are carried in this repository on purpose: clone it or include it and
you have the entire pipeline, with nothing else to install.

### The order, and why it is that order

```
create passthrough -> execute -> convert (gate) -> apply -> label (gate)
                   -> validate (gate) -> display
```

The audit record is built **before** the scan, because that is when the honest
start time and the pipeline provenance are known. Only finish time, the artifact
digest and the outcome counts are added afterwards.

### Two artifacts

| artifact | shape | for |
|---|---|---|
| `results.final.json` | HDF v3 `baselines[]` | authoritative evidence — schema-validated, carries the audit record and typed target components, feeds `hdf convert --to oscal-sar` |
| `results-heimdall.json` | InSpec exec-json `profiles[]` | loading into Heimdall |

The Heimdall artifact is a **copy, not a conversion**. Tested against a live
Heimdall: every `profiles[]` variant loads, including the output of both
`--to hdf@1` and `--to hdf@2`; only the `baselines[]` v3 document is refused. So
the choice is fidelity, and every conversion path drops `resource_params` from
each result plus `depends` / `status` / `status_message` from the profile.
Copying what cinc-auditor already wrote loses nothing.

**Do not reach for `hdf convert --to hdf@2`.** The `hdf@N` namespace was
renumbered between hdf-libs 3.4.1 and 3.5.1 — on 3.4.1 it emits `baselines[]`,
on 3.5.1 `profiles[]` — so a pipeline pinned to it silently changes artifact
across an image bump. On 3.5.1, `@1` and `@2` are byte-identical.

### Three gates, each of which has failed silently in this estate

- `hdf convert` without `--no-validate`
- `hdf label` followed by `hdf label show | grep '^Component:'` — `label set`
  prints `Labels written` and writes a byte-identical file when the document has
  no components
- `hdf validate`

The exec step additionally fails the job on a missing or **zero-result**
artifact. A run that assessed nothing must not go green.

### The audit record

Written on every run — clean, failed, findings or none. Target, scan window,
scanner, profile and version, pipeline provenance, actor, converter, a sha256 of
the pre-conversion artifact, and outcome counts.

Two properties are deliberate: **absent is not empty** (an inapplicable field is
omitted, an undeterminable one is `null` with a reason), and the record **marks
which fields are corroborable** against systems the producer does not control.
An audit chain where every field is self-asserted is a story.

Schema authority: [dev-sec-ops-baseline#33](https://github.com/risk-sentinel/dev-sec-ops-baseline/issues/33).

---

## Consuming this profile

Depend on it rather than forking, so you get fixes:

```yaml
depends:
  - name: cis-rhel-9-v2.0.0
    git: https://github.com/risk-sentinel/cis-rhel-9-baseline.git
    tag: v0.1.1
```

Then `include_controls 'cis-rhel-9-v2.0.0'` and supply your own inputs. Input overrides
reach the depended profile's controls, so your values win without editing
anything here.

## Contributing

Control logic changes belong here. `cinc-auditor check` only *loads* a profile —
it will not catch a resource that returns empty because an API call failed.
Anything touching `libraries/` needs a real `exec` against a real target before
it is trusted.

## License

Apache-2.0. See [LICENSE](LICENSE).
