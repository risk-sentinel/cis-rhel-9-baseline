# CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0

InSpec / CINC Auditor profile validating SPARC environments against **CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0**.

## Scope

- **Target:** PostgreSQL server (RDS instance or self-managed on a
  unix host).
- **Platform family:** `unix`.
- No AWS partition logic, no `inspec-aws` resource pack.

Connection inputs (`pg_host`, `pg_port`, `pg_user`, `pg_password`, TLS
config, etc.) are **not yet defined** in `inputs.yml` — they will be
added as part of the describe-fill sub-issue for this profile. Until
then, `cinc-auditor check` passes but `exec` returns `skip` for every
control.

## Running Locally

Prerequisites: Docker. Network path to the target PostgreSQL server.

```bash
docker pull risksentinel/sparc-auditor:v0.1.1
```

Typical execution pattern once connection inputs land:

```bash
docker run --rm \
  --network host \
  -v "$PWD:/src" \
  risksentinel/sparc-auditor:v0.1.1 exec /src/profiles/cis-rhel-9 \
  --input pg_host=<host> \
  --input pg_port=5432 \
  --input pg_user=<user> \
  --input pg_password=<password> \
  --reporter cli json:/src/hdf.json
```

For RDS, the usual pattern is to run from a bastion or ECS task with
VPC and security-group access to the database.

## NIST 800-53 Tagging

Every control carries `tag nist: [...]` resolved at scaffold time from
the XCCDF's DISA CCI identifiers via Heimdall's
`CciNistMappingData.ts`. Provenance chain:

```
XCCDF <ident system="http://cyber.mil/cci">CCI-XXXXXX</ident>
    ↓ (lookup in heimdall2/libs/hdf-converters/src/mappings/CciNistMappingData.ts)
NIST 800-53 control (e.g. "AC-2 (3)")
    ↓ (emitted by tools/xccdf_to_inspec/scaffold.py)
tag nist: ['AC-2 (3)']
```

The scaffolder **fails loudly** if any rule has a CCI that is not
present in the map — we never ship controls with CCI-only tags.

## Regenerating From XCCDF

```bash
python3 tools/xccdf_to_inspec/scaffold.py \
  --xccdf benchmarks/xccdf/CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0_xccdf.xml \
  --cci-map /path/to/heimdall2/libs/hdf-converters/src/mappings/CciNistMappingData.ts \
  --output profiles/cis-rhel-9 \
  --profile-name cis-rhel-9 \
  --profile-title "CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0" \
  --supports-platform os --partitions "" --no-inspec-aws
```

Use `--only <cis-number>` to regenerate a single control.

## Status

Currently scaffolded — every `describe` body is `skip 'TODO[scaffolder]: …'`.
See the top-level `README.md` for the overall repo state and the
sub-issue tracker for per-profile describe-fill progress.

---

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_cis-rhel-9-v2.0.0)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_cis-rhel-9-v2.0.0)
