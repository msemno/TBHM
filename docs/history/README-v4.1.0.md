# TBHM 4.1.0

The Bug Hunter Master: the complete Python tool, optional Go executor, existing
web/API/source/mobile/enterprise/firmware/reverse phases, profiles, templates and
reports in one installable distribution.

This distribution targets **Linux x86-64, glibc 2.27+, Python 3.12**. Python
3.12.14 is the tested interpreter. It includes all ten resolved core dependency
wheels. External scanners, browsers and local AI models remain optional and are
reported separately by the tool's diagnostics; a catalog entry does not mean an
integration is installed or its checks ran.

## Install

Extract the archive and enter `TBHM-4.1.0`, then run:

```bash
bash install.sh
./tbhm --version
./tbhm --help
```

Installation verifies the package and installs the hash-locked core into `.venv`
using the included wheels, without network access or system Python changes.
Use `bash install.sh --python /path/to/python3.12` if needed. `--online` explicitly
allows pip to fetch the same locked versions instead. A virtual environment
requires the interpreter's venv/ensurepip support. If you select `--venv PATH`,
run with `TBHM_PYTHON=PATH/bin/python ./tbhm ...`.

## Analyze local source

```bash
./tbhm --code-dir /path/to/project --offline \
  --phases code_scan,code_intel,report,evidence_finalize \
  --no-ai-observe -o /path/to/results -y
```

This generates native source findings and a local SBOM without publishing
project dependencies. Offline mode blocks repository cloning, native HTTP
requests, and external adapters without a local-analysis contract. Install the
optional scanners you need separately; their actual invocations and failures
are recorded in `execution_ledger.json`.

## Run an authorized web assessment

```bash
./tbhm -u https://app.example.com --profile authorized_safe \
  --rate-limit 2 --no-bootstrap -o /path/to/results -y
```

Replace the example with your authorized target. Existing CLI switches and
phase names are retained. Python Requests calls enforce target/policy checks,
shared rate/request budgets, verified TLS, explicit proxy settings and response
byte limits before evidence is consumed. Redirects are evaluated explicitly;
browser request interception checks destinations before navigation/subresources.
Child scanners use their adapter controls; their traffic is not measured by the
Python request counter. Avoid treating that counter as a cross-process traffic
quota. `--offline` is the supported zero-network analysis mode.

Automatic bootstrap downloads are disabled unless `--update-templates` is
explicitly requested. OSV dependency enrichment is opt-in through
`--allow-external-enrichment` and is always disabled by `--offline`.

## Read the results

- `REPORT_final.html` / `REPORT_final.md`: main report.
- `REPORT_confirmed.md`: only findings accepted by the current verifier.
- `execution_ledger.json`: planned phases, tool invocations, failures and blocked work.
- `evidence_manifest.json`: pointer to the sealed delivery snapshot.
- `delivery/run-.../`: final files, redaction scan, consistent SQLite backup and hashes.

A later resume creates a new delivery rather than rewriting the previous one.
Resume skips completed phases only when the effective configuration, targets and
local input contents match the saved fingerprint; changed inputs are rerun.
Deliver the snapshot directory. The working directory contains live state and
an owner-only capture key needed to validate recorded proof on resume. Do not
copy that private key into a client deliverable. Snapshot file permissions
prevent accidental edits; hashes detect tampering and are not digital signatures
by an independent third party.

## Verification and migration

Confirmation requires a version 2 class-specific contract, authenticated local
captures, matching target/request/identity bindings, a negative control, and two
distinct repeat captures. Supported automatic confirmation contracts currently
cover cross-actor object access, anonymous sensitive-data exposure, and controlled
open redirects. The native open-redirect detector records these controls and repeats itself.
Other detectors remain supported evidence or leads pending an
appropriate verifier. Imported flags, status codes, counters, scanner prose,
legacy `verified=true`, cached assessments and AI output cannot confirm a finding.

Existing databases retain their schema and record IDs. Opening an old database
redacts legacy credential text in place; legacy confirmation claims are retained
as evidence but require revalidation. Back up existing results privately before
migration if your retention process requires original credential-bearing data.
The trusted capture adapter API and proof format are documented in
`docs/PROOF-v2.md`.

Firmware, mobile and reverse integrations retain their existing capabilities.
Static Android manifest booleans are interpreted structurally; this does not
constitute a device test or complete effective Android security-policy analysis.
External tool versions, licenses, configurations and privileges remain operator
managed. Repository code is never intentionally executed by native source
analysis; external scanner sandboxes are not supplied by this core distribution.
ESLint uses a framework-owned config and Semgrep uses bundled local rules.

Full process capture is bounded at 64 MiB per stream (128 MiB hard maximum),
and individual sanitized output records at 16 MiB. An exceeded limit is reported
as incomplete output with a nonzero tool result rather than silently accepted.

## Check the installation

```bash
./.venv/bin/python scripts/validate_v4_release.py
./.venv/bin/python scripts/run_tests.py --workers 3
```

The suite runs independent copies of the tool. Details are written to
`/tmp/tbhm-4.1.0-test-results.json` by default. Release-specific tests include
forged/replayed proof, capture tampering, database reopen/redaction, live local
HTTP boundary checks and delivery snapshot integrity.

`RELEASE_MANIFEST-v4.1.0.json`, `RELEASE_INFO-v4.1.0.json`, `runtime.json`,
`requirements.lock`, `SBOM.cdx.json` and `vendor/licenses` describe this release.
Older release manifests/manuals are retained as project history. The previous
README and installer recipe are under `docs/history/`; the historical installer
is not the 4.1.0 installation entry point. Project licensing information is in
`NOTICE.md`.
