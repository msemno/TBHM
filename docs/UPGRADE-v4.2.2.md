# Install and use TBHM 4.2.2

## Installation

Extract `TBHM-4.2.2-linux-x86_64.zip`, enter `TBHM-4.2.2`, and run:

```bash
bash install.sh --offline
./tbhm --version
./tbhm --help
```

This package targets Linux x86-64, Python 3.12 and glibc 2.27+. The installer
verifies the release manifest and installs the ten hash-locked core dependencies
from bundled wheels into `.venv`; optional scanners and model weights are separate.
Use `bash install.sh --python /path/to/python3.12` to select an interpreter.

Keep the prior release in its own directory. Existing result directories and
SQLite schemas remain readable. Review the deliberate changes in the changelog
before resuming a previous run. Historical manifests/documentation are retained;
the current manifest is `RELEASE_MANIFEST-v4.2.2.json`.

## Local analysis with kernel-enforced offline mode

```bash
./tbhm --offline --profile passive_only \
  --code-dir /absolute/path/to/source \
  --no-ai-observe -o ./results/source-offline
```

Offline denies sockets in the CLI and its descendants. It also denies local
Ollama/model HTTP services and UNIX-socket services. A missing kernel capability
fails with exit 77; there is no fallback to network-enabled execution. Existing
approved offline adapter allowlists remain in force. This isolates network
syscalls, not filesystem access or arbitrary hostile local programs.

For an already installed local model during source-only passive analysis:

```bash
./tbhm --profile passive_only --code-dir /absolute/path/to/source \
  --local-llm --local-llm-model YOUR_INSTALLED_MODEL \
  --local-llm-url http://127.0.0.1:11434 --no-ai-observe \
  -o ./results/source-with-local-model
```

Model advice remains non-authoritative. This release does not train or benchmark
a model, install weights, or convert scanner hypotheses into training labels.

## Two-account private API object replay

1. Create two dedicated owned test accounts and one private object belonging to
   the owner account. Record the actual JSON object ID and owner field/value.
2. Copy and edit `examples/api-authz-plan.json` and
   `examples/api-authz-policy.json`. Replace every example host/path with the
   reviewed scope. The missing-object control must be a distinct explicit URL on
   the same scheme/host/port, also allowed by the program policy.
3. Set `accounts[].id` to stable labels. If the response's owner field differs
   from the owner label, set `cases[].owner_value` to its expected string/integer.
   Dotted dictionary paths such as `data.id` and `data.ownerId` are supported.
4. Set `owned_test_account=true`, `owned_test_object=true` and
   `expected_challenger_access="deny"` only for the owned fixtures and reviewed
   access rule. These declarations are prerequisites, not vulnerability proof.
5. Supply the full Authorization header values through the environment names
   referenced in the plan. For Bash, avoid placing secrets in command history:

```bash
read -rsp 'Owner Authorization header: ' TBHM_OWNER_AUTH
export TBHM_OWNER_AUTH
read -rsp 'Challenger Authorization header: ' TBHM_CHALLENGER_AUTH
export TBHM_CHALLENGER_AUTH

./tbhm -u https://api.example.test \
  --api-authz-plan ./my-owned-object-plan.json \
  --program-policy ./my-reviewed-policy.json \
  --approve-api-authz -y --no-bootstrap --no-ai-observe \
  -o ./results/owned-object-replay

unset TBHM_OWNER_AUTH TBHM_CHALLENGER_AUTH
```

Without explicit `--phases`, the new plan chooses a narrow authorization,
validation, coverage and reporting workflow. It does not start broad recon.
An explicit `--phases` list remains the manual override: it must include
`authenticated_session_model` to execute the plan.

Each case sends at most six GET requests, with up to twenty cases per plan:

| Capture | Identity | URL | Required observation for confirmation |
|---|---|---|---|
| Baseline | Owned owner | Explicit private object | 2xx; exact object and owner |
| Mutation | Owned challenger | Same object | Same exact owner/object under distinct credentials |
| Negative control | Challenger | Explicit nonexistent/denied object | 401/403/404; does not expose protected object |
| Privacy control | Anonymous | Same private object | 401/403/404; no protected object |
| Repeat 1 and 2 | Challenger | Same mutation request | Two distinct authenticated captures of the same failure |

Confirmation requires all controls, capture integrity and repeatability. Expired
credentials, public data, HTTP 200 alone, redirects, timeouts, missing owner
fields, exhausted budgets and tampering never confirm BOLA. Unconfirmed outcomes
remain inconclusive; they do not certify the API as secure. BFLA, write operations,
cleanup, account login/refresh and automatic tenant enumeration are not implemented
by this replay module. Non-JSON or ownerless APIs require separate manual proof.

The policy's GET/action/rate ceilings and exact URLs apply to every request. This
module uses the native shared request budget. It does not make arbitrary external
scanner traffic globally metered. HTTPS certificate checks remain enabled;
interception uses the existing approved CA configuration.

## Outputs

- `OPERATOR.html`: existing searchable review queue and evidence links.
- `REPORT_final.html`, `REPORT_final.md`, `report.json`: normal report pipeline.
- `evidence/api_authorization/results.json`: case outcomes, reasons and references.
- `evidence/captures/`: sanitized, authenticated capture records; the signing key
  stays private in the original run.
- `compliance/test_id_coverage.json`: partial execution-backed WSTG/API/ASVS mapping.
- `evidence_manifest.json` and `delivery/run-*/`: sealed sanitized delivery snapshot.

Do not publish a signing key or assume a delivery digest is independent third-party
attestation. Keep the original run for trusted proof revalidation. The operator
view and existing reporting flow remain the review surface.

## Reproduce validation

```bash
.venv/bin/python scripts/run_tests.py --workers 3 --output /tmp/tbhm-4.2.2-tests.json
.venv/bin/python scripts/evaluate_api_authz_v422.py --output-dir /tmp/tbhm-api-fixtures
.venv/bin/python scripts/evaluate_proof_fixtures_v421.py --output-dir /tmp/tbhm-proof-fixtures
.venv/bin/python scripts/build_release_manifest.py --check
.venv/bin/python scripts/validate_v4_release.py
```

The runtime API corpus is intentionally small and synthetic. Its four scenario
types, each repeated twice, measure the listed controlled replay behavior. It
does not establish field precision/recall, independent project generalization,
complete standards coverage, or any bounty payout record.
