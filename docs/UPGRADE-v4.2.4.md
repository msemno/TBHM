# TBHM 4.2.4 — installation and strict read validation

Linux x86-64, Python 3.12, glibc 2.27+. Python 3.12.14 is the tested interpreter.
Keep previous versions separately and back up your results before any upgrade.
The main database schema is unchanged; no migration is introduced. A database
created by the actual 4.2.3 Storage implementation is covered by compatibility
tests for row semantics and evidence IDs.

```bash
unzip TBHM-4.2.4-linux-x86_64.zip
cd TBHM-4.2.4
bash install.sh --offline
./tbhm --version
```

The packaged wheels and hash lock are unchanged. Existing commands, aliases,
profiles, 145 phases, output contracts, BOLA workflow, LLM imports and corpus
governance remain available. Start with prior upgrade guides for their workflows.
Optional scanners and model runtimes remain separately installed.

## Strict read replay

The new input routes to existing preflight, controlled validation, reporting and
finalization phases. An explicit `--phases` selection remains authoritative.
Nothing active is enabled unless a reviewed plan, approval, target and program
policy are supplied.

```bash
export TBHM_ADMIN_AUTH='Bearer <owned privileged account token>'
export TBHM_MEMBER_AUTH='Bearer <owned limited account token>'
./tbhm -u https://owned-test.example \
  --strict-replay-plan ./reviewed-strict-plan.json --approve-strict-replay \
  --program-policy ./reviewed-policy.json \
  --no-ai-observe --no-bootstrap -o ./results/strict-read -y
unset TBHM_ADMIN_AUTH TBHM_MEMBER_AUTH
```

Use a synthetic, fresh `TBHM_` plus 32 random hex characters as the canary. The
canary is an expected response value and must not be sent in any request. It is
not a real password or customer secret. Role credentials come from environment
variable names; values are registered for redaction and remain in the parent.
Credentialed HTTP is limited to numeric loopback labs; other targets require
HTTPS with certificate verification. The default confirmed finding severity is
MEDIUM for this bounded demonstrated read impact; broader impact is not inferred.

Policy must explicitly allow `strict_read_validation`, `brokered_http_read`,
GET, exact included assets/paths/ports and a permitted request rate. Existing
scope/profile/rate/request/body/cooldown gates still apply. Each plan has 1–10
cases, at most six requests per case, a 200,000-byte decoded capture cap and a
shared accepted-body/request ledger. If a case fails transport, later work may
be denied by the same budget/cooldown; errors are never a clean result.

The top-level schema is `tbhm.strict-replay/1`, with `destination_pins` mapping
each exact HTTP(S) origin to 1–8 numeric IPv4/IPv6 addresses and a `cases` array.
There are at most 20 origins. Paths and queries do not belong in origin keys.
All resolved answers must be within reviewed pins. Numeric socket connects keep
the original hostname for Host/SNI/certificate verification. Private addresses
require explicit pins and target/program scope; unspecified, multicast,
link-local, mapped IPv6 and zone-scoped addresses are unsupported. Use ASCII/IDNA
origin names. Proxy integrations are unsupported in this mode.

All cases require `test_id`, `vulnerability_class`, `controlled_fixture=true`,
`scope_reference`, `canary`, `baseline_url`, `mutation_url`,
`negative_control_url`, and an `actors` object keyed by stable actor IDs. Each
actor has `owned_test_account=true` and an optional `credential_env` name;
credentialed roles are mandatory for BFLA. All case URLs must be GETs on one
explicit pinned origin; controls must be distinct. The entire plan is validated
before DNS, HTTP or child execution.

| Class | Additional fields and prepared fixture | Confirmation |
|---|---|---|
| `path_traversal` | One actor; `parameter`, `baseline_value` (owned public `.txt` file), `baseline_sha256`, `traversal_value` (`../` repeated 1–8 times then `tbhm-proof-<32 hex>.txt`), `missing_value` (`../.../tbhm-missing-<32 hex>.txt`) | Known public-file baseline; exact query-only mutation; outside-root file body equals the complete canary; missing control denies without canary; mutation and two repeats agree |
| `bfla` | Two distinct credentialed actors; `privileged_actor`, `limited_actor`, `expected_limited_access=deny`, `function_id`; baseline/mutation use the exact same protected read URL | Privileged, limited and repeats return exactly `{"function_id":"<reviewed ID>","proof_canary":"<canary>"}`; missing-function and anonymous same-function controls deny without the marker |

These contracts require fixtures you own and prepare. No file is created on the
remote system, object IDs are not enumerated, and no write/rollback operation is
performed. Dedicated TBHM filenames intentionally prevent this verifier from
being used as a generic arbitrary-file reader. Existing detectors may still
raise other leads; these narrow contracts do not automatically confirm them.

Outputs: `evidence/strict_replay/results.json`, its separate ledger, authenticated
`evidence/captures/`, validation attempts/test executions, normal findings and
reports, `OPERATOR.html`, graph associations and the sealed delivery. The private
capture key remains in the live run and is excluded from client snapshots.

## Pinning the existing broker

The existing `tbhm.brokered-http/1` plan accepts the same optional
`destination_pins` map. Without it, the previous 4.2.3 workflow retains its
existing scope/budget controls. Supported drivers are `native` and packaged
`pipe-v1` only. The child cannot open sockets and requests approved IDs from the
parent. Arbitrary tools/browser/proxy driver IDs fail before launch.

Pinned dispatch is serialized across processes sharing the ledger. Body counters
mean accepted decoded response bytes. HTTP requests and redirects received are
accounted; redirects are not followed or retried. DNS resolution, failed socket
attempts, TLS framing, all wire bytes and unrelated tools are not global quotas.
429/503 cooldown is now recorded before body consumption, even on body failure.

## Privacy and evaluation

Use the 4.2.3 prior-delivery audit command with synthetic canaries. New supported
variants include UTF-32, percent encodings, hex, HTML/JSON and URL-safe base64,
plus BZip2 and memory-limited XZ containers. Recursion/output/file/input budgets
remain finite. Concatenated/truncated/oversized XZ, unknown images/PDFs/encryption
and exhausted budgets remain incomplete. Canary tests do not prove absence of
unknown secrets or personal data. Live raw evidence is not rewritten by the audit.

Reproduce the paired local confirmation evaluation against your saved baseline:

```bash
.venv/bin/python scripts/evaluate_release_v424.py \
  --baseline /absolute/path/TBHM-4.2.3 --output-dir /tmp/tbhm-paired-evaluation
.venv/bin/python scripts/run_tests.py --workers 3 --output /tmp/tbhm-4.2.4-tests.json
.venv/bin/python scripts/validate_v4_release.py
```

The evaluator starts owned loopback vulnerable/patched fixtures and sends real
scoped, pinned HTTP requests. It compares the same signed captures with both
versions. The four cases measure narrow confirmation, not real-world discovery.
Repeat captures are part of each proof, not extra independent samples. Legacy
proof vectors compare outcome flags/reasons and receipt issuance. Stage/class
quality metrics keep inconclusive cases visible and distinguish conditional
metrics from full-denominator bounds. Synthetic intervals do not support general
accuracy percentages. No model, paid service or third-party target is used.

See `research-v4.2.4/ROADMAP.md`, coverage matrices and actual verification records
for unsupported paths and remaining gates.
