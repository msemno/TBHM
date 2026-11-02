# TBHM 4.2.3 — install and operate

## Install

Linux x86-64, Python 3.12, glibc 2.27+:

```bash
unzip TBHM-4.2.3-linux-x86_64.zip
cd TBHM-4.2.3
bash install.sh --offline
./tbhm --version
./tbhm --help
```

Keep the previous release in its own directory. The existing offline installer,
hash-locked wheels, profiles, reports, optional Go executor and all 145 phases are
retained. Optional scanners/models remain separately installed. The existing
4.2.2 owned-account BOLA workflow is documented in `docs/UPGRADE-v4.2.2.md`.

The new features add nine CLI arguments and four typed capabilities. Their inputs
choose only the relevant existing phases plus preflight/report/finalization;
an explicit `--phases` override wins. Local imports use `local-analysis.invalid`
as an analysis label when no target is supplied. Brokered network replay needs an
actual explicit target and reviewed program policy.

## 1. Import existing LLM security evaluations offline

Garak JSONL evaluation records:

```bash
./tbhm --offline --profile passive_only \
  --llm-security-input ./examples/research-v423/garak.report.jsonl \
  --llm-security-format garak --no-ai-observe -o ./results/garak-review
```

Promptfoo JSON/JSONL results:

```bash
./tbhm --offline --profile passive_only \
  --llm-security-input ./examples/research-v423/promptfoo-results.json \
  --llm-security-format promptfoo --no-ai-observe -o ./results/promptfoo-review
```

Supported Promptfoo JSON shapes are a result array or `results.outputs` /
`results.results`; JSONL contains one row per result. Only consistent explicit
boolean `success` and `gradingResult.pass` values are treated as evaluator
pass/failure. Scores are ignored for security confirmation; provider errors and
missing/contradictory grades remain unresolved. For Garak, only `entry_type=eval`
with integer `passed`, `total_evaluated` and optional `nones` is normalized;
attempt/config/digest payloads are not copied into the report. Detector counts
must not be interpreted as unique application attacks or bounty-valid bugs.

For a separately reviewed PyRIT or other framework export, use `--llm-security-format
tbhm` with this data schema:

```json
{
  "schema": "tbhm.llm-security-evidence/1",
  "records": [{
    "id": "reviewed-case-1",
    "producer": "PyRIT reviewed export",
    "category": "tool-misuse",
    "evaluator_outcome": "fail",
    "application_impact_review": "Controlled application effect still needs reproduction",
    "program_policy_review": "Check the reviewed program policy"
  }]
}
```

This is an import format, not a native PyRIT database reader or model executor.
No provider is contacted by the new import path. Optional `metadata.tbhm_category`
annotations map to `LLM01:2025`–`LLM10:2025` research IDs; unknown annotations stay
unmapped. These tags do not create executed security/standards coverage. The
artifact is `evidence/llm_security_review/review.json`. The normal operator/report
pipeline receives an informational review lead, never a confirmed vulnerability.

The current pinned IDs are: prompt-injection, data-leakage, supply-chain,
data-poisoning, output-handling, tool-misuse, system-prompt, rag-cross-tenant,
misinformation and resource-consumption. Program scope is separately reviewed;
generic jailbreak behavior is not automatically a reportable security impact.

## 2. Audit learning data and export reviewed retrieval cards

```bash
./tbhm --offline --profile passive_only \
  --learning-corpus-input ./examples/research-v423/learning-corpus.json \
  --export-retrieval-cards --no-ai-observe -o ./results/corpus-review
```

Each record needs an ID, `project_id`, `root_cause_id`, explicit
`train|validation|test` split, HTTPS provenance URL, reviewed `source_license` or
data-use basis, `reuse_approved=true`, `human_reviewed=true`,
`contains_sensitive_data=false`, and a `reviewed_text_sha256` matching sanitized
text. A declaration is not independent legal verification. Public availability
or a bounty payout does not grant reuse rights.

Keep these labels separate:

| Field | Values |
|---|---|
| `technical_validity` | `confirmed`, `refuted`, `inconclusive` |
| `program_outcome` | `accepted`, `duplicate`, `informative`, `not-applicable`, `out-of-scope`, `pending`, `unsubmitted` |

The audit exposes duplicate sanitized content and project/root-cause/content
cross-split leakage. An accepted outcome cannot replace a missing technical label
or human review. Only eligible, reviewed `train` records with confirmed/refuted
technical validity can be exported. Validation/test records are never exported
as training retrieval cards.

Output: `evidence/learning_corpus_audit/audit.json` and optional indexed Markdown
data cards. They remain fenced untrusted evidence. No weights are trained, no
agent skill is installed, no report data is fetched, and no model-quality gain
is claimed. A fresh audit revokes prior unchanged cards from this exporter;
manually changed/untracked contents block regeneration for review.

## 3. Audit a previous sealed delivery

Provide a synthetic canary that was planted in controlled test evidence. The
audit checks the canary; it does not plant it or require live credentials.

```bash
read -rsp 'Synthetic audit canary: ' TBHM_PRIVACY_CANARY
export TBHM_PRIVACY_CANARY
./tbhm --offline --profile passive_only \
  --delivery-audit-input /absolute/path/to/prior-run \
  --privacy-canary-env TBHM_PRIVACY_CANARY --require-private-delivery \
  --no-ai-observe -o ./results/privacy-review
unset TBHM_PRIVACY_CANARY
```

Use a separate output directory, outside the audited run. Supply 1–32 environment
names containing 8–128 character canaries. Values are not emitted. UTF-8, UTF-16LE,
UTF-16BE and base64 forms are searched in raw/SQLite bytes and supported bounded
ZIP/tar/gzip contents. No archive is extracted or executed. Inventory, per-file,
expanded-byte, member-count and nesting budgets bound the operation.

The audit binds to the prior manifest hash, checks integrity before/after, and
leaves the source snapshot untouched. Results are `pass`, `fail` or `incomplete`.
Images, PDFs, encrypted/unrecognized formats, unsafe members or exceeded budgets
cannot yield a clean privacy result. A pass covers only supplied canaries and
supported formats; unknown secrets, PII and image pixels still need review.
`--require-private-delivery` makes fail/incomplete fail the phase while retaining
the audit and normal partial report. Output: `evidence/delivery_privacy_audit/audit.json`.

## 4. Run a bounded read-only broker plan

Edit the example plan and policy for your explicit authorized URLs:

```bash
./tbhm -u https://api.example.test \
  --brokered-http-plan ./my-brokered-plan.json \
  --program-policy ./my-reviewed-policy.json --approve-brokered-http -y \
  --no-bootstrap --no-ai-observe -o ./results/brokered-reads
```

The plan schema is `tbhm.brokered-http/1`, shown in
`examples/research-v423/brokered-http-plan.json`. Up to 100 explicit requests use
unique IDs, URLs, uppercase GET/HEAD/OPTIONS, and `driver=native|pipe-v1`.
An optional `credential_env` names a parent-only Authorization value; HTTPS is
required for credentials except numeric loopback fixtures. No shell/command/tool
field is executed and no response body is passed to the pipe worker.

The parent owns all HTTP. The packaged child runs under inherited Linux seccomp
socket denial and exchanges only authorized request IDs and status summaries over
pipes. Native/child requests use the same ledger and existing TBHM scope,
program/method/rate/cooldown guards. Redirects are not followed. A plan with an
unsupported scanner/browser driver fails before launch. Offline refuses network
replay. There is no fallback to an unrestricted child.

`request_limit`, `body_limit` and `max_response_body_bytes` impose conservative
request-slot and accepted decoded-response-body reservations before dispatch.
Shared pacing/cooldown and quotas are transactional across ledger users. Very
low rates below 0.05 rps are incompatible with this bounded capability and are
refused, never raised above program policy. A crash can leave reserved slots
consumed; the ledger is not silently reset. Incomplete replay fails the phase and
retains `evidence/brokered_http/results.json` and `ledger.sqlite3`.

These quotas are **not** a TLS/kernel/all-wire byte meter. Existing Requests
guard buffering, other legacy scanners and browser network traffic are not
globally covered by this new ledger. The release metadata keeps that global gate
false. HTTP observations/digests never create vulnerability confirmation.

## Verification and limits

```bash
.venv/bin/python scripts/run_tests.py --workers 3 --output /tmp/tbhm-4.2.3-tests.json
.venv/bin/python scripts/evaluate_additions_v423.py --output-dir /tmp/tbhm-4.2.3-fixtures
.venv/bin/python scripts/build_release_manifest.py --check
.venv/bin/python scripts/validate_v4_release.py
```

`docs/research-v4.2.3/VERIFICATION.json` records the measured scope. All existing
4.2.2 proof contracts and their tests remain authoritative; no new auto-confirmed
vulnerability class was added. The new fixtures exercise transport, parsing,
known-canary and data-hygiene behavior, not real-model security or production
detector precision/recall. See `ROADMAP.md` for the gates still open.
