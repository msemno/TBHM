# TBHM v3.4-redteam-safe Changelog — False-Positive Reduction

Driven by the real output you collected. The reports.zip showed the exact failure
modes the recommendations predicted:

- `payment_findings.json`: **287** hits — keyword "price"/"charge" matched in
  `filen-rs/LICENSE`.
- `code_ai_api_findings.json`: **362** hits — "prompt"/"claude-" matched in
  `CHANGELOG.md`, `.claude/` config, agent docs.
- `secrets_findings.json`: **37** — dummy values in `*.test.ts`, `*_tests.rs`,
  `SKILL.md` (`"some_password"`, `"invalid_api_key"`, `"ak-replace"`, `"sk-prod-abc123"`).
- `endpoint_to_live_map.json`: empty / wildcard-200 (no real reachability gate).

375 findings, 292 from `code_intel` handler-branches keyword-matching docs/license/
test files. This release removes that class of noise while preserving every
suppressed item for audit.

## Root-cause fixes

### 1. Path-context gate (the #1 fix)
New `core/fp_filters.py`, applied at **every** `save_finding` (all phases benefit)
and at the `code_intel` source scan:
- **Non-code files** (LICENSE, CHANGELOG, README, `*.md/.rst/.txt/.example/.sample`,
  `*.test.*`, `*_tests.*`) never produce secret or keyword-branch findings.
- **test/mock/fixtures/examples/docs/vendor/node_modules/.claude/.github** paths
  are dropped for secrets/keyword branches and downgraded to leads for SAST.

### 2. Dummy / low-entropy secret suppression
- Known placeholder values (`some_password`, `invalid_api_key`, `AKIA…EXAMPLE`,
  `changeme`, `sk-prod-abc123`, …) are dropped.
- Generic "secret assignment" matches below `--secret-min-entropy` (default 3.0 bits)
  are dropped. `--secret-confidence high` downgrades generic/low-confidence secrets
  to leads (kept out of the report).

### 3. code_intel handler branches: prod vs suppressed split
Each keyword branch (payment/AI/webhook/upload/admin/cloud/mobile) now tags every
hit with its path context and splits output:
- `<branch>_findings.json` → **production hits only** (what you read).
- `suppressed_findings.jsonl` → the test/docs/LICENSE hits (audit, not lost).
Keyword-only hits are LOW-confidence **leads**, never MEDIUM report findings,
unless corroborated.

### 4. Same-server control (fixes the wildcard-200 live map)
The `--map-code-to-live` prober now fetches a random nonexistent path per host and
compares. If a "reachable" endpoint returns the same status and ~identical length
as the control, the host answers 200-on-everything (SPA/wildcard/WAF) and the match
is flagged `generic_response` and **not reported**. In your data every endpoint was
a false 200; this turns those into 0 reachable.

### 5. SCA production-only (`--sca-prod-only`, default on)
devDependency CVEs are dropped (they don't ship to prod). `--include-dev-deps`
restores them.

### 6. FR-106 register + FR-105 lead tagging
`fp_review` now also writes **`false_positives.md`** — a grouped table of every
suppressed finding with its auto-drop reason and source — alongside the existing
`dropped_findings.jsonl`. Suppressed code hits flow into it via the dropped register.
Unverified heuristic findings keep the existing `[LEAD]` tag so the report never
presents a candidate as proven.

## New flags

```
--secret-confidence {low,medium,high}   --secret-min-entropy BITS
--exclude-tests (default) / --include-tests
--ignore-patterns-file PATH  (also auto-reads .tbhmignore in each repo)
--secret-ignore-list PATH
--reachable-only             --sca-prod-only (default) / --include-dev-deps
--dep-filter EXPR            --confidence-threshold N
--no-fp-filter               --fp-review
--no-include-<branch>  for: dependencies, ci-cd, secrets, business-logic,
   access-control, admin-routes, api-routes, payment-flows, upload-flows,
   webhook-flows, auth-flows, cloud-config, mobile-api
```

## Measured effect (reconstruction of your repo layout)

| | before | after |
|---|---|---|
| payment_findings.json | LICENSE keyword hits | prod handler only |
| secrets in report | test/docs dummies | 1 real prod AWS key |
| live map | false 200-on-everything | 0 reachable (control-matched) |
| suppressed items | lost | archived + in `false_positives.md` |

Report keeps only the real AWS key (HIGH), the real SQLi lead, and the real payment
handler; 8 noise items are preserved in the audit trail.

## My additional recommendations — implemented

- **Same-server control** on the live map (kills 200-on-everything) — done.
- **Global gate at `save_finding`** so the filter protects *every* phase, not just
  code — done.
- **Tag-and-split instead of delete** so nothing is lost and the client sees what
  was filtered and why — done.

## Deliberately NOT automated (safety / needs external infra)

These recommendations are sound but I did not auto-enable them, matching the tool's
safe model — they can be added by the operator behind explicit flags:

- **Validating found secrets by authenticating with them** (call STS/GitHub/Slack
  with the discovered key). That is *active use of discovered credentials*; TBHM
  should not do it automatically. Left as a manual triage step.
- **Headless-browser DOM-XSS execution**, **CodeQL/Semgrep taint call-graphs**,
  **live EPSS/KEV gating**, **two-egress reproducibility** — these need external
  tools/network/creds not available to ship-and-test here. The hooks (`--dep-filter`,
  `--reachable-only`, `--confidence-threshold`) are in place for when they are.

Nothing was removed; 78 phases still load; integration tests pass.
