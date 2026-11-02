# TBHM v3.5 — False-Positive Hardening

Driven by the Anthropic-targets run, where ~2500 findings were emitted and
zero were real. Every FP class from that run is now closed. Nothing is silently
deleted: drops are archived to `dropped_findings` / `*.filtered.json`,
downgrades are kept as visible `lead`-tier items out of the confirmed report.

## Root causes fixed

1. **Provider-key examples passed the gate.** v3.4 only screened generic/assignment
   secrets for placeholders. `AKIAIOSFODNN7EXAMPLE` (AWS docs), the jwt.io demo JWT,
   and `ghp_XXXX…` placeholders sailed through as HIGH.
   → `code_patterns.find_secrets` now runs a universal non-secret screen on every
     match (example denylist, all-placeholder shapes, GitHub PAT CRC32 checksum,
     demo-JWT `sub=1234567890`). `fp_filters.is_dummy_secret` mirrors it at save time.

2. **Secret value never extracted from TBHM's own evidence format.** v3.4's
   extractor only handled quoted values, so the `path:line  VALUE` format used by
   code_scan/code_intel yielded an empty string and nothing was screened.
   → extractor now handles quoted, `path:line VALUE`, and unquoted-assignment shapes.

3. **Test/fixture files misclassified as prod.** `Anthropic.Tests/FooTests.cs`
   wasn't matched (regex required a `/tests/` segment).
   → `path_context` now recognises embedded `.Tests`/`Tests.cs`/`_spec.rb` dir and
     file names, plus `bench`, `winogenerated`, `datasets`, `evals`.

4. **Self-referential security tooling flagged itself.** The scanner flagged
   `security-guidance/hooks/patterns.py` (the pattern definitions) and `sanitizer.ts`
   (the redactor) for containing the very strings they exist to match.
   → new `security_tooling` path context drops secret/sink hits in
     sanitiz*/redact*/pattern*/detector*/lint*/rules* files.

5. **gitleaks output dumped raw.** 2242 hits came from 40-hex git SHAs / plugin IDs
   in one `marketplace.json`; dataset column names matched `generic-api-key`.
   → `validate_gitleaks_report` runs gitleaks JSON through the same gate; git-SHA/ID
     in manifests and dataset labels are recognised and filtered. code_scan now emits
     only validated gitleaks hits and writes the rest to `*.filtered.json`.

6. **Confidence never capped severity.** LOW-confidence regex sinks were emitted at
   HIGH/MEDIUM. Synthetic `[chain]` findings had `verified_at: null`.
   → code_scan emits sinks at LOW/LOW. `fp_filters` downgrades any SAST sink without
     taint/reachability proof to `lead`, and any chain without a verified hop to `lead`.

7. **Manifest/doc files in secret-scan scope.** `.json/.jsonl/.csv/.md/.txt` fed the
   secret + sink engine.
   → removed from `SCAN_EXT`; new `ENDPOINT_EXT` scans them for endpoints only.

## Verification
- 13/13 gate test cases correct: all 10 observed FP classes drop/downgrade;
  3 real-finding controls (live AWS key in prod, verified IDOR, verified chain) keep.
- `find_secrets` unit test: junk suppressed, real `AKIA…` retained.
- Full-package syntax check clean; `tbhm.py --help` OK.

## Flags (unchanged, still honored)
- `--no-fp-filter` bypasses the gate.
- `--secret-min-entropy` (default 3.0), `--secret-confidence {medium,high}`.
- `.tbhmignore` / `--ignore-patterns-file` / `--secret-ignore-list`.
