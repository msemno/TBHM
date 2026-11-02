# TBHM v3.9.3 — restore completion, phase connectivity, whole-run LLM

## Reverse-engineering restore — completed (audit items A/B/C)
- **A. Real secrets no longer discarded by premature redaction.** New
  `reverse_utils.secret_candidates()` returns the actual value (kept in memory
  only). The legacy phase screens the REAL value through the FP gate, then stores
  ONLY the redacted form. Result: a live-looking key survives, example/placeholder
  keys drop, and the raw value is never persisted. Path-based test/doc suppression
  is NOT applied to a supplied binary (so a binary named `sample.bin` still gets
  its real secrets checked).
- **B. Short dangerous APIs caught.** New `reverse_utils.raw_short_imports()`
  scans raw bytes for `gets`/`system`/`popen`/`strcpy`/`WinExec`/... that fall
  under the 8-char printable-string floor. Wired into the legacy phase.
- **C. capa restored.** The legacy phase runs `capa -j <binary>` when capa is
  installed and `--reverse-tooling` is set, writing `<stem>.capa.json`.

## New-phase safety hardening (audit items 4/5)
- **Rate limiting** enforced on `js_analysis` and `deep_crawl` using the profile's
  `per_target_rps` (was relying on anti_block only).
- **Post-redirect scope re-validation**: both phases now re-check the FINAL URL
  after any redirect and drop it if it left scope.

## Version + tests (audit items 6/7)
- Product/report version bumped to **v3.9.3** (banner, tbhm.py title,
  reporter VERSION + report headers).
- **integration_test_v393.py**: 20 regression assertions covering P0-2, P0-3,
  and restore items A/B/C. All pass.

## Phase connectivity (your request: connect source code + alive hosts + more)
- **New `surface_correlation` phase.** Unifies endpoints discovered by
  code_scan/code_intel (`code/endpoints.txt`), mobile_scan (`mobile/`),
  js_analysis (`recon/js_endpoints.txt`), and deep_crawl
  (`crawl/discovered_urls.txt`), joins every path against every live host, and
  scores the concrete URLs into the shared endpoint store — so the EXISTING
  audit/injections phases test source- and binary-discovered endpoints instead of
  leaving them siloed. Read-only; reachability is confirmed later by the gated
  audit path. Runs after all discovery, before protected_routes/audit.
  Verified: 5 code/JS paths × 2 live hosts → 10 URLs scored into the audit queue.

## Whole-run LLM (your request: LLM helps the full tool logic after scanning)
- **New `llm_run_analysis` phase.** Where local_llm_triage enriches one finding at
  a time, this runs once near the end and reasons over the WHOLE run: overall risk
  narrative, cross-finding correlations the rule engine missed, prioritized
  "what to verify next", and coverage gaps. Written to
  llm_analysis/RUN_ANALYSIS.md. Same safety envelope: loopback-only, redirects
  rejected, inputs redacted/bounded, non-agentic — it cannot call tools, run
  commands, generate payloads, change classifications, or promote to confirmed.
  Advisory only. Requires --local-llm; skips cleanly if the model is absent.

## Preserved
No existing phase, gate, profile, or safety boundary was removed or weakened. All
new phases are read-only/advisory; active testing stays on the existing gated
audit path. New phases insert into the master order so their output feeds the
pipeline; profiles with explicit phase lists opt in by name.
