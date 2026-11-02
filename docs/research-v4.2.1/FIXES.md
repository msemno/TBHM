# TBHM 4.2.1 — FIXES by workstream

| Workstream | Actual change | Acceptance evidence | Status |
|---|---|---|---|
| 1 / Containment | `--offline` rejects the egress-canary diagnostic; sensitive internal SSRF probes disabled by default; Go runner executable restored | `tests/test_egress_v421.py`, `tests/test_ssrf_v421.py`, runner redaction | **Partial**; arbitrary child scanners not globally metered and no universal OS namespace |
| 2 / Trust | No new strict auto-confirmation classes shipped; three legacy classes retained | Existing `tests/test_release_v410.py`; new adversarial proof suite | **Deferred**, not labeled complete |
| 3 / Accuracy | Local OAST challenge/event corroboration and new labeled proof-contract fixtures | `tests/test_oast_v421.py`, `tests/test_ssrf_v421.py`, proof evaluation JSON | **Partial**; no proven production blind-SSRF confirmation or independent detector accuracy |
| 4 / Stateful API | No change; requires scoped owned multi-actor fixtures | N/A | **Deferred** |
| 5 / Standards | Add execution-based WSTG/API/ASVS map; correct misleading phase-only tested-clean labels | `tests/test_standards_v421.py` | **Partial catalog shipped** |
| 6 / Packaging | Root `RELEASE_VALIDATION.json` generated from v4.2.1 evidence; new release manifest | Archive verifier + extracted tree check | **Complete on verified archive**, results recorded separately |

**Compatibility:** no old source file deleted; `load`, `finding_tags`, `map_findings` preserved; same 145 phase names and same original CLI. SQLite schema was not edited. Go executor source unchanged. A legacy internal-SSRF probing behavior has intentionally been converted into an opt-in loopback-only experiment; this is a safety behavior change, not a claim of transparent bitwise runtime equivalence.
