# TBHM 4.2.1 — Competitive tool assessment and implementation record

**Baseline:** the supplied `TBHM-4.2.0-linux-x86_64.zip`, not an older version. This is an incremental engineering patch, not a new scanner framework. All 145 phase names and original CLI actions are retained.

## Evidence discipline

- **A**: independently visible program or paid/triaged outcome, with statuses distinguished.
- **B**: advisories, patches or independent reproduction, not necessarily a paid bounty.
- **C**: reproducible test targets, not evidence of payout.
- **D**: author/vendor claims and demonstrations without external acceptance confirmation.
- **Operational**: widely usable engine, but no single accepted vulnerability automatically attributable to the engine.

Citations and starting URLs are in the supplied research (`TBHM_Proven_Bug_Bounty_Tools_and_LLM_Research_2026(3).md` and `TBHM_Ultimate_Bug_Bounty_Research_2026(3).md`). Every row is a **research hypothesis or a scoped engineering decision**, not proof of successful integration. In particular, CAI (aliasrobotics/cai) is archived as of August 28, 2026; recommendations claiming it remains actively maintained should not be used for new production dependencies. HackerOne requires human validation of AI-assisted reports. Proprietary vendors' zero-false-positive marketing claims are not platform-wide guarantees.

## Competitive comparison

| Tool | Best relevant feature | Evidence | Decision |
|---|---|---|---|
| XBOW | Proof and reviewer-controlled report gate | A (H1 leaderboard; acceptance statuses mixed) | Defer proprietary integration |
| Aikido Attack AI Pentest | Authenticated workflow assessment and issue retests | B/C (small sponsored independent study) | Design reference |
| OpenAI Codex Security | Repo-specific threat models and reproducible validation | B (vendor-reported advisories; verify individual attribution) | Future research |
| Google Big Sleep | Patched-bug variant analysis | B (research case studies) | Research only |
| Vulnhuntr | LLM semantic source-to-sink search | B/D (case claims and OSS updates) | Defer parser integration |
| Shannon | Source-aware browser/API replay with checkpointing | C/D (demos, no H1 acceptance established) | Evaluate in isolated lab |
| Strix | Browser/proxy and specialist agents | D (repository/vendor claims) | No runtime dependency yet |
| PentAGI | Durable graph memory/observability | D | Design reference |
| PentestGPT | Staged reasoning and task tree | C/D (academia/demo; no paid bounty claim) | Compare independently |
| CAI / aliasrobotics | Multi-agent task decomposition | B/D (research, archived Aug 2026) | Reject live dependency |
| HexStrike AI | Tool adapters and planning surface | D (features; accepted payout record unverified) | Defer integration |
| Burp Suite | Manual proxy / authenticated testing / BChecks | Operational (not payout attribution) | Keep external optional |
| OWASP ZAP | Automatable authenticated DAST | C (labs and reference implementations) | Existing adapter review |
| Nuclei | Structured signature matching | C (known cases; not confirmation) | Retain, improve quality |
| Subfinder | Passive enumeration from multiple providers | Operational | Keep optional |
| httpx | Active HTTP fingerprints and metadata | Operational | Keep optional |
| Katana | JS-aware routes/forms crawling | Operational | Keep optional |
| BBOT | Event-based asset relationships | C/D | Design reference |
| Kiterunner | Method/path-aware API inventory | C | Defer active integration |
| Arjun | Unknown parameter discovery | C | Review optional adapter |
| Turbo Intruder | Controlled request scheduling | Operational | Defer live automation |
| CodeQL | Interprocedural codeflow and taint | C (reproducible OSS fixtures) | Keep optional |
| Semgrep | AST and taint rules | C | Keep optional |
| TruffleHog | Credential candidates and safe verification modes | Operational | Keep optional |
| OSV-Scanner | Affected-version advisory matching | C | Keep optional |
| Syft + Grype | SBOM provenance and vulnerability matching | C | Keep optional |
| MobSF | App source/binary inventory and tests | C | Defer dynamic runtime |
| JADX + Frida | Decompiled code with approved runtime observations | C | Defer device testing |
| Binwalk + EMBA | Firmware extraction and component analysis | C | Retain optional workflow |
| Ghidra + FirmAE | Binary analysis and isolated emulation | C | Defer emulation |
| Slither | Static smart-contract IR and detectors | C | Existing Slither import |
| Foundry + Echidna | Invariants, deterministic local transactions | C | Defer toolchain |
| Prowler + Checkov | Scoped policy evaluation | C | Keep optional |
| CloudFox + PMapper | Permission relationship analysis | C | Defer optional integration |

## Decisions reflected in this code

1. **Local OAST:** New `core/oast.py` collects HTTP callback interactions for approved loopback fixtures using unique challenge tokens, capped budgets and sanitized artifact export. Callback events are *corroborating observations* only. `phases/waf_evasion_ssrf.py` uses it in explicit local-lab mode and writes observations to the existing SQLite store; it cannot self-confirm SSRF.
2. **SSRF default:** Old tests to metadata/private/alternate loopback destinations no longer fire. Candidate URLs are inventoried and recorded as requiring separate permission; no production origin or metadata targets are inferred in scope.
3. **Coverage accounting:** `core/compliance_catalog.py` retains historic `load`, `finding_tags`, and `map_findings` APIs while adding execution-backed mapping for a small OWASP WSTG, API Top 10 (2023), and ASVS 5.0 subset. `phases/compliance_coverage.py` emits `test_id_coverage.json`. Missing evidence is never `tested-clean`.
4. **Proof benchmark:** Twelve local synthetic cases cover *existing* strict verification classes (`access_control`, `sensitive_data_exposure`, `open_redirect`); 24 separate adversarial evidence tamper cases were rejected. These results do not measure web vulnerability discovery accuracy.
5. **Offline diagnostic:** Egress canary respects `--offline`; zero probes are initiated when offline, including when egress-canary testing is otherwise enabled.
6. **Packaging compatibility:** The optional Go executor binary had no executable bit in the supplied extracted ZIP. Restoring its executable bit makes the bundled Go evidence-protocol test runnable on compatible Linux x86-64 systems. No Go logic is modified.

## LLM architecture and training choice

Existing evidence-first architecture remains authoritative. A security LLM must be **advisory**, cite verified evidence IDs, and never drive privileged network actions or promote an unverified issue to confirmed. For a workstation with **16 GiB system RAM and 8 GiB VRAM**, local quantized 4B inference is the reasonable *evaluation starting point*, not a promised benchmark. RAG for versioned OWASP/CWE/security cases and strict output schemas has higher priority than QLoRA. No model weights, fine-tuning datasets or GPU benchmark are shipped in this patch. Fine-tuning needs licensed, permissioned, de-duplicated, independently held-out labeled records and performance improvement over deterministic/RAG-only controls. Training on scanner hypotheses or private bounty reports without consent is disallowed.

## Limitations that remain release-blocking for the requested high-level scanner

- External child-scanner egress is **not** globally metered. A local OAST callback listener does not address child-scanner containment.
- `--offline` is **not** a systemwide OS network namespace for every child process. Native-HTTP guards and egress-canary behavior do not prove zero packets by arbitrary child tools.
- The strict confirmation verifier still has only three complete audited vulnerability-class contracts. SQLi/XSS/SSRF/SSTI/traversal/deserialization/auth/CSRF remain incomplete.
- No independent cross-project detector precision/recall, false-negative rate, live accepted bounty track record or multi-actor BOLA business workflow benchmark was established in this pass.
- Standards mapping is deliberately **partial** and measures executed strict-test types; it does not attest full WSTG, ASVS, MASVS or MASTG compliance.
- No externally accessible OAST DNS/HTTP service is provisioned. Use approved lab-only callbacks and do not infer remote callback availability.
- Existing end-to-end mobile/IoT/Web3/runtime/agent ecosystems have **not** been exhaustively retested.

## Sources checked online during implementation

- HackerOne Code of Conduct: https://www.hackerone.com/policies/code-of-conduct
- CAI archived repository: https://github.com/aliasrobotics/cai
- WSTG IDOR `WSTG-ATHZ-04`: https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- WSTG reflected XSS `WSTG-INPV-01`: https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting
- WSTG SQL injection `WSTG-INPV-05`: https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
- ASVS 5.0 authorization `V8.2.2`: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md

