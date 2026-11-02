# TBHM v3.7 — Security Tooling Coverage Expansion

This additive release preserves all v3.6 phases and adds five optional integration layers:

- `sast_tooling`: Semgrep execution and SARIF/JSON import for SAST platforms.
- `mobile_tooling`: MobSF-compatible evidence import and an explicitly gated API-upload adapter.
- `web_scanner_tooling`: optional ZAP baseline plus ZAP/SARIF/XML scanner import.
- `network_firewall_tooling`: Nmap/generic result import and static firewall configuration checks.
- `ai_llm_tooling`: Garak-compatible execution and generic Garak/PyRIT JSON/JSONL import.

## Design rules

1. Existing native phases are not removed, renamed, or weakened.
2. New live integrations are opt-in and gracefully skip when tools are unavailable.
3. Commercial products are supported through export normalization instead of undocumented APIs.
4. Imported findings enter TBHM as medium-confidence evidence and continue through the existing verification, false-positive, reporting, and evidence-finalization pipeline.
5. Device-side exploitation, credential theft, persistence, C2, phishing, destructive actions, and evasion are not automated.
