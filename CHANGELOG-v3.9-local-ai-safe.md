# TBHM v3.9-local-ai-safe — Additive Change Log

This update is additive. Existing phase names, default v3.8 code-security tool selection, profiles, evidence storage, and report outputs remain available. New features are opt-in and return immediately when their flags are not used.

## Added

- `local_llm_triage` phase using an operator-controlled Ollama endpoint.
  - Extracts CWE, CVSS, affected component/version, duplicate hints, safe validation plans, and remediation guidance from existing findings.
  - Redacts common credentials, tokens, cookies, JWTs, API keys, and hash-like values before model input.
  - Does not expose tool calling, execute generated commands, generate payloads, or alter lead/confirmed classification.
  - A loopback endpoint is always required; proxy inheritance and HTTP redirects are disabled.
- Hardware detection and conservative 4B model sizing (`core/hardware_profile.py`).
- Shared SARIF/JSON/JSONL scanner normalizer (`core/scanner_normalizer.py`).
- `source_orchestration_tooling` phase.
  - Runs s0-cli locally with `--no-llm` and imports its SARIF.
  - Imports Argus, Mega-Linter, SonarQube, CodeQL, DefectDojo, and compatible results without embedding their deployment/runtime.
- Expanded `code_security_tooling` adapters.
  - Preserves the original default list: Bandit, njsscan, Gitleaks, Trivy, Grype, Checkov, Terrascan, and tfsec.
  - Adds optional Semgrep, Ruff, Brakeman, Gosec, ESLint, TruffleHog with live verification disabled, detect-secrets, Syft, Safety, OWASP Dependency-Check, and Hadolint.
  - Platform/cloud/build-coupled tools remain import-only.
- `ad_access_assessment` phase.
  - Read-only DC service/SMB-signing review.
  - Certificate-validated read-only LDAPS configuration inventory for SPNs, pre-authentication flags, delegation, RBCD, and password-control exceptions.
  - Filters DCs through scope/exclusion rules and approved corporate CIDRs; supports bounded BloodHound ZIP import.
  - Extends `lateral_movement_paths` to normalize standard BloodHound/SharpHound JSON/ZIP and compute deterministic, read-only shortest privilege-path exposure leads to high-value objects.
  - Imports BloodHound/SharpHound, LDAPDomainDump, ADRecon, LDIF, Nmap, and compatible assessment evidence as unconfirmed leads.
- Optional installer switches:
  - `INSTALL_CODE_SECURITY=1 ./install.sh`
  - `INSTALL_OLLAMA=1 ./install.sh`
  - Model files are never downloaded automatically.
- Diagnostic coverage for local source scanners, Ollama, NVIDIA GPU visibility, and AD export utilities.

## Reliability and evidence fixes

- Imported scanner/adapter phases are now inherently classified as leads until independently verified.
- `Runner.run()` accepts optional working directory, environment overrides, and command-log redaction while preserving old call compatibility.
- `Storage.enrich_finding()` attaches non-authoritative model enrichment without overwriting existing CWE/CVSS values or finding status.
- `ad_identity_safe` no longer puts LDAP passwords in command arguments or logs; it uses a temporary mode-0600 password file, requires LDAPS for authenticated inventory, and deletes the file.
- Executable and report version labels were synchronized to `v3.9-local-ai-safe` while preserving SARIF schema version `2.1.0`.

## Deliberately not automated

The following were not added: credential poisoning/capture, Kerberos ticket extraction, password/hash cracking, pass-the-hash, remote command execution, DCSync/secretsdump, Golden Tickets, Metasploit/Meterpreter, reverse or bind shells, persistence, AMSI/EDR bypass, payload obfuscation, or disabling TBHM safety gates. These require separate, tightly controlled manual procedures and are represented only as residual-risk/import/simulation coverage.
