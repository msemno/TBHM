# TBHM v3.9.1-integrated-llm-evidence-safe — Additive Change Log

This update preserves the v3.9 command surface and existing phase behavior. It adds an integrated local-model runtime and a bounded evidence-import/instructor-simulation path.

## Integrated local LLM

- The local Ollama runtime is now initialized and reused by TBHM itself.
- `--local-llm` still performs redacted, loopback-only, non-agentic enrichment.
- Report generation automatically invokes local enrichment when `--local-llm` is enabled, including custom phase lists that omit `local_llm_triage`.
- `--local-llm-status` reports hardware, Ollama, model, and context readiness without requiring a target.
- `--local-llm-setup` explicitly asks a local Ollama installation to pull the configured model, or create it from an operator-approved `--local-llm-modelfile`.
- `--local-llm-required` makes model unavailability a non-zero run result while preserving reports and evidence.
- Model weights are not bundled or redistributed.

## Authorized exercise evidence and instructor mode

New phase: `engagement_evidence_review`.

- `--engagement-evidence PATH` imports existing JSON/JSONL/SARIF/text/log/CSV/XML/ZIP evidence produced by a separately governed authorized exercise.
- Imported content is categorized into credential-capture, offline credential recovery, Kerberos exposure, pass-the-hash, remote execution, directory-replication exposure, Metasploit/session, remote shell, persistence, and defense-evasion evidence.
- Secrets, hashes, tokens, and operational command lines are redacted.
- SHA-256 provenance is preserved for every processed evidence file/member.
- Every imported item remains an unconfirmed lead until corroborated.
- `--exercise-simulation` generates a synthetic instructor scenario with no network activity, credentials, payloads, commands, or live exploitation.

## Explicit execution boundary

TBHM still does not autonomously execute credential capture, password/hash cracking, Kerberos ticket extraction, pass-the-hash, remote command execution, DCSync, secrets dumping, Golden Tickets, Metasploit/Meterpreter sessions, reverse/bind shells, persistence, defense evasion, or safety-gate disabling.

The new evidence phase exists so authorized externally generated evidence can be normalized, mapped, taught, and reported without embedding those actions in TBHM.

## Compatibility

- Existing profiles and original phase ordering remain intact.
- Existing v3.9 flags remain available.
- The new phase is opt-in and is inserted before reporting only when evidence or simulation is requested.
- Local LLM behavior remains non-authoritative and cannot change lead/confirmed status.
