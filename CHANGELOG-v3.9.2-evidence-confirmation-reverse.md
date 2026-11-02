# TBHM v3.9.2 — Evidence Confirmation, Reporting, and Reverse Engineering

## Purpose

v3.9.2 is an additive update over v3.9.1. It preserves the existing web, API, source-code, enterprise, mobile, cloud, AD, AI, evidence, and reporting pipeline while adding two cross-cutting capabilities:

1. an evidence-grounded exploitability/confirmation assessment for every finding; and
2. a five-stage reverse-engineering workflow that orchestrates established static-analysis platforms and imports controlled runtime evidence.

The update does not convert scanner, static, imported, or LLM observations into confirmed vulnerabilities without reproducible evidence.

## Global finding assessment

New phase: `exploitability_assessment`.

For every stored finding it derives and persists:

- confirmation status: `CONFIRMED`, `SUPPORTED`, or `UNCONFIRMED`;
- exploitability status: `PROVEN`, `LIKELY`, `POSSIBLE`, or `UNKNOWN`;
- evidence strength and the exact confirmation basis;
- a safe proof of concept or existing reproducer;
- confirmed steps to reproduce, or validation steps still required;
- prerequisites and a possible attacker access path;
- assessed access outcome;
- security impact, remediation, and retest criteria.

Strict rule: imported scanner evidence, static patterns, local-LLM analysis, and sandbox exports are leads unless an independent TBHM verifier or an explicit controlled proof records successful reproduction.

## Final report redesign

The primary deliverables are now:

- `REPORT_final.md`
- `REPORT_final.html`
- `REPORT_confirmed.md`
- `REPORT_leads.md`
- `REPORT_executive.md`
- `REPORT_manager.md`
- `REPORT_developer.md`
- `REPORT_defender.md`
- JSON, CSV, SARIF, per-finding reproducer kits, and methodology audit outputs.

The final report contains:

- table of contents;
- executive summary;
- scope and engagement context;
- methodology and confirmation standard;
- findings summary;
- strictly confirmed vulnerabilities;
- supported findings requiring final verification;
- unconfirmed leads and observations;
- prioritized remediation roadmap;
- retest and closure criteria;
- conclusion.

Each confirmed vulnerability has its own complete section with summary, classification, possible access path, proof of concept, confirmed reproduction steps, confirmation basis, evidence, security impact, remediation, and retest criteria.

## Reverse-engineering workflow

Five ordered phases were added before the legacy compatibility adapter:

1. `reverse_triage`
   - file type, architecture, hashes, entropy, strings, endpoints, secret-like material, imports/exports, and suspicious capability triage;
   - uses built-in parsing and optional `file`, `readelf`, `objdump`, `nm`, FLOSS, and capa;
   - never executes the artifact.

2. `reverse_static_analysis`
   - headless Ghidra, licensed IDA batch mode, Radare2, and Rizin orchestration;
   - exports functions, imports, symbols, sections, strings, CFG/call-graph data, and cross-reference evidence to JSON/SARIF-compatible records;
   - static only.

3. `reverse_dynamic_evidence`
   - imports approved GDB, WinDbg, x64dbg, Frida, CAPE/Cuckoo, QEMU/Unicorn, ANY.RUN, Hybrid Analysis, Joe Sandbox, and VirusTotal artifacts;
   - does not launch untrusted binaries;
   - controlled instruction-pointer/crash evidence can be marked verified only when the record contains the required proof and a matching SHA-256-bound verification manifest marks it controlled, reproduced, and approved.

4. `reverse_symbolic_analysis`
   - optional bounded angr CFG/function exploration;
   - imports angr, Triton, and Unicorn result files;
   - does not synthesize concrete exploit inputs, shellcode, or payloads.

5. `reverse_correlation`
   - correlates static functions/imports/strings with runtime/sandbox evidence;
   - enriches findings and prepares a defensible attack-path narrative;
   - keeps LLM observations non-authoritative.

The existing `reverse_engineering_tooling` phase remains as a compatibility import adapter.

## Local LLM integration

The local Ollama model remains integrated into the TBHM report path. v3.9.2 extends its structured output with:

- `access_path_summary`;
- `evidence_gaps`;
- `report_summary`.

The model cannot call tools, execute commands, create payloads, promote findings, or override the deterministic confirmation engine. Sensitive values are redacted before inference.

## New CLI options

- `--reverse-static`
- `--reverse-backends auto,ghidra,r2,rizin,ida`
- `--reverse-ghidra-home PATH`
- `--reverse-ida-path PATH`
- `--reverse-dynamic-results PATH`
- `--reverse-verification-manifest PATH`
- `--reverse-symbolic`
- `--reverse-symbolic-results PATH`
- `--reverse-symbolic-timeout SECONDS`
- `--reverse-symbolic-max-functions N`
- `--reverse-max-files N`
- `--reverse-max-file-mb N`
- `--reverse-evidence-max-mb N`
- `--reverse-strings-min N`
- `--no-exploitability-assessment`

## Installer and diagnostics

Optional reverse tooling can be installed with:

```bash
INSTALL_REVERSE_TOOLING=1 ./install.sh
```

Optional angr support:

```bash
INSTALL_REVERSE_TOOLING=1 INSTALL_ANGR=1 ./install.sh
```

Ghidra, IDA Pro, Binary Ninja, WinDbg/x64dbg, CAPE/Cuckoo, and commercial sandboxes remain operator-managed. Diagnostics now report availability for the reverse-engineering toolchain.

## Validation

- Python source compilation passes.
- YAML profiles parse.
- shell syntax validation passes.
- original add-on integration test passes.
- v3.9 local-AI/source-tooling test passes.
- v3.9.1 integrated-LLM/evidence test passes.
- v3.9.2 confirmation/report/reverse test passes.
- an end-to-end local `/bin/true` reverse-analysis/report run was used to validate graceful tool degradation and report generation.

## Safety and evidence boundary

TBHM can explain whether the available evidence indicates a plausible access path and can confirm a vulnerability when the stored proof meets the strict standard. It does not automatically generate or deploy reverse shells, credential-theft workflows, persistence, destructive payloads, or exploit code. Dynamic execution belongs in an isolated, separately governed sandbox; TBHM imports and correlates the resulting evidence.
