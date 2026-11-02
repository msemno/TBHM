# TBHM v3.9.7.2 — Capability Depth and Backward Compatibility

TBHM v3.9.7.2 upgrades the original v3.9.6 enterprise-control-plane source tree while preserving its public CLI, phase graph, configuration keys, report names, evidence paths, schemas, and entry points. It adds a truthful central capability registry, environment doctor, allowlisted read-only plan execution, import-only session/beacon and passive-wireless evidence handling, native RDAP collection, graph-based cloud IAM analysis, evidence predicates for compliance, CI/CD trust/dataflow analysis, class-aware deterministic OCSF export, and proposal-only adapter generation.

Historical behavior from v2.16-fixed, v2.21, v3.8-expanded, and v3.9.5 was compared semantically against v3.9.6. Older code was restored only where it improved correctness, safety, evidence integrity, scope enforcement, or compatibility. The release keeps planned, unavailable, import-only, and adapter-backed capabilities visibly distinct from native operational features.

Safety boundaries remain strict: no credential theft, automatic exploitation, arbitrary command execution, payload generation, C2 startup, persistence, lateral movement, destructive wireless behavior, or AI-directed shell execution was added.

Quick validation and status commands:

```bash
python3 integration_test_v3972.py
python3 integration_test_v3971.py
python3 integration_test_historical_regressions_v3971.py
./tbhm.py --capability-status
./tbhm.py --doctor
./tbhm.py --list-profiles
./tbhm.py --code-dir ./source --code-scan-data-files
./tbhm.py -y --safe-plan plan.json --safe-plan-dry-run -o results/plan-validation
```

Release evidence and design records:

- `CHANGELOG-v3.9.7.2.md`
- `VALIDATION-v3.9.7.2.md`
- `docs/CAPABILITY_DEPTH_v3.9.7.2.md`
- `docs/HISTORICAL_ARCHAEOLOGY_v3.9.7.2.md`
- `docs/compatibility/BACKWARD_COMPATIBILITY_REPORT_v3.9.7.2.md`
- `docs/historical/HISTORICAL_DECISION_REGISTER.md`
- `RELEASE_MANIFEST-v3.9.7.2.json`

---

# TBHM v3.9.4.1 — AI-plane correctness and safety hardening

This package preserves the v3.9.4 portable AI Control Plane and fixes the
remaining audited correctness issues: stale source-index documents, full
re-embedding on small deltas, mixed embedding spaces, raw resource persistence,
pre-request/redirect scope gaps, passive crawl requests, public-suffix scope,
static-taint classification, reverse artifact correlation, phase-resume state,
and evidence-boundary scope/redaction. Reports now surface conservative coverage
and posture context without fabricated remediation-time estimates.

Important commands:

```bash
./tbhm.py --ai-sync-tool
./tbhm.py --ai-review-delta
./tbhm.py --ai-propose-delta
./tbhm.py --ai-backup
./tbhm.py --ai-restore <backup.tar.gz>
python integration_test_v3941.py
```

See `CHANGELOG-v3.9.4.1.md`. The AI plane remains non-authoritative: it cannot
execute tools, change finding status, apply patches, or bypass scope/safety gates.

---

# TBHM v3.4-redteam-safe

## v3.4 — false-positive reduction (new)

Driven by real noisy output. Kills the dominant FP class (keyword branches matching
LICENSE/CHANGELOG/docs, dummy secrets in test files, wildcard-200 live maps) while
preserving every suppressed item for audit:

- `core/fp_filters.py` path-context + dummy/low-entropy secret gate at every
  `save_finding` (all phases) and at the code_intel source scan.
- code_intel splits each keyword branch into `<branch>_findings.json` (prod only)
  vs `suppressed_findings.jsonl` (test/docs/LICENSE, archived).
- Same-server control on `--map-code-to-live` flags 200-on-everything endpoints.
- `--sca-prod-only` drops devDependency CVEs; `--secret-confidence high`,
  `--secret-min-entropy`, `--ignore-patterns-file`/`.tbhmignore`, `--no-include-<branch>`.
- `fp_review` writes the FR-106 `false_positives.md` register.

See `CHANGELOG-v3.4.md`. Active credential-validation / headless-browser / CodeQL
were intentionally left as manual steps.

---

# TBHM v3.3-redteam-safe

## v3.3 — coverage, scenarios & ops (new)

Adds 12 phases (78 total, all safe/additive): `auth_modern_review` (JWT/OAuth/
SAML detection), `graphql_audit`, `k8s_recon_safe`, `llm_agent_tool_call_abuse`,
`mfa_bypass_safe`, `lateral_movement_paths` (read-only AD paths + BloodHound
export), `ot_ics_safe`, `modern_protocols_discovery`, `cloud_inventory_safe`,
`browser_extension_audit`, `backup_restore_simulation`, and `playbook_integration`
(`--playbook-mode`: coverage_tracker.csv + BR objective cards + master_coverage.html).

Ops: `--no-destructive`/`--force-write`, `--recheck-only`, `--update`,
`phase_timings.json`, `tbhm.jsonl` (SIEM), and input validation. See
`CHANGELOG-v3.3.md`. Exploitation/C2/live-wireless/live-phishing remain safe
detection-only per the tool's model.

---

# TBHM v3.2-redteam-safe

## v3.2 — red-team analysis & ops (new)

v3.2 adds seven phases on top of v3.1, all additive and safe:

- `attack_path` (`--chain-simulate`) — findings → multi-stage attack chains +
  MITRE ATT&CK map (+ ATT&CK Navigator layer).
- `compliance_coverage` — OWASP Top 10 / CWE / PCI-DSS matrix + gap detection.
- `supply_chain_review` — dependency confusion / typosquat / lockfile integrity.
- `honeypot_detection` — deception/trap warning from collected data.
- `egress_canary` (`--test-egress-canary`) — DLP/egress reachability matrix,
  canary tokens only, no data exfiltrated.
- `iac_drift` (`--terraform-state` + `--live-inventory`) — shadow-resource /
  ClickOps drift detection.
- `evidence_finalize` — `--evidence-manifest` (SHA256 + redaction scan),
  `--roe-ticket` stamping, and `--ci` (junit.xml + non-zero gate on CRITICAL/HIGH).

Regression: v3.1/v3.2 are strict supersets of v3 — 66 phases, all load, nothing
removed. Exploitation/C2/wireless-active/live-phishing items from the roadmap are
kept as safe detection/review per the tool's existing `*_safe` model; see
`CHANGELOG-v3.2.md` for the explicit in/out list.

---

# TBHM v3.1-redteam-safe

## v3.1 — source-code intelligence (new)

v3.1 adds a full source-code testing brain on top of everything below. The new
`code_intel` phase turns a repo into a code-intelligence map and then connects
`source code -> live endpoint -> exploit hypothesis -> safe verification -> report`.

- Framework/stack detection, framework-aware route extraction, auth/roles/models
  and upload/payment/admin/webhook/cloud/mobile/AI handler mapping.
- Source→vuln traces: `file -> function -> input -> sink -> missing control ->
  possible vuln -> how to safely test live`.
- Endpoint→live matching (reachability only, no payloads).
- 15 branch modules, each with its own output file, plus a remediation plan.
- Additive and safe: `code_scan` and every other phase are unchanged; exploit
  confirmation is delegated to the existing consented active phases.

See `CHANGELOG-v3.1.md` for flags, output layout, and the full example command.

---

# TBHM v3.0-redteam-safe

## What this is

This is a merged v3 build made from:

1. `TBHM-v2_24-redteam-safe` as the full base tool.
2. `tbhm_v2_24_addons` as extra modules.

The add-ons are now wired into the real TBHM phase system instead of staying as a separate package.

## New v3 capabilities

| Capability | Native v2.24 redteam | v2.24 add-ons | v3 merged build |
|---|---:|---:|---:|
| Full TBHM CLI/profiles/reports | ✅ | ❌ | ✅ |
| Redteam-safe orchestration | ✅ | ❌ | ✅ |
| Focused SQLi verifier | Partial | ✅ | ✅ integrated as `add_sqli` |
| Deeper read-only AD SPN/AS-REP/delegation/crypto review | Partial | ✅ | ✅ integrated as `add_net_ad` |
| Windows service primitive detection | ❌ | ✅ | ✅ integrated as `add_service_primitive` |
| Add-on structured logs | ❌ | ✅ | ✅ for v3 add-on phases |
| Native TBHM findings/report integration | ✅ | ❌ | ✅ |

## New phases

### `add_sqli`

A focused SQL injection verifier for URLs with query parameters.

It checks:

- Error-based SQLi signals.
- Boolean response differentials.
- Time-delay differentials.
- Optional conservative sqlmap confirmation after a firm hit.

It does **not** dump database data.

### `add_net_ad`

A deeper read-only AD review.

It checks:

- SPN accounts / Kerberoast target exposure.
- AS-REP roastable accounts.
- Delegation configuration.
- Weak Kerberos crypto such as DES / RC4-only.
- Password-never-expires accounts.
- DC fingerprinting and safe host discovery when CIDR/DC inputs are supplied.

It does **not** request tickets, crack passwords, relay NTLM, run DCSync, dump credentials, move laterally, or persist.

### `add_service_primitive`

Local Windows service primitive review.

It checks:

- Writable service binaries.
- Writable service binary directories.
- Unquoted service paths with writable intermediates.
- Weak service ACL conditions.
- DLL-hijackable writable service directories.

It does **not** drop executable payloads or restart services. Optional proof uses a temporary inert `.txt` marker only when `--allow-writes --svc-prove-writable` are both supplied.

## Recommended use

### Normal web/API test with v3 SQLi add-on

```bash
python3 tbhm.py -u https://target.example/path?id=1 --profile authorized_safe -y --phases add_sqli --addon-sqli-target 'https://target.example/path?id=1'
```

### Full internal red-team review

```bash
export TBHM_AD_PASSWORD='READ_ONLY_AD_PASSWORD_HERE'
python3 tbhm.py -d company.local --profile authorized_redteam -y --redteam --corp-cidr 10.10.0.0/16 --dc-ip 10.10.10.10 --ad-domain company.local --ad-user readonly@company.local
```

### Disable all v3 add-ons

```bash
python3 tbhm.py -d example.com --profile authorized_safe -y --no-addons
```

## Evidence locations

V3 add-on evidence is written under:

```text
results/<run>/evidence/v3_addons/
```

Add-on structured logs are written under:

```text
results/<run>/logs/
```

Files include:

- `full.jsonl`
- `full.log`
- `exceptions.jsonl`
- `audit.jsonl`
- `background.json`

## Build note

This v3 package keeps the original v2.24 safety model. The new modules are integrated as additional safe verification and review phases, not as destructive exploit automation.

## v3.7 additive tooling adapters

TBHM now accepts evidence from external web, SAST, mobile, AI/LLM, network and firewall scanners without replacing its native phases. See `CHANGELOG-v3.7.md` and `--help` for the opt-in flags. Commercial tools are integrated through their exported JSON, XML or SARIF evidence so the results can be normalized, verified and reported by TBHM.

## v3.8 additive external, reverse-engineering, privilege, AD and code-security adapters

v3.8 expands the safe integration architecture without replacing any existing phase:

- `external_perimeter_tooling`: normalizes Amass, Sublist3r, Shodan, Maltego/theHarvester, web scanner, OpenVAS/Nessus/Nuclei, SearchSploit and Metasploit assessment evidence. It deliberately excludes phishing credential capture, Evilginx, SET payload delivery, C2, covert tunnels and exploit execution.
- `reverse_engineering_tooling`: performs bounded static metadata/string review and imports IDA, Ghidra, radare2/Cutter, capa, DIE/PE-bear, mobile and firmware analysis results. It does not execute samples, inject into processes, attach debuggers or boot firmware.
- `privesc_audit_tooling`: imports LinPEAS, WinPEAS, LinEnum, PSpy, PowerUp, Seatbelt, SharpUp and exploit-suggester output. It never attempts elevation or launches an exploit.
- `internal_ad_tooling`: normalizes BloodHound/SharpHound, ADRecon, LDAP/PowerView/ADFind, NetExec/CrackMapExec, Impacket and related authorized evidence. Password spraying, credential dumping, relay, ticket attacks, remote execution, DCShadow and persistence are excluded.
- `code_security_tooling`: optionally runs local read-only Bandit, njsscan, Gitleaks, Trivy, Grype, Checkov, Terrascan and tfsec adapters against `--code-dir`, and imports JSON/SARIF from commercial/open-source SAST, SCA, secret, IaC, IAST/RASP and AI review products.

All imported results flow through TBHM's existing finding storage, false-positive review, verification, evidence finalization and reporting layers.

## v3.9-local-ai-safe additive update

v3.9 preserves the v3.8 pipeline and adds opt-in local-only finding enrichment, deterministic source-orchestrator import/execution, expanded read-only source scanners, and a safe AD access/exposure assessment.

- Local model and source tooling: `docs/LOCAL_LLM_AND_SOURCE_TOOLING_v3.9.md`
- AD assessment safety boundary: `docs/AD_ACCESS_SAFE_BOUNDARY_v3.9.md`
- Full additive changes: `CHANGELOG-v3.9-local-ai-safe.md`

The update does not add credential capture/cracking, lateral movement, remote shells, domain-secret dumping, defense evasion, or any safety-gate override.

## v3.9.1 integrated local LLM and exercise-evidence update

v3.9.1 keeps the v3.9 pipeline intact and adds two opt-in capabilities:

1. The local Ollama model is now a shared TBHM runtime and is automatically used by report generation when `--local-llm` is enabled. Use `--local-llm-status` and `--local-llm-setup` without a target for local readiness and model management.
2. `engagement_evidence_review` imports sanitized evidence from separately authorized exercises or generates a synthetic instructor scenario. It preserves provenance and produces lead-only observations; it does not execute the represented activity.

See `docs/INTEGRATED_LLM_AND_EXERCISE_EVIDENCE_v3.9.1.md` and `CHANGELOG-v3.9.1-integrated-llm-evidence-safe.md`.

## v3.9.2 evidence confirmation, reporting, and reverse engineering

- Global evidence-grounded exploitability assessment for every finding.
- Strict confirmed/supported/lead separation.
- Complete final-report sections and complete per-confirmed-vulnerability records.
- Five-stage reverse-engineering pipeline using static orchestration plus controlled dynamic-evidence import.
- Structured local-LLM access-path summary and evidence-gap fields; the model remains non-authoritative.

See `docs/REVERSE_ENGINEERING_AND_REPORTING_v3.9.2.md`.
