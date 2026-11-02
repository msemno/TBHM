# TBHM v3.9.7.1-backward-compatibility

This release upgrades the original v3.9.6 enterprise-control-plane source tree in two stages:

- **v3.9.7 capability depth:** truthful capability registry, environment doctor, allowlisted read-only plan execution, import-only session/beacon normalization, native RDAP collection framework, cloud IAM graph analysis, evidence predicates for compliance, CI/CD trust/dataflow analysis, class-aware OCSF export, passive wireless inventory, and proposal-only adapter generation.
- **v3.9.7.1 backward compatibility:** historical source archaeology across v2.16-fixed, v2.21, v3.8-expanded, v3.9.5, and the original v3.9.6; restored compatibility surfaces; corrected false-positive controls; canonical profile ordering; and machine-readable baseline comparison.

## Measured compatibility

- Original v3.9.6 source paths preserved: **322 / 322**.
- Original CLI option strings preserved: **300 / 300**.
- Final CLI option strings: **330**.
- Original ordered phases preserved: **124 / 124**.
- Final ordered phases: **129**.
- New real phases: `integration_adapter_proposal`, `osint_api_collectors`, `passive_wireless_inventory`, `safe_plan_execution`, and `session_beacon_import`.
- Known unintentional breaking changes: **none found**.

## Capability registry and doctor

- Added `tooling/capability_registry_v3971.json` and `core/capability_registry.py`.
- Added `--capability-status [ID[,ID]]` and optional `--capability-registry`.
- Added `--doctor` with package, executable, configuration, policy, evidence-store, local-AI, output-directory, environment-variable-presence, and optional local-service checks.
- Planned or unavailable capabilities are never presented as operational.
- Missing optional tools degrade honestly instead of terminating the whole application.

## Safe execution from structured plans

- Added `core/safe_plan_executor.py` and the `safe_plan_execution` phase.
- Initial allowlist is limited to native RDAP lookup, Sherlock username lookup, Maigret username lookup, and local `cosign verify-blob`.
- Unknown actions, arbitrary commands, raw executables, raw argv, shell fields, shell metacharacters, and unsupported arguments are rejected.
- Subprocesses use validated argument lists, bounded timeouts, and no shell expansion.
- Dry-run output, timestamps, tool versions, exit codes, stdout/stderr bounds, approval state, provenance, and evidence hashes are recorded.

## Import-only and passive evidence features

- Added JSON/CSV session and beacon evidence import with validation, deterministic identifiers, deduplication, provenance, malformed-record accounting, and optional username redaction. No C2 service, payload generation, beacon execution, or session control exists.
- Added passive wireless JSON/CSV inventory for SSID, BSSID, channel, frequency, encryption, signal, vendor, timestamps, source, user-supplied location label, and risk notes. No capture, deauthentication, cracking, impersonation, rogue access point, or credential interception exists.

## OSINT, cloud, compliance, CI/CD, and OCSF

- Added a provider framework with a genuinely implemented and offline-tested native RDAP collector. No other provider is falsely advertised as native.
- Added normalized AWS, Azure, GCP, and generic IAM graph imports with evidence-backed privilege paths, uncertainty, prerequisites, and compatibility output `cloud_identity_paths.json`.
- Preserved indicators for AWS `iam:CreateAccessKey` and Azure Application Administrator without treating a permission name as proof of exploitability.
- Added control-level compliance predicates with `pass`, `fail`, `unknown`, `not_applicable`, and `not_tested`; a scanner run alone cannot create a pass.
- Added native CI/CD workflow trust/dataflow analysis and truthful optional-tool reporting for actionlint, zizmor, cosign, and related evidence. Workflow commands are never executed.
- Added class-aware OCSF-style events and deterministic fingerprints that exclude volatile runtime fields.

## Historical regression recovery

- Strengthened curl method-override validation with an ordinary-GET control; a plain 405 is not a finding.
- Added same-host catch-all controls and content-type/body validation for sensitive-file probes.
- Added a direct `/admin` control for X-Original-URL/X-Rewrite-URL routing checks.
- Retained the bounded non-destructive Range-header indicator.
- Nuclei now counts only structurally usable templates and reports failed updates instead of implying success.
- Retained absolute workflow paths, tag fallback, ProjectDiscovery httpx identity checks, Go `/v2` and `/v3` executable-name handling, idempotent installer behavior, and non-privileged Python package installation.
- Added bounded recursion, cross-line deduplication, source provenance, CWE preservation, and SARIF-specific handling to the shared scanner normalizer.
- Retained the five-stage reverse workflow and strengthened the dependency-free fallback with bounded reads, canonical hashes, short dangerous-API detection, valid IP filtering, and secret redaction.
- Restored useful reporter, reverse, and code-security compatibility wrappers without replacing the modern implementations.

## Reporting compatibility

The release writes both current and compatibility machine-readable names:

- `report.json` and `REPORT.json`
- `report.csv` and `REPORT.csv`
- `report.sarif` and `REPORT.sarif`

It also preserves `REPORT.html`, `REPORT_final.html`, `REPORT_final.md`, `REPORT_confirmed.md`, `REPORT_leads.md`, audience reports, `METHODOLOGY_AUDIT.md`, and complete per-finding reproducer kits. The qualified posture rule remains explicit: no confirmed finding does not mean the target is safe.

## Safety boundaries

No autonomous credential theft, credential dumping, password spraying, brute force, phishing delivery, MFA interception, exploit weaponization, arbitrary remote command execution, reverse shell, C2 startup, persistence, lateral movement, DCSync, ticket forgery, pass-the-hash, ransomware, EDR bypass, disruptive wireless operation, badge cloning, lock bypass, OT/ICS write operation, destructive cloud action, or arbitrary AI-plan shell execution was added.
