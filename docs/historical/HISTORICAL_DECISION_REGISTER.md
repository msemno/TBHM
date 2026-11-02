# Historical Decision Register

Total classified decisions: **29**. No meaningful reviewed difference remains `UNRESOLVED`.

## HIST-0001 — source_precedence

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v2.16-v3.9.6 — `all historical trees`
- **Current implementation:** `v3.9.6 source tree`
- **Old behavior:** Older trees provide behavioral references.
- **Current behavior:** v3.9.6 remains the only implementation baseline; older code is merged selectively.
- **Regression/improvement:** Prevents wholesale downgrade while allowing safer/correct behavior recovery.
- **Safety:** Newer safety boundaries win unless an older implementation is demonstrably stricter.
- **Evidence quality:** Every merge is tied to a focused offline test and decision record.
- **Compatibility:** No public path is replaced wholesale.
- **Implementation:** No source change; policy decision only.
- **Tests:** `integration_test_historical_regressions_v3971.py`
- **Residual risk:** Undocumented external consumers may depend on private internals not visible in supplied archives.

## HIST-0002 — curl_method_override

- **Decision:** `MERGE_OLD_AND_NEW`
- **Historical source:** v2.16-fixed — `core/curl_probes.py::probe_method_override`
- **Current implementation:** `core/curl_probes.py::probe_method_override`
- **Old behavior:** Synthetic DEBUG override; plain 405 must not confirm.
- **Current behavior:** Same-request GET control plus explicit DEBUG-context or status differential.
- **Regression/improvement:** Strengthened the old false-positive fix with a direct control.
- **Safety:** Non-destructive fake method only; no state-changing method is sent.
- **Evidence quality:** Requires meaningful response evidence, not status alone.
- **Compatibility:** Same function and return tuple retained.
- **Implementation:** `core/curl_probes.py`
- **Tests:** `integration_test_historical_regressions_v3971.py`
- **Residual risk:** Some frameworks normalize both control and override responses, producing an intentional false negative rather than an unsafe false positive.

## HIST-0003 — curl_sensitive_files

- **Decision:** `MERGE_OLD_AND_NEW`
- **Historical source:** v2.16-fixed/v2.21 — `core/curl_probes.py::probe_sensitive_files`
- **Current implementation:** `core/curl_probes.py::probe_sensitive_files`
- **Old behavior:** GET probes with body signatures.
- **Current behavior:** Adds random same-host control, content-type filtering and distinctive-body checks.
- **Regression/improvement:** Generic SPA/soft-404 HTML no longer confirms .env or .git/config exposure.
- **Safety:** Read-only GET requests, throttled and timed out.
- **Evidence quality:** Body signature and control differential are stored in the reproducer evidence.
- **Compatibility:** Same public function retained.
- **Implementation:** `core/curl_probes.py`
- **Tests:** `integration_test_historical_regressions_v3971.py`
- **Residual risk:** Highly customized raw-file renderers may require manual review.

## HIST-0004 — curl_admin_bypass

- **Decision:** `RESTORE_OLDER_BEHAVIOR`
- **Historical source:** v2.16-fixed — `core/curl_probes.py::probe_admin_bypass`
- **Current implementation:** `core/curl_probes.py::probe_admin_bypass`
- **Old behavior:** Header routing probe looked only at the injected response.
- **Current behavior:** Direct /admin control is compared with the header-routed request.
- **Regression/improvement:** Eliminates root-dashboard false positives and requires access-control differential.
- **Safety:** Read-only request; localhost forwarding header removed from the bypass claim.
- **Evidence quality:** Admin-specific content plus denied/absent direct control is required.
- **Compatibility:** Same function and output contract retained.
- **Implementation:** `core/curl_probes.py`
- **Tests:** `integration_test_historical_regressions_v3971.py`
- **Residual risk:** Reverse proxies that intentionally mask direct responses may still need manual confirmation.

## HIST-0005 — curl_range_indicator

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v2.16-fixed — `core/curl_probes.py::probe_range_overflow`
- **Current implementation:** `core/curl_probes.py::probe_range_overflow`
- **Old behavior:** Bounded overlapping Range header indicator.
- **Current behavior:** Retained as a 20-range, read-only indicator with timeout and qualified language.
- **Regression/improvement:** No destructive denial-of-service workload added.
- **Safety:** Safe bounded request only.
- **Evidence quality:** 206 is a lead requiring manual safe retest, not proof of service exhaustion.
- **Compatibility:** Same function retained.
- **Implementation:** `core/curl_probes.py`
- **Tests:** `integration_test_historical_regressions_v3971.py`
- **Residual risk:** 206 may be standards-compliant on some servers; report language remains qualified.

## HIST-0006 — nuclei_template_management

- **Decision:** `MERGE_OLD_AND_NEW`
- **Historical source:** v2.16-fixed — `core/bootstrap.py::nuclei_template_count/ensure_nuclei_templates`
- **Current implementation:** `core/bootstrap.py::_template_is_valid/_valid_template_count/ensure_nuclei_templates`
- **Old behavior:** Known paths and bounded self-healing update.
- **Current behavior:** Common paths retained; only structurally valid YAML is counted; nonzero update exits are reported.
- **Regression/improvement:** Malformed or empty stores can no longer be reported healthy.
- **Safety:** Updates are explicit, bounded and only attempted when nuclei exists and store is below threshold.
- **Evidence quality:** stderr/exit code and post-update valid count determine result.
- **Compatibility:** Existing functions and return keys preserved; error field is additive.
- **Implementation:** `core/bootstrap.py`
- **Tests:** `integration_test_historical_regressions_v3971.py`
- **Residual risk:** Template schemas evolve; structural validation intentionally checks mandatory fields rather than every Nuclei schema rule.

## HIST-0007 — nuclei_workflows

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v2.16-fixed — `phases/nuclei_extended.py::_resolve_sweep_args`
- **Current implementation:** `phases/nuclei_extended.py::_resolve_sweep_args`
- **Old behavior:** Absolute workflow directory with tag fallback.
- **Current behavior:** Retained unchanged when valid workflows exist; tags used when absent.
- **Regression/improvement:** Avoids silent no-template runs caused by fragile relative paths.
- **Safety:** No workflow execution during tests.
- **Evidence quality:** Resolved command arguments reveal whether workflow or tag coverage was used.
- **Compatibility:** Same helper retained.
- **Implementation:** `phases/nuclei_extended.py`
- **Tests:** `integration_test_historical_regressions_v3971.py`
- **Residual risk:** Installed templates may omit expected technology workflows; tag fallback provides partial coverage only.

## HIST-0008 — installer_tool_identity

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v2.16-fixed — `install.sh::go_tool_name/tool_is_usable`
- **Current implementation:** `install.sh::go_tool_name/tool_is_usable`
- **Old behavior:** Go semantic-import suffixes and ProjectDiscovery httpx identity handling.
- **Current behavior:** Retained and regression-checked; no privileged pip install added.
- **Regression/improvement:** Prevents false detection of binaries named v2/v3 or unrelated Python httpx.
- **Safety:** Installation remains explicit; optional failures degrade gracefully.
- **Evidence quality:** Tool version output is used for identity validation.
- **Compatibility:** Shell function behavior retained.
- **Implementation:** `install.sh`
- **Tests:** `integration_test_historical_regressions_v3971.py`
- **Residual risk:** Installer still depends on external package managers and network availability when the operator invokes it.

## HIST-0009 — false_positive_baselines

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v2.20-v2.21 — `core/api_baseline.py/core/fp_engine.py/core/soft404.py`
- **Current implementation:** `same modules`
- **Old behavior:** Random-path, status, body, length, redirect and JSON-code controls.
- **Current behavior:** Retained and tested across wildcard 200, custom 404, redirect and JSON catch-all fixtures.
- **Regression/improvement:** Prevents status-200-only endpoint confirmation.
- **Safety:** At most a small bounded number of control requests; shared rate limiter remains authoritative.
- **Evidence quality:** Differential evidence is required to classify an endpoint as distinct.
- **Compatibility:** Public helpers retained.
- **Implementation:** `core/api_baseline.py`, `core/fp_engine.py`, `core/soft404.py`
- **Tests:** `integration_test_historical_regressions_v3971.py`
- **Residual risk:** Dynamic pages with highly variable bodies may need manual baselining.

## HIST-0010 — source_mobile_interfaces

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v2.17-v2.21 — `phases/code_scan.py, phases/mobile_scan.py and interface phases`
- **Current implementation:** `same paths plus later enrichment phases`
- **Old behavior:** Source/mobile/SBOM/API/GraphQL/WebSocket/SSE/PWA/CNAME/safe-smuggling discovery.
- **Current behavior:** All historical paths remain; newer confirmation model keeps static results as leads.
- **Regression/improvement:** Newer implementation is a functional and safety superset.
- **Safety:** No static observation self-confirms; active checks remain scope- and profile-gated.
- **Evidence quality:** Reachability, provenance and evidence strength are separated.
- **Compatibility:** All v3.9.6 paths and phase names retained.
- **Implementation:** `phases/code_scan.py`, `phases/mobile_scan.py`, `phases/interface_identity_discovery.py`, `phases/sbom.py`
- **Tests:** `integration_test_v3961.py`, `integration_test_v3971.py`
- **Residual risk:** Optional external analyzers may be unavailable and are reported as coverage gaps.

## HIST-0011 — governance_coverage

- **Decision:** `PRESERVE_WITH_COMPATIBILITY_ALIAS`
- **Historical source:** v2.22-v2.24 — `core/reporter.py legacy branch helpers and governance phases`
- **Current implementation:** `core/reporter.py::_load_branch_matrix/_branch_status_from_findings and current governance summaries`
- **Old behavior:** Branch matrix, objective map, approval register, safe-write policy and conservative status language.
- **Current behavior:** Structured governance architecture retained with compatibility helpers restored.
- **Regression/improvement:** Detailed branch table had disappeared from newer report output and is restored.
- **Safety:** Not Tested is never rendered Safe; absence of findings is not a pass.
- **Evidence quality:** Coverage status references actual phase/finding evidence.
- **Compatibility:** Legacy helper names restored where externally callable.
- **Implementation:** `core/reporter.py`, `phases/coverage_map.py`, `phases/redteam_governance.py`
- **Tests:** `integration_test_v3961.py`, `integration_test_historical_regressions_v3971.py`
- **Residual risk:** Automated branch mapping remains partial and requires human review.

## HIST-0012 — addon_compatibility

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v3.0-v3.3 — `tbhm_addons/* and safe add-on phases`
- **Current implementation:** `same paths and current phase graph`
- **Old behavior:** Opt-in SQLi, read-only AD, service primitive and code-intelligence add-ons.
- **Current behavior:** Preserved as opt-in/local-only or approval-controlled paths.
- **Regression/improvement:** No historical add-on becomes active by default.
- **Safety:** Write-capable or sensitive actions remain disabled/external.
- **Evidence quality:** Add-on outputs flow through evidence manifests as leads unless confirmed separately.
- **Compatibility:** Paths, imports and phase names retained.
- **Implementation:** `tbhm_addons`, `tbhm.py`
- **Tests:** `integration_test_addons.py`, `integration_test_v3961.py`
- **Residual risk:** Third-party tool/API availability remains environment-dependent.

## HIST-0013 — confirmation_model

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v3.4-v3.6 — `core/fp_filters.py and confirmation phases`
- **Current implementation:** `core/fp_filters.py, core/exploitability.py and confirmation phases`
- **Old behavior:** Path/test/doc/placeholder/entropy suppression and runtime proof parsing.
- **Current behavior:** Five-level evidence distinction is retained: observation, reachable observation, supported, reproduced, confirmed.
- **Regression/improvement:** Static traces cannot confirm themselves.
- **Safety:** Live validation is authorization-gated and bounded.
- **Evidence quality:** Confirmation basis, negative controls and provenance are report fields.
- **Compatibility:** Existing status keys retained with additive fields.
- **Implementation:** `core/fp_filters.py`, `core/exploitability.py`, `phases/exploitability_assessment.py`, `phases/fp_review.py`
- **Tests:** `integration_test_v393.py`, `integration_test_v3941.py`, `integration_test_v395.py`
- **Residual risk:** Business-logic confirmation still requires suitable test accounts and manual judgment.

## HIST-0014 — scanner_normalization

- **Decision:** `REPLACE_OLD_WITH_NEW`
- **Historical source:** v3.7-v3.8 — `phases/code_security_tooling.py::sev/walk`
- **Current implementation:** `core/scanner_normalizer.py plus compatibility wrappers`
- **Old behavior:** Tool-specific recursive generic parser.
- **Current behavior:** Shared JSON/JSONL/SARIF normalizer with bounded recursion, deduplication, CWE, location and provenance preservation.
- **Regression/improvement:** The shared implementation is stricter and avoids duplicate SARIF parsing.
- **Safety:** Imported records remain leads; malformed input is ignored safely.
- **Evidence quality:** Source, rule, file, line, CWE and raw record provenance are retained.
- **Compatibility:** sev/walk wrappers retained for import compatibility; shared normalizer is preferred.
- **Implementation:** `core/scanner_normalizer.py`, `phases/code_security_tooling.py`
- **Tests:** `integration_test_historical_regressions_v3971.py`, `integration_test_v3961.py`
- **Residual risk:** Highly proprietary scanner formats may need an explicit reviewed adapter.

## HIST-0015 — reporter_migration

- **Decision:** `PRESERVE_WITH_COMPATIBILITY_ALIAS`
- **Historical source:** v2.16-v3.8 — `core/reporter.py::_top_concerns_md/_defender_ioc_for/_write_html`
- **Current implementation:** `core/reporter.py compatibility helpers plus structured renderers`
- **Old behavior:** Legacy private helpers produced audience summaries and HTML.
- **Current behavior:** Modern structured report remains authoritative; helper names restored as wrappers/compatible implementations.
- **Regression/improvement:** Avoids blindly reverting to the old reporter while preserving callable surfaces.
- **Safety:** Report language remains evidence-bounded and redacted.
- **Evidence quality:** All confirmation fields and per-finding kits are generated from normalized assessments.
- **Compatibility:** Legacy names and old REPORT.html path preserved.
- **Implementation:** `core/reporter.py`
- **Tests:** `integration_test_v3961.py`, `integration_test_historical_regressions_v3971.py`
- **Residual risk:** Private-helper consumers outside the supplied tree may still rely on undocumented exact formatting.

## HIST-0016 — report_output_contracts

- **Decision:** `MERGE_OLD_AND_NEW`
- **Historical source:** v2.16-v3.9.6 — `report.json/report.csv/report.sarif and REPORT* outputs`
- **Current implementation:** `lowercase canonical outputs plus uppercase compatibility writers`
- **Old behavior:** Machine-readable and multi-audience reports evolved across releases.
- **Current behavior:** Both lowercase current names and uppercase compatibility names are written deterministically.
- **Regression/improvement:** Restores REPORT.json, REPORT.csv and REPORT.sarif consumers without removing current paths.
- **Safety:** No finding is upgraded by export.
- **Evidence quality:** Exports preserve evidence references, confirmation, confidence and provenance.
- **Compatibility:** Additive aliases; no old path removed.
- **Implementation:** `core/reporter.py`, `phases/report.py`
- **Tests:** `integration_test_historical_regressions_v3971.py`, `integration_test_v3961.py`
- **Residual risk:** Duplicate aliases consume modest disk space by design.

## HIST-0017 — reverse_engineering_fallback

- **Decision:** `MERGE_OLD_AND_NEW`
- **Historical source:** v3.8 — `phases/reverse_engineering_tooling.py::import_json/static_strings`
- **Current implementation:** `core/reverse_utils.py, core/scanner_normalizer.py and compatibility wrappers`
- **Old behavior:** Dependency-free strings/import/JSON fallback.
- **Current behavior:** Modern five-stage workflow is primary; bounded dependency-free fallback and legacy wrappers are retained.
- **Regression/improvement:** Short dangerous APIs, canonical hashes, valid IPs, secret redaction and bounded reads are improved.
- **Safety:** No target artifact is executed.
- **Evidence quality:** Canonical artifact ID and per-binary metadata correlate all stages; capa/imported output stays non-confirming.
- **Compatibility:** Legacy helper names and evidence directories supported.
- **Implementation:** `core/reverse_utils.py`, `phases/reverse_engineering_tooling.py`, `phases/reverse_triage.py`, `phases/reverse_static_analysis.py`, `phases/reverse_dynamic_evidence.py`, `phases/reverse_symbolic_analysis.py`, `phases/reverse_correlation.py`
- **Tests:** `integration_test_historical_regressions_v3971.py`, `integration_test_v3961.py`, `integration_test_v392.py`
- **Residual risk:** Packed/encrypted binaries and unsupported formats require external manual analysis.

## HIST-0018 — phase_ordering

- **Decision:** `MERGE_OLD_AND_NEW`
- **Historical source:** v3.9.6 — `tbhm.py::PHASE_ORDER and profile YAML`
- **Current implementation:** `tbhm.py::canonicalize_profile_phases and PHASE_ORDER`
- **Old behavior:** Profiles could place OSINT before preflight or Web3 after report finalization.
- **Current behavior:** All profile subsets are canonicalized against one graph; preflight first and evidence_finalize last.
- **Regression/improvement:** Corrects orchestration regressions without deleting explicit operator phase overrides.
- **Safety:** Safety preflight precedes operational phases.
- **Evidence quality:** Report/finalization cannot precede optional operational phases in canonical profiles.
- **Compatibility:** All old phase identifiers retained; five real opt-in phases added.
- **Implementation:** `tbhm.py`, `profiles/authorized_assumed_breach.yaml`, `profiles/authorized_redteam.yaml`, `profiles/quick_recon.yaml`
- **Tests:** `integration_test_v3961.py`, `integration_test_v3971.py`
- **Residual risk:** Explicit --phases remains intentionally operator-controlled and may choose a custom subset.

## HIST-0019 — capability_truthfulness

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v3.9.6 — `distributed tool/phase claims`
- **Current implementation:** `core/capability_registry.py and tooling/capability_registry_v3971.json`
- **Old behavior:** Capabilities were inferred from phases and documentation.
- **Current behavior:** Central registry declares native/adapter/import/proposal/planned/unavailable state and requirements.
- **Regression/improvement:** Prevents planned or unavailable functions from being presented as operational.
- **Safety:** Approval, network and safety classes are explicit.
- **Evidence quality:** Status command reports exact availability reasons and dependencies.
- **Compatibility:** Existing phases remain; registry is additive.
- **Implementation:** `core/capability_registry.py`, `tooling/capability_registry_v3971.json`, `tbhm.py`
- **Tests:** `integration_test_v3971.py`
- **Residual risk:** Registry metadata must be updated when integrations change.

## HIST-0020 — environment_doctor

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v3.9.6 — `diagnostics/bootstrap checks`
- **Current implementation:** `core/doctor.py and --doctor`
- **Old behavior:** Checks were distributed and focused mainly on scan tooling.
- **Current behavior:** Unified truthful environment, policy, evidence-store, package, executable and secret-presence checks.
- **Regression/improvement:** Missing optional dependencies no longer imply global failure.
- **Safety:** Secret values are never printed; service probes are opt-in.
- **Evidence quality:** Every failed check includes a reason/remediation.
- **Compatibility:** Additive management command; old diagnostics retained.
- **Implementation:** `core/doctor.py`, `tbhm.py`
- **Tests:** `integration_test_v3971.py`
- **Residual risk:** Service reachability is not checked unless explicitly requested.

## HIST-0021 — safe_plan_execution

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v3.9.6 — `proposal/plan-only orchestration`
- **Current implementation:** `core/safe_plan_executor.py and phases/safe_plan_execution.py`
- **Old behavior:** Plans were generated but not natively executable.
- **Current behavior:** Only RDAP, Sherlock, Maigret and local cosign verify-blob are allowlisted with structured arguments.
- **Regression/improvement:** Adds real capability without arbitrary command execution.
- **Safety:** Unknown actions, shell fields, metacharacters and unapproved actions are rejected; shell=False.
- **Evidence quality:** Timestamps, exit code, version, stdout/stderr and provenance are recorded.
- **Compatibility:** Opt-in phase; no old behavior removed.
- **Implementation:** `core/safe_plan_executor.py`, `phases/safe_plan_execution.py`, `tbhm.py`
- **Tests:** `integration_test_v3971.py`
- **Residual risk:** External tools may change CLI syntax; failures are captured honestly.

## HIST-0022 — session_beacon_import

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v3.9.6 — `external evidence import concepts`
- **Current implementation:** `core/session_importer.py and phases/session_beacon_import.py`
- **Old behavior:** No normalized dedicated session/beacon importer.
- **Current behavior:** JSON/CSV import-only tracker with validation, deterministic IDs and deduplication.
- **Regression/improvement:** Adds reporting depth without C2 startup, payload generation or control.
- **Safety:** Import-only safety class.
- **Evidence quality:** Every record retains source/provenance and malformed records are counted.
- **Compatibility:** Additive opt-in phase.
- **Implementation:** `core/session_importer.py`, `phases/session_beacon_import.py`
- **Tests:** `integration_test_v3971.py`
- **Residual risk:** Vendor-specific fields outside the normalized schema remain in raw provenance only where safe.

## HIST-0023 — osint_api_collectors

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v3.9.6 — `OSINT depth collectors`
- **Current implementation:** `core/osint_collectors.py and phases/osint_api_collectors.py`
- **Old behavior:** Mixed external tools and proposal-only provider coverage.
- **Current behavior:** Provider framework with one genuinely implemented native RDAP collector; other providers are not falsely advertised.
- **Regression/improvement:** Adds bounded retry, rate, timeout, PII policy, redaction and offline transport fixtures.
- **Safety:** No real service calls occur in tests; credentials are presence-checked only.
- **Evidence quality:** Provider errors and provenance are normalized.
- **Compatibility:** Additive opt-in capability.
- **Implementation:** `core/osint_collectors.py`, `phases/osint_api_collectors.py`
- **Tests:** `integration_test_v3971.py`
- **Residual risk:** Only RDAP is native in this release; additional APIs require reviewed implementations.

## HIST-0024 — cloud_iam_graph

- **Decision:** `MERGE_OLD_AND_NEW`
- **Historical source:** v3.9.6 — `phases/cloud_identity_path_analysis.py legacy indicators`
- **Current implementation:** `core/cloud_iam_graph.py and upgraded phase`
- **Old behavior:** Permission-name indicators and limited normalized paths.
- **Current behavior:** AWS/Azure/GCP/generic graph import with evidence-backed paths and compatibility output.
- **Regression/improvement:** Restores CreateAccessKey and Azure Application Administrator indicators while avoiding exploitability claims.
- **Safety:** Read-only import/analyze only.
- **Evidence quality:** Paths list prerequisites, uncertainty and source evidence.
- **Compatibility:** cloud_identity_paths.json and legacy helper behavior retained.
- **Implementation:** `core/cloud_iam_graph.py`, `phases/cloud_identity_path_analysis.py`
- **Tests:** `integration_test_v3971.py`, `integration_test_v3961.py`
- **Residual risk:** Provider exports vary; partially recognized data is imported generically with lower confidence.

## HIST-0025 — compliance_predicates

- **Decision:** `MERGE_OLD_AND_NEW`
- **Historical source:** v3.9.6 — `phases/compliance_reporting_extended.py`
- **Current implementation:** `core/compliance_predicates.py and upgraded phase`
- **Old behavior:** Some summaries could imply coverage from tool execution.
- **Current behavior:** Control predicates evaluate actual evidence with pass/fail/unknown/not_applicable/not_tested.
- **Regression/improvement:** A scanner run alone cannot produce pass.
- **Safety:** Read-only evidence evaluation.
- **Evidence quality:** Reason, confidence, evaluator version and references are mandatory.
- **Compatibility:** Existing mappings and output keys retained.
- **Implementation:** `core/compliance_predicates.py`, `phases/compliance_reporting_extended.py`
- **Tests:** `integration_test_v3971.py`
- **Residual risk:** Control mappings remain advisory and require assessor review for formal certification.

## HIST-0026 — cicd_dataflow

- **Decision:** `MERGE_OLD_AND_NEW`
- **Historical source:** v3.9.6 — `phases/ci_cd_supply_chain_security.py`
- **Current implementation:** `core/cicd_dataflow.py and upgraded phase`
- **Old behavior:** Workflow checks and optional external tool summaries.
- **Current behavior:** Native trust/dataflow analysis plus honest actionlint/zizmor/cosign availability.
- **Regression/improvement:** Untrusted sources reaching shell and risky trust boundaries are modeled without command execution.
- **Safety:** Workflow commands are parsed only, never executed.
- **Evidence quality:** Findings include source, sink, path, permissions and uncertainty.
- **Compatibility:** Legacy summary keys retained.
- **Implementation:** `core/cicd_dataflow.py`, `phases/ci_cd_supply_chain_security.py`
- **Tests:** `integration_test_v3971.py`, `integration_test_v3961.py`
- **Residual risk:** Complex reusable workflows and generated YAML may require manual graph expansion.

## HIST-0027 — ocsf_export

- **Decision:** `MERGE_OLD_AND_NEW`
- **Historical source:** v3.9.6 — `core/ocsf.py and phases/ocsf_normalization.py`
- **Current implementation:** `core/ocsf_export.py plus compatibility fields`
- **Old behavior:** Generic event normalization and earlier field names.
- **Current behavior:** Class-aware export with stable fingerprints excluding volatile fields; old fields retained.
- **Regression/improvement:** Same logical event receives the same fingerprint across order/time changes.
- **Safety:** Export cannot change finding confirmation.
- **Evidence quality:** Original evidence reference and observable/finding IDs are preserved.
- **Compatibility:** Legacy _fingerprint/vulnerabilities/unmapped compatibility retained.
- **Implementation:** `core/ocsf_export.py`, `core/ocsf.py`, `phases/ocsf_normalization.py`
- **Tests:** `integration_test_v3971.py`, `integration_test_v3961.py`
- **Residual risk:** OCSF coverage is intentionally subset-based; unknown mappings are explicit.

## HIST-0028 — passive_wireless

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v3.9.6 — `wireless/physical planning and imported evidence`
- **Current implementation:** `core/wireless_inventory.py and phases/passive_wireless_inventory.py`
- **Old behavior:** No dedicated normalized passive wireless observation importer.
- **Current behavior:** SSID/BSSID/channel/frequency/encryption/signal/vendor/time/source/location-label import only.
- **Regression/improvement:** Adds passive inventory without capture, deauthentication, cracking or impersonation.
- **Safety:** Observational/import-only.
- **Evidence quality:** Deterministic observations retain source and risk notes.
- **Compatibility:** Additive opt-in phase.
- **Implementation:** `core/wireless_inventory.py`, `phases/passive_wireless_inventory.py`
- **Tests:** `integration_test_v3971.py`
- **Residual risk:** Vendor resolution is local/best-effort and location labels are user supplied.

## HIST-0029 — adapter_proposals

- **Decision:** `PRESERVE_WITH_TEST`
- **Historical source:** v3.9.6 — `adapter/tool catalog definitions`
- **Current implementation:** `core/adapter_proposals.py and phases/integration_adapter_proposal.py`
- **Old behavior:** Adapters were manually authored or cataloged.
- **Current behavior:** Generator emits unapproved proposal metadata, parser/test/doc skeleton descriptions and risk classification.
- **Regression/improvement:** Generated content cannot auto-install, activate or execute.
- **Safety:** Proposal-only state and human review are mandatory.
- **Evidence quality:** Proposal includes explicit implementation state and review status.
- **Compatibility:** Additive opt-in phase.
- **Implementation:** `core/adapter_proposals.py`, `phases/integration_adapter_proposal.py`
- **Tests:** `integration_test_v3971.py`
- **Residual risk:** Human reviewers remain responsible for validating commands and parsers before implementation.
