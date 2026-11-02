# Python module map

Generated from actual Python ASTs. Descriptions identify declared module purpose; they are not correctness claims. Refer to the patch and root-cause report for reviewed changes.

| File | Purpose | Main definitions |
| --- | --- | --- |
| `core/__init__.py` | TBHM v2 core package. |  |
| `core/adapter_contract.py` | Common adapter contract for new TBHM integrations (v3.9.5). | AdapterSpec, AdapterResult, binary_provenance, validate_spec, write_result |
| `core/adapter_proposals.py` | Proposal-only integration adapter generator. | generate |
| `core/ai_plane/__init__.py` | TBHM AI Control Plane. | Plane, _NullClient, build_plane |
| `core/ai_plane/advisor.py` | The advisor: analysis and proposals only. Never executes, never mutates. | Advisor, _as_str, _as_list_of, next_steps_response_schema, validate_next_steps, validate, _json |
| `core/ai_plane/bootstrap.py` | First-run bootstrap for the AI plane. | run_init |
| `core/ai_plane/cli.py` | Dispatch for the --ai-* command family. | requested, handle, _doctor, _sync, _review_delta, _propose_delta, _baseline, _migrate, _regression, _backup, _restore, _ingest, _ingest_folder, _list_proposals, _extract_text |
| `core/ai_plane/embeddings.py` | Portable embeddings and an incrementally maintained vector cache. | EmbeddingDeferred, Embedder, VectorIndex, _hash_embed |
| `core/ai_plane/findings.py` | Single source of truth for a finding's confirmation status. | confirmation_status, is_confirmed, is_confirmed_or_supported, counts |
| `core/ai_plane/home.py` | Portable AI-plane home directory. | AIHome, resolve_home, get |
| `core/ai_plane/improvement.py` | Comparative, operator-approved retrieval configuration promotion and rollback. | Improvements, configuration |
| `core/ai_plane/indexer.py` | Delta-aware TBHM source indexer. | _sha256, _git_commit, _tbhm_version, iter_source_files, _mk, _split_big, _chunk_python, _chunk_text, chunk_file, compute_delta, _source_type, _safe_snapshot, _unified_diff, reindex |
| `core/ai_plane/learning_cli.py` | Standalone bounded scenario operations; no scan target or model is required. | dashboard, operate, handle |
| `core/ai_plane/learning_jobs.py` | Small durable bounded queue; optional model failures never change a scan. | LearningJobs |
| `core/ai_plane/observer.py` | Run-lifecycle observer. | RunObserver, _psutil_pressure, _render_plan_md, _render_md |
| `core/ai_plane/proposals.py` | Propose-and-approve gate + tamper-evident audit. | Audit, ProposalGate, _hash |
| `core/ai_plane/public_knowledge.py` | Bounded lexical RAG over public reference data, separate from reviewed cases. | Catalog, default_path, safe_url, retrieve_context |
| `core/ai_plane/run_learning.py` | Bounded run-artifact learning for the portable AI control plane. | _local_file, snapshot, changed_files, _chunks, ingest_run_log, ingest_phase_artifacts |
| `core/ai_plane/runtime_control.py` | Bounded model-assisted scheduling in the real phase dispatcher. | RuntimeController, ready_window, response_schema, validate_choice |
| `core/ai_plane/sanitizer.py` | Sanitizer + trust model for everything that reaches the advisor. | scrub, wrap_untrusted, controlled_state |
| `core/ai_plane/scenario_import.py` | Explicit opt-in import from the existing run SQLite, preserving provenance. | ingest_run, capture_findings |
| `core/ai_plane/scenarios.py` | Reviewed project-scoped scenario memory in the existing AI-plane SQLite store. | ScenarioMemory, canonical, digest, identity, text, _items, normalize |
| `core/ai_plane/self_evaluation.py` | Independent label evaluation, split hygiene and grounded advisory predictions. | Evaluator, _tokens, check_leakage |
| `core/ai_plane/store.py` | SQLite store: the single source of truth for the AI plane. | Store |
| `core/android_manifest.py` | NEW bounded parser for explicit Android application boolean declarations. | manifest_inventory, application_booleans |
| `core/anti_block.py` | Anti-block Engine. | _HostState, headers_for, observe, next_delay, state_for |
| `core/api_authorization.py` | Explicit, read-only two-account object authorization replay. | _url, prepare, run |
| `core/api_baseline.py` | core/api_baseline.py   (v2.13) | Signature, Baseline, RateLimiter, make_signature, detect_catch_all, classify |
| `core/api_contracts.py` | Offline OpenAPI inventory/diff. Documentation and traffic are not auth proof. | load_document, inventory, compare, traffic_inventory, review_files |
| `core/approval_gate.py` | Human approval gate for intrusive operator-layer integrations. | load_manifest, _parse_time, _host, _target_allowed, approved, summary |
| `core/artifact_store.py` | Content-addressed artifact store and campaign index for reverse projects. | ArtifactStore, sha256_file |
| `core/assertion_engine.py` | Structured vulnerability assertion evaluation. | AssertionResult, _utcnow, _body, _status, _headers, snapshot_digest, _json_path, _condition, evaluate, confirmation_fields |
| `core/atlassian_patterns.py` | Atlassian recon patterns — shared by atlassian_audit + sensitive_data_scan. | is_atlassian |
| `core/attack_knowledge.py` | core/attack_knowledge.py   (v3.2) | map_attack, capabilities_of, owasp_for |
| `core/binary_diff.py` | Function-level binary patch comparison over normalized IR documents. | _feature, _security_tokens, compare |
| `core/bootstrap.py` | core/bootstrap.py  —  v2.11 | _have, _template_is_valid, _valid_template_count, nuclei_template_count, ensure_nuclei_templates, find_seclists, ensure_seclists, ensure_custom_templates, nuclei_templates_root, bootstrap_all |
| `core/brokered_http.py` | Opt-in read-only HTTP replay through a parent-owned broker and shared ledger. | SharedLedger, Broker, pipe_replay, run |
| `core/campaign_model.py` | Typed red-team campaign and imported-operation evidence records. | utcnow, load, normalize_operation, validate_operation, validate_campaign, _redacted_marker, sanitize_result_record, _parse_time, result_is_complete |
| `core/capability_inputs_v423.py` | Opt-in argparse routing to existing phases; ordinary arguments are unchanged. | CapabilityInput |
| `core/capability_registry.py` | Central, truthful capability registry for TBHM v3.9.7.5. | CapabilityAvailability, load, validate_registry, by_id, _platform_supported, availability, summary |
| `core/cicd_dataflow.py` | Native static CI/CD workflow and build-file dataflow/trust checks. | workflow_files, _context, analyze_text, analyze_tree |
| `core/cloud_iam_graph.py` | Evidence-backed, read-only multi-provider cloud IAM graph analysis. | Graph, _walk, _iter_strings, _find_first, _provider_hints, _provider_hint, _principal_name, _permissions, _azure_role_assignments, _gcp_bindings, analyze |
| `core/code_intel.py` | core/code_intel.py   (v3.1) | configure_scan_policy, _is_test_path, iter_source_files, detect_stack, extract_routes, _scan_signals, build_map, trace_vulns, normalise_path, build_live_match_plan, _route_is_authed, live_bases_from_targets |
| `core/code_patterns.py` | core/code_patterns.py   (v2.17) | _entropy, _is_nonsecret_token, find_secrets, find_structured_data_secrets, find_endpoints, find_sinks, is_minified |
| `core/compliance_catalog.py` | Policy-driven compliance catalog loader for TBHM v3.9.6. | load, finding_tags, map_findings, _class_from_test, test_id_coverage |
| `core/compliance_predicates.py` | Control-level compliance predicate evaluation from evidence. | _confirmation, _legacy_status, evaluate_control, evaluate_catalog |
| `core/config.py` | Profile loader. Profiles live in profiles/*.yaml. | ProfileError, list_profiles, load_profile |
| `core/correlation.py` | Correlation Engine — turns isolated findings into evidence chains. | build, _host_of, _highest_sev, _fid, write |
| `core/crash_triage.py` | Crash evidence normalization, deduplication, reproduction planning and input minimization. | stack_signature, collect_crashes, delta_minimize, reproduce_and_minimize, write_plan |
| `core/cross_language_flow.py` | Cross-language JavaScript -> Java/Kotlin -> JNI -> native correlation. | _iter_source_files, _read, _method_calls, collect_mobile_bridges, _call_arguments, collect_js_calls, collect_native_functions, correlate, save |
| `core/curl_probes.py` | Curl Probe Library - v2.16 fixed/merged | set_rate, _throttle, _run_curl, run_captured_curl, _curl_str, _split_response, _get_status, _status_code, _header_value, _normalized_body, _response_signature, _same_response, _random_control, _root, _with_param, probe_trace, probe_options, probe_webdav, probe_method_override, probe_cors, probe_host_header, probe_admin_bypass, probe_sensitive_files, probe_admin_paths, probe_server_status, probe_open_redirect, probe_reflection, probe_sql_errors, probe_path_traversal, probe_api_roots, probe_range_overflow, run_all, _run_all |
| `core/curl_reproducer.py` | Curl Reproducer Generator. | build, _build_audit_curl, _build_pivot_curl, _build_anon_curl, _build_redirect_curl, _build_cors_curl, _build_header_curl, _build_method_curl, _build_takeover_curl, _build_bucket_verification_curl, _build_js_fetch_curl, _build_basic_curl |
| `core/cwe_cvss.py` | core/cwe_cvss.py   (v2.18) | cwe_for, cvss_for, reference_cves, enrich |
| `core/delivery_privacy_audit.py` | Opt-in audit of a *prior sealed delivery*, including supported containers. | audit, run |
| `core/diff_engine.py` | Diff Engine — Burp/ZAP-style baseline-vs-mutation comparison. | ResponseSample, Baseline, DiffResult, _tokens, _jaccard, collect_baseline, compare, send_one |
| `core/doctor.py` | Honest environment and dependency diagnostics for TBHM v3.9.7.5. | _check, _package_name, _requirements, _writable_directory, _json_valid, _yaml_valid, _service_state, run |
| `core/dynamic_mapper.py` | Map imported runtime addresses/events to normalized reverse-IR functions. | _walk, _value_for_keys, _addresses_from_record, _module_catalog, _select_modules, _candidate_addresses, map_events, load_json_documents |
| `core/engagement_evidence.py` | Authorized exercise evidence normalization and instructor simulation helpers. | sanitize_excerpt, _safe_zip_name, _read_file, iter_evidence_blobs, _line_excerpt, analyze_path, synthetic_scenario |
| `core/entity_graph.py` | Small portable entity/relationship/timeline store for corporate intelligence. | EntityGraph, now, stable_id, _csv, _graphml, _stix |
| `core/evaluation.py` | Explicit labeled-fixture metrics; unknown labels/predictions stay unresolved. | _records, evaluate |
| `core/evidence_graph.py` | Bounded, read-only evidence relationships. Correlation is never proof. | canonical_asset, stable_key, build |
| `core/evidence_manifest.py` | Atomic delivery snapshots, consistent SQLite backups and integrity checks. | _sanitize_text, _sanitize_snapshot, _sha256, redaction_scan, build_manifest, verify_manifest |
| `core/evidence_redaction.py` | Conservative persistence-boundary redaction. | StreamRedactor, _redact_url, register_secrets, safe_argv, redact_text, redact_value, sanitize_finding |
| `core/execution_ledger.py` | Actual phase/tool outcomes, separate from finding counts and test coverage. | ExecutionLedger, tool_identity, tracked_tool, sanitize_output, input_fingerprint |
| `core/execution_registry.py` | Declarative execution-adapter registry for TBHM v3.9.6. | load, validate_adapter, index, plan_record |
| `core/exploitability.py` | Evidence-grounded exploitability and confirmation assessment (v3.9.2). | _text, _extract_existing_poc, _existing_steps, _default_steps, _access_impact, _confirmation, _prerequisites, assess, markdown_block |
| `core/finding_class.py` | Strict lead / supported / confirmed classifier. | _structured_confirmation, proof_authority, classify, apply |
| `core/firmware_safety.py` | Safe filesystem helpers for untrusted extracted firmware trees. | canonical_root, _normalise_parts, safe_resolve, safe_read_text, iter_regular_files, validate_rootfs, strip_shell_comments |
| `core/fp_engine.py` | FP Engine — central False-Positive reduction utilities. | Baseline, soft_404_baseline, is_soft_404_match, boolean_differential, math_time_validate, waf_fingerprint, confidence_score, severity_from_score |
| `core/fp_filters.py` | core/fp_filters.py   (v3.5) | path_context, _entropy, _b62_decode, github_token_valid_checksum, _extract_secret_value, is_dummy_secret, _structured_differential_proof, _has_runtime_proof, _has_vulnerability_proof, _target_path, assess, validate_gitleaks_report, load_ignore_patterns |
| `core/fuzz_harness.py` | Generate reviewable fuzzing harnesses and seed corpora from normalized IR. | _param_type, candidate_functions, _safe_c_name, generate_harness, generate_all |
| `core/git_intake.py` | NEW: HTTPS-only repository intake with ephemeral, non-argv credentials. | repository_name, clone_repository |
| `core/hardware_profile.py` | Local hardware detection and conservative LLM sizing recommendations. | _ram_gb, _nvidia_gpus, detect, write |
| `core/http_policy.py` | Scope/policy/budget boundary for explicitly migrated HTTP adapters. | RequestBlocked, BudgetedSession, _ceiling, _budget |
| `core/httpx_adapter.py` | ProjectDiscovery HTTPX JSON contract; Python httpx is not this adapter. | parse_records |
| `core/idor_engine.py` | IDOR Engine — reusable IDOR discovery + verification. | detect_ids, mutate_id, build_mutated_url, fingerprint_response, classify_idor, looks_like_spa_fallback, random_invalid_path |
| `core/ineligible_findings.py` | core/ineligible_findings.py   (v2.12) | _normalise, _user_extra, is_never_report, classify, should_suppress, mark_suppressed |
| `core/insertion_points.py` | Insertion Point discovery — Burp/ZAP style. | InsertionPoint, _looks_like_id, discover, _looks_like_json, _walk_json, _walk_xml, apply, _set_by_path |
| `core/intel_feeds.py` | Local/optional-online vulnerability intelligence feed helpers. | extract_cves, load_kev, load_epss, load_osv, _float |
| `core/intensity.py` | Intensity overlays applied on top of safety profile. | apply, get |
| `core/interprocedural_taint.py` | Bounded interprocedural taint analysis over TBHM's normalized reverse IR. | Flow, Summary, IRTaintAnalyzer, _name, _var_id, _call_name, address_name, load_kb |
| `core/js_intelligence.py` | Complete JavaScript candidate aggregation and usefulness analysis. | canonical_url, _extract_urls, discover_candidates, entropy, find_raw_secrets, analyze_text |
| `core/knowledge.py` | Knowledge Engine — the platform's long-term memory. | Knowledge, _kb_path, get |
| `core/learning_corpus_audit.py` | Permission/split hygiene checks and opt-in sanitized retrieval cards. | audit, run |
| `core/lifecycle.py` | Internal phase-stop control flow, distinct from a recoverable probe error. | PhaseStopped, check |
| `core/llm_local.py` | Safe local LLM client used for evidence enrichment and triage. | LocalLLMConfig, OllamaClient, LocalLLMRuntime, redact_text, is_loopback_url, runtime_from_args, local_llm_status, setup_local_model |
| `core/llm_review.py` | Grounded refutation advice. Model output cannot suppress or confirm findings. | response_schema, _location, _resolve_source, _python_line_kind, _read_source_bytes, _python_shell_facts, context_for, validate_response, run_refutation |
| `core/llm_security_import.py` | Offline, non-authoritative Garak/Promptfoo/export observation normalizer. | _text, _count, normalize, run |
| `core/mcp_registry.py` | Generate a local, non-executing MCP capability manifest. | build |
| `core/noise_filter.py` | Noise Filter — central blocklist for known false-positive sources. | is_noise, should_drop_finding |
| `core/notifier.py` | Sanitized one-shot completion notifications. | _NoRedirect, _allowed, send_completion |
| `core/nuclei_runtime.py` | Bounded, read-only Nuclei template and result readiness checks. | records, installed_templates, interpret_execution, evidence_fields |
| `core/oast.py` | Opt-in, loopback-only out-of-band callback oracle for controlled labs. | LocalOAST, _iso, _stable, verify_export |
| `core/ocsf.py` | Backward-compatible, class-aware OCSF-oriented normalization facade. | _fingerprint, finding_event, write_jsonl |
| `core/ocsf_export.py` | Class-aware deterministic OCSF-oriented export. | _stable, fingerprint, classify, event |
| `core/offline_isolation.py` | Linux x86-64 deny-network syscall filter, inherited across fork/exec. | install, child_argv |
| `core/operator_view.py` | One operator page derived from stored findings, ledger and actual artifacts. | write |
| `core/origin_firewall_analysis.py` | Offline origin attribution and WAF behavior review. | _ip, review_origin_candidates, review_firewall_pairs |
| `core/osint_collectors.py` | Structured native OSINT collector framework. | ProviderDefinition, provider_status, _default_transport, _rdap_url, collect, normalize_rdap |
| `core/ownership_confirm.py` | Cloud bucket ownership confirmation. | extract_target_keywords, detect_prior_research, _extract_keys_from_listing, _extract_sizes_from_listing, confirm_bucket_ownership, build_bucket_verification_curl |
| `core/package_verifier.py` | Release/package integrity verification for TBHM source trees and ZIP archives. | sha256_file, _manifest_entries, _safe_rel, verify_zip, _verify_worker, _verify_zip, verify_tree |
| `core/pinned_transport.py` | Explicit-origin/IP-pinned Requests transport. No proxy, retry or DNS-at-connect. | DestinationPins, PinnedAdapter, origin, _address, install, serial_dispatch |
| `core/program_policy.py` | Machine-readable bug-bounty / engagement policy evaluation. | load, _parsed, _host, _host_matches, _matches_asset, _rule_label, evaluate_asset, _action_match, evaluate_action, _norm_vuln, _vuln_match, evaluate_vulnerability, summary |
| `core/proof_contracts.py` | Versioned confirmation contracts over authenticated local captures. | ConfirmationReceipt, _canonical, _key, capture_snapshot, _read_capture, _body, _same_request, _path_value, verify_contract, restore_confirmation |
| `core/quality_evaluation.py` | Stage-separated metrics with explicit abstentions; no discovery/field claims. | _wilson, score |
| `core/ratelimit.py` | core/ratelimit.py   (v2.14) | cap |
| `core/redteam_utils.py` | Utilities for TBHM red-team expansion phases. | rt_dir, evidence_dir, write_md, write_csv, read_lines, get_cidrs, get_dc_ips, safe_target_file, parse_nmap_grepable_hosts, parse_nmap_open_ports_gnmap, parse_nmap_normal_services, cmd_available, host_from_url, save_json, add_control_finding |
| `core/reporter.py` | TBHM v4.2.1 multi-audience and final technical report renderer. | Reporter |
| `core/request_guard.py` | Run-scoped guard for native Requests callers, including legacy adapters. | permitted_service, _bounded_send, activate, _blocked, deactivate |
| `core/request_model.py` | Redacted exact-request metadata for authorised replay and workflow tests. | _is_secret_key, _redact_headers, _redact_url, _redact_object, _redact_body, _safe_host, _secret_refs, normalize_request, import_har |
| `core/research_input.py` | Bounded JSON data access for optional research capabilities; never executes it. | _pairs, loads, read_bytes, load |
| `core/reverse_families.py` | Managed inventory workflows for UEFI, drivers, mobile, protocol and hardware evidence. | detect_family, _bounded_tree_inventory, _run_static_tool, analyze_uefi, analyze_driver, analyze_mobile_package, _pcap_header, analyze_protocol_capture, analyze_hardware_evidence |
| `core/reverse_ir.py` | Universal reverse-engineering intermediate representation for TBHM. | FunctionRange, parse_address, address_text, _json_load, _stable_list, _function_common, normalize_ghidra, normalize_r2, normalize_angr, normalize, function_fingerprint, add_fingerprints, function_ranges, find_function, save |
| `core/reverse_phase_utils.py` | Shared helpers for TBHM deep reverse phases. | candidate_ir_paths, load_ir_documents, write_json |
| `core/reverse_utils.py` | Shared helpers for the v3.9.2 reverse-engineering pipeline. | iter_files, _file_cache_key, _hashes_cached, clear_artifact_cache, artifact_id, hashes, entropy_bytes, _sample_entropy_cached, sample_entropy, _magic_type_cached, magic_type, extract_strings, indicators, secret_candidates, raw_short_imports, write_json, bounded_text, safe_stem, container_type, identify, find_offsets, is_elf, elf_header_info, parse_hardening, hardening_gaps |
| `core/runner.py` | Bounded subprocess execution for TBHM. | _TailBuffer, Runner |
| `core/safe_archive.py` | Hardened archive extraction shared across phases. | ExtractReport, safe_extract_zip, _extract_worker, _extract_zip |
| `core/safe_plan_executor.py` | Allowlisted, read-only structured plan executor for TBHM v3.9.7.5. | load_plan, validate_plan, _clean, _existing_file, _validated_arguments, _stable_id, _tool_version, _command, execute |
| `core/safe_writes.py` | Safe Writes Gate. | configure, global_gate, gate, _profile_name, ctx_gate, guarded_request |
| `core/safety.py` | Safety layer: | HardLimits, ScopeChecker, ResourceMonitor, tool_available, tool_version |
| `core/sandbox_manager.py` | TBHM-owned disposable sandbox and VM lifecycle management. | SandboxError, SandboxResult, SandboxManager, parse_command_json |
| `core/sbom.py` | core/sbom.py   (v2.18) | _npm, _requirements, _go_mod, _cargo, _pom, _gemfile, parse_dependencies, query_osv, cyclonedx |
| `core/scanner_normalizer.py` | Shared scanner result normalizer for additive source-security adapters. | severity, _first, _cwe_from, _sarif, _generic_walk, _njsscan, scanner_diagnostics, _checkov, parse_json_value, parse_file, iter_result_files, save_items |
| `core/scope.py` | core/scope.py   (v2.15) | Scope, _compile, _norm |
| `core/scoped_http.py` | Shared scope-safe HTTP helpers for read-only discovery phases. | _GetAdapter, network_discovery_enabled, effective_rps, safe_get |
| `core/scoring.py` | Section 3.1 — Endpoint Scoring Algebra | ScanTracker, score_endpoint, real_priority, mrs_score |
| `core/seclists.py` | SecLists integration helper. | _find_seclists_root, get, get_or_warn, status, list_available |
| `core/secret_validator.py` | core/secret_validator.py   (v3.6) | _get, _validate_github, _validate_slack, _validate_google_api, _validate_aws, _validate_stripe, _validate_sendgrid, validate, annotate_finding |
| `core/secret_vault.py` | Run-scoped sealed handoff for discovered secret candidates. | _run_dir, _key_path, _vault_path, _restrict, _load_or_create_key, _existing_key, _stdlib_seal, _stdlib_unseal, seal, unseal, shred |
| `core/session_importer.py` | Import-only session and beacon evidence normalization. | _records, _normalize, import_evidence |
| `core/session_state.py` | Session state tracking — Burp/ZAP-style. | Session |
| `core/soft404.py` | core/soft404.py   (v2.20) | _sig, _calibrate, _base_of, is_catch_all |
| `core/source_provenance.py` | Bounded local source provenance labels for evidence prioritization. | classify_source |
| `core/sourcemaps.py` | core/sourcemaps.py   (v2.18) | extract_from_map, reconstruct_dir, _write_recovered |
| `core/storage.py` | SQLite-backed storage layer. | _EvidenceCursor, _EvidenceConnection, Storage, _clean_parameter, _clean_parameters, _utcnow |
| `core/strict_api_v425.py` | Owned two-tenant, read-only BOLA proof. No inferred production object IDs. | verify, prepare_case |
| `core/strict_classes_v424.py` | Narrow, read-only proof extensions. Captures, never imported flags, are authority. | ControlHeld, _require, _status, _text, _success, _identity, _object, verify |
| `core/strict_replay.py` | Approved controlled-canary traversal and owned-role read-only function replay. | prepare, run |
| `core/taint_engine.py` | core/taint_engine.py   (v3.6) | TaintFlow, _PyTaintVisitor, _py_dotted, _py_source_of, _names_in, _numeric_expr, _expr_sanitized, analyze_python, js_runtime_context, js_sink_compatible, analyze_js, analyze |
| `core/targets.py` | Unified target accessors and conservative network-scope helpers. | _bare_host, get_domains, get_url_targets, _registrable_domain, get_root_domains, target_scope_allows, primary_label |
| `core/tool_catalog.py` | Versioned external-tool catalog and readiness helpers for TBHM v3.9.7.5. | _python_status, load, by_id, select, executable_status, readiness, _group, is_high_risk |
| `core/verifier.py` | Verification helpers. | shadow_replay, manual_repro_score |
| `core/version.py` | Central TBHM release identity. | source_fingerprint |
| `core/wireless_inventory.py` | Passive wireless observation import and risk annotation. | _rows, _risk, import_observations |
| `phases/__init__.py` | TBHM v2 phases package. Each module exports run(ctx). |  |
| `phases/access_control.py` | Phase: access_control - IDOR heuristics, CORS misconfigurations. | run, _idor_heuristic, _cors |
| `phases/ad_access_assessment.py` | Safe Active Directory access and exposure assessment (v3.9). | _base_dn, _entry_dict, _save_lead, _ldap_review, _is_bloodhound, _import_bloodhound, _import_text_content, _import_text, _import_zip, run |
| `phases/ad_identity_safe.py` | Active Directory / identity read-only checks. | run |
| `phases/add_net_ad.py` | TBHM v3 phase: deeper network + AD read-only review add-on. | run |
| `phases/add_service_primitive.py` | TBHM v3 phase: Windows service execution-primitive review add-on. | run |
| `phases/add_sqli.py` | TBHM v3 phase: focused SQL injection verification add-on. | _candidate_urls, run |
| `phases/addons_common.py` | Shared helpers for TBHM v3 add-on phases. | evidence_dir, save_json, write_md, make_logger, domain_to_base_dn, severity, confidence, now_iso |
| `phases/agentic_control_manifest.py` | Generate non-executing MCP/agentic and capability manifests. | run |
| `phases/ai_llm_tooling.py` | Opt-in AI/LLM assessment adapter and result normalizer (v3.7). | _iter, run |
| `phases/ai_redteam_safe.py` | AI/LLM/RAG/agentic application safe coverage. | run |
| `phases/ai_supervision.py` | AI supervision of phase/tool coverage and run learning (v3.9.5). | run |
| `phases/api_fuzz.py` | Phase: api_fuzz   (v2.13) | _request, _calibrate, run, _curl, _load_wordlist |
| `phases/api_key_pivot.py` | Phase: api_key_pivot | run, _pivot, _pivot_google, _pivot_stripe, _pivot_github, _pivot_slack, _pivot_twilio, _pivot_sendgrid, _pivot_firebase, _collect_secrets |
| `phases/api_specific.py` | Phase: api_specific - GraphQL, webhooks (G2), mobile-API hints (G3), LLM probing (G1). | run, _websockets, _sse, _graphql, _graphql_deep, _webhooks, _mobile_api_hints, _llm_probe |
| `phases/atlassian_audit.py` | Phase: atlassian_audit | run, _collect_atlassian_hosts, _probe_endpoints, _get_invalid_baseline, _idor_sweep, _jql_injection_test, _servicedesk_request_enum, _scan_sensitive, _count_entities, _mrs_for |
| `phases/attack_path.py` | Phase: attack_path   (v3.2)   [--chain-simulate] | run |
| `phases/audit.py` | Phase: audit (Burp/ZAP-style active scanner) | run, _has_id_like_path, _audit_url, _send_and_diff, _verify, check_sqli, check_xss, check_ssti, check_path_traversal, check_cmd_injection, check_ssrf_oob, _start_oast, _poll_oast |
| `phases/auth_advanced.py` | Phase: auth_advanced - 2FA paths, JWT audit, OAuth callback flags. | run, _b64d, _audit_jwt, _jwt_audit, _tfa_surfaces, _oauth_flags |
| `phases/auth_modern_review.py` | Phase: auth_modern_review   (v3.3) | _b64url, _decode_jwt, _collect_jwts, run |
| `phases/authenticated_session_model.py` | Offline multi-role HAR/session authorization matrix (v3.9.5). | norm_path, _role_rules, run |
| `phases/backend_map.py` | Phase: backend_map | run, _extract_js_refs, _fetch_js, _extract_api_calls |
| `phases/backup_restore_simulation.py` | Phase: backup_restore_simulation   (v3.3) | run |
| `phases/browser_extension_audit.py` | Phase: browser_extension_audit   (v3.3)   [--browser-extension-audit FILE] | _load_list, run, _ids |
| `phases/bug_bounty_workspace.py` | Bug-bounty identity, request, workflow and policy workspace. | _load, _hash, _assertion, run |
| `phases/business_logic.py` | Phase: business_logic | run, _check_param_pollution, _check_price_manipulation, _check_mass_assignment, _flag_race_endpoints, _flag_idor_endpoints |
| `phases/cache_deception.py` | Phase: cache_deception | run, _probe_url, _body_similarity |
| `phases/ci_cd_supply_chain_security.py` | CI/CD trust-boundary, dataflow, adapter, and attestation review. | _files, run |
| `phases/client_platform.py` | Phase: client_platform   (v2.19) | run |
| `phases/cloud_identity_path_analysis.py` | Read-only AWS/Azure/GCP IAM graph and privilege-path analysis. | _walk, run |
| `phases/cloud_inventory_safe.py` | Phase: cloud_inventory_safe   (v3.3)   [--cloud-profiles aws,gcp,azure] | run, _count |
| `phases/cloud_posture_tooling.py` | Multi-cloud/Kubernetes posture adapter phase (v3.9.5). | _run, run |
| `phases/cloud_recon.py` | Phase: cloud_recon | _bucket_candidates, run, _discover_from_files, _probe_s3, _probe_gcs, _probe_azure, _probe_firebase |
| `phases/cloud_recon_extended.py` | Phase: cloud_recon_extended | _do_spaces_urls, _r2_urls, _b2_urls, _gae_urls, _azure_func_urls, _heroku_urls, _oracle_oci_urls, _wasabi_urls, _ibm_cos_urls, _linode_urls, _vultr_urls, _alibaba_oss_urls, _scaleway_urls, _firebase_storage_urls, run, _generate_candidates, _probe_resource, _verify_ownership |
| `phases/cname_takeover.py` | Phase: cname_takeover   (v2.19) | _cnames_via_dnsx, _cname_python, run |
| `phases/code_intel.py` | Phase: code_intel   (v3.1) | _gather_repos, _clone, _selected_branches, _probe_live, _emit_secrets, _append_suppressed, _emit_routes, _emit_auth, _emit_access_control, _dev_dependency_names, _emit_dependencies, _emit_handler_branch, _emit_business_logic, _emit_injection, _emit_ci_cd, run, _read_file_list, _write_remediation_plan, _write_report_html, _esc |
| `phases/code_scan.py` | Phase: code_scan   (v2.17) | _extension_set, _secret_token, _redact_secret_match, _save_secret, _save_sink, _gather_repos, _clone, run, _run_optional_tools |
| `phases/code_security_tooling.py` | Unified safe code-security orchestration (v3.9 additive update). | sev, emit, walk, import_file, _write_stdout, _run_simple, _tool_available, run, _record_diagnostics |
| `phases/compliance_coverage.py` | Phase: compliance_coverage   (v3.2) | run |
| `phases/compliance_reporting_extended.py` | Evidence-predicate compliance reporting with v3.9.6 output aliases. | run |
| `phases/console_leaks.py` | Phase: console_leaks | run |
| `phases/content_discovery.py` | Phase: content_discovery | run, _parse_ffuf_results |
| `phases/controlled_validation_plane.py` | Approval-gated operator validation register and evidence importer (v3.9.5). | _load, _hash_file, run |
| `phases/corporate_osint.py` | Corporate/company intelligence phase, deliberately separate from recon/enum. | _lines, _flatten_values, _seed_values, _hash, _scope, _seed_domains, _ingest_text, _run_tools, run |
| `phases/coverage_map.py` | Phase: coverage_map — ingest the FULL field-playbook objective taxonomy so the | _touched_phases, run |
| `phases/curl_verify.py` | Phase: curl_verify | run, _remediation_for, _cwe_for, _mrs_for |
| `phases/custom_nuclei.py` | Phase: custom_nuclei   (v2.11) | run, _to_finding |
| `phases/dashboard.py` | Phase: dashboard | run, _safe_finding |
| `phases/data_analysis_intelligence.py` | Dedicated entity, relationship, timeline and data-quality analysis phase. | _hash_bytes, _hash_file, _iter_records, _record_text, _ingest_record, _duckdb_export, run |
| `phases/deep_crawl.py` | Phase: deep_crawl (v3.9.3-new) | _in_scope, _interesting, run |
| `phases/deep_scan.py` | Phase: deep_scan | run, _nikto, _jaeles, _wapiti, _wapiti_sev |
| `phases/diagnostics.py` | Phase: diagnostics | run, _get_version |
| `phases/discovery.py` | Phase: discovery | _archive_domains, run, _analyze_js |
| `phases/egress_canary.py` | Phase: egress_canary   (v3.2)   [--test-egress-canary] | _tcp_probe, _dns_probe, _http_probe, _icmp_probe, run |
| `phases/engagement_evidence_review.py` | Authorized exercise evidence review and instructor simulation phase. | _save_observation, run |
| `phases/engagement_objectives.py` | First-class engagement lifecycle, objective and kill-chain state model. | _load, run |
| `phases/evidence_finalize.py` | Phase: evidence_finalize   (v3.2) | _junit, run, _incomplete_gate |
| `phases/execution_orchestration_plan.py` | Single-pane execution planning and result correlation (v3.9.6). | _load_obj, _hash, _default_actions, run |
| `phases/exploitability_assessment.py` | Global evidence-grounded exploitability assessment for every finding (v3.9.2). | run |
| `phases/external_perimeter_tooling.py` | External perimeter assessment adapters (v3.8, additive and safe). | emit, walk_json, import_file, run |
| `phases/firmware_reverse_safe.py` | Firmware and embedded static-analysis phase for TBHM v3.9.7.5. | _rootfs_candidates, _locate_rootfs, _reset_directory, _attempt_record, _validate_candidate, _carve_and_unsquash, _extract, _elf_inventory, _dominant_arch, _audit_hardening, _audit_accounts, _audit_keys, _audit_services, _audit_permissions, _audit_web, _parse_control_blocks, _parse_apk_installed, _component_inventory, _audit_update_chain, _binary_priorities, _attack_surface_map, _artifact_graph, _rootfs_audit, run |
| `phases/firmware_tooling_extended.py` | Extended firmware-tool adapters for TBHM v3.9.7.5. | _iter_evidence, _read_text, _find_emba, _emba_mode, _emba_profile_name, _emba_profile, _run_emba, _summarize_emba, _routersploit_root, _literal_info, _catalog_routersploit, _import_routersploit_results, _import_generic, run |
| `phases/fp_review.py` | Phase: fp_review | run, _write_md |
| `phases/graphql_audit.py` | Phase: graphql_audit   (v3.3) | _candidates, _schema_depth, run |
| `phases/honeypot_detection.py` | Phase: honeypot_detection   (v3.2) | _scan_text_blobs, run |
| `phases/iac_drift.py` | Phase: iac_drift   (v3.2)   [--terraform-state PATH --live-inventory PATH] | _load_json, _tfstate_resources, _live_resources, run |
| `phases/identity_security_tooling.py` | AD/Entra/ADCS posture and attack-path evidence integration (v3.9.5). | _import_text, _live_readonly, run |
| `phases/infra_exposure.py` | Phase: infra_exposure | run, _scan_host, _scan_sentry_dsn, _impact_for, _remediation_for, _cwe_for, _mrs_for |
| `phases/injections.py` | Phase: injections - XSS, SQLi, LFI, redirect, SSRF probes. | run, _xss, _redirect_host, _redirect_verification, _open_redirect, _lfi, _ssrf, _sqli |
| `phases/integration_adapter_proposal.py` | Generate a disabled, proposal-only integration adapter design. | run |
| `phases/interface_probe.py` | Phase: interface_probe — additive read-only discovery of protocol/identity | _rl_wait, _get, _finding, _grpc, _socketio, _asyncapi, _jsonapi_hostmeta, _saml, _scim, _mcp, run |
| `phases/internal_ad_tooling.py` | Internal network and advanced AD evidence normalization (v3.8-safe). | emit, parse_text, run |
| `phases/internal_network_safe.py` | Internal network safe discovery and segmentation review. | _run_nmap_ping, _run_service_scan, run |
| `phases/iot_cctv_safe.py` | IoT, CCTV, sensors, printers, VoIP, BMS/OT-like safe inventory. | run |
| `phases/js_analysis.py` | Complete JavaScript intelligence over every discovered in-scope candidate. | _name_score, _safe_name, _merge_lines, _fetch, _decode_inline_source_map, _emit_findings, run |
| `phases/k8s_recon_safe.py` | Phase: k8s_recon_safe   (v3.3) | _targets, run |
| `phases/lateral_movement_paths.py` | Phase: lateral_movement_paths   (v3.9-safe) | _safe_json_bytes, _iter_bloodhound_docs, _bloodhound_graph, _normalized_graph, _load_graph, _shortest_paths, run |
| `phases/llm_agent_tool_call_abuse.py` | Phase: llm_agent_tool_call_abuse   (v3.3) | _catalog_md, run |
| `phases/llm_run_analysis.py` | Phase: llm_run_analysis (v3.9.3-new) | _build_summary, run |
| `phases/local_llm_triage.py` | Local-only LLM enrichment for normalized TBHM findings. | _compact, _batches, enrichment_response_schema, _defensive_text, run |
| `phases/mfa_bypass_safe.py` | Phase: mfa_bypass_safe   (v3.3)   [also serves conditional_access_review] | run |
| `phases/mobile_reverse_extended.py` | Extended mobile/desktop reverse adapters: JADX, YARA, Quark, .NET imports. | run |
| `phases/mobile_scan.py` | Phase: mobile_scan   (v2.17) | _strings, _emit, run, _scan_text_blob, _scan_apk, _analyze_manifest, _scan_ipa, _scan_source, _record_manifest |
| `phases/mobile_tooling.py` | Mobile security tooling adapter (v3.7). Native mobile_scan remains authoritative. | run |
| `phases/modern_protocols_discovery.py` | Phase: modern_protocols_discovery   (v3.3) | _ssdp_discover, _mdns_discover, run |
| `phases/network_firewall_tooling.py` | Read-only network/firewall evidence adapters and static configuration checks (v3.7). | finding, audit_cfg, import_results, run |
| `phases/nuclei_extended.py` | Phase: nuclei_extended | run, _collect_targets, _resolve_sweep_args, _looks_like_no_templates, _short, _to_finding, _adj_mrs, _build_curl_from_nuclei |
| `phases/ocsf_normalization.py` | Emit class-aware, deterministic OCSF-oriented evidence streams. | _load_optional, run |
| `phases/opsec_preflight.py` | Corporate OSINT/red-team OPSEC preflight (v3.9.5). | _load, run |
| `phases/osint_api_collectors.py` | Native authorized OSINT API collectors. | _queries, run |
| `phases/osint_depth_collectors.py` | Depth-oriented corporate OSINT collectors and import normalizer (v3.9.6). | _murmur3_32, _favicon_hash, _read_lines, _import_values, run |
| `phases/ot_ics_safe.py` | Phase: ot_ics_safe   (v3.3) | _connect, run |
| `phases/package_verification.py` | Verify TBHM packages or source trees without executing their code. | run |
| `phases/passive_wireless_inventory.py` | Passive/import-only wireless observation inventory. | run |
| `phases/pdf_injection.py` | Phase: pdf_injection | run |
| `phases/playbook_integration.py` | Phase: playbook_integration   (v3.3)   [--playbook-mode] | run |
| `phases/ports.py` | Phase: ports | run, _hosts_from_urls, _naabu, _nmap_discover, _nmap_service_detect, _parse_gnmap, _impact_for_port, _authorized_addresses |
| `phases/privesc_audit_tooling.py` | Privilege-escalation audit evidence normalization (v3.8). | emit, scan_text, scan_json, run |
| `phases/protected_routes.py` | Review anonymous route responses without treating public 200s as auth bypass. | route_class, response_assessment, run |
| `phases/purple_team_validation.py` | Purple-team detection-validation plan/result normalizer (v3.9.5). | _load, run |
| `phases/recon.py` | Phase: recon (v2.1 multi-target rewrite) | _network_rate, _dns_authorized, run, _report_recon_capabilities, _dns_basics, _crtsh, _subfinder, _assetfinder, _chaos, _github_subdomains, _amass_passive, _dns_bruteforce, _dns_permutations, _alive_check, _python_alive_fallback |
| `phases/redteam_campaign_control.py` | Typed, approval-gated red-team campaign control and result import. | _hash, _result_files, _artifact_refs, run |
| `phases/redteam_final_summary.py` | Final red-team lifecycle summary. | run |
| `phases/redteam_governance.py` | Red-team governance, coverage matrix, approvals, and residual-risk register. | _is_redteam, run |
| `phases/report.py` | Phase: report - generates layered reports and per-finding reproducer kits. | _ensure_local_llm_enrichment, _ensure_exploitability_assessment, run |
| `phases/reverse_campaign_index.py` | Campaign-scale content-addressed artifact deduplication and reuse index. | run |
| `phases/reverse_correlation.py` | Phase 5: correlate reverse-engineering evidence and prepare report narrative (v3.9.2). | run |
| `phases/reverse_crash_triage.py` | Crash deduplication, reproduction planning and explicit isolated minimization. | run |
| `phases/reverse_cross_language.py` | JavaScript-to-Java/Kotlin-to-JNI-to-native static correlation. | run |
| `phases/reverse_diff_analysis.py` | Function-level old/new binary comparison over normalized IR. | _load, run |
| `phases/reverse_dynamic_evidence.py` | Phase 3: normalize dynamic-analysis evidence from approved sandboxes (v3.9.2). | _text_files, _flatten_json, _load_text, _load_verification_manifest, _emit, run |
| `phases/reverse_dynamic_mapping.py` | Map imported runtime addresses and events back to decompiled functions. | run |
| `phases/reverse_engineering_tooling.py` | Reverse-engineering compatibility phase (v3.9.3-restore). | emit, import_json, static_strings, _capa_items, _static_binary_review, run |
| `phases/reverse_family_analysis.py` | Managed UEFI, driver, protocol, mobile and hardware-evidence workflows. | run |
| `phases/reverse_fuzzing.py` | Automatic bounded fuzz-harness proposal generation from reverse IR. | run |
| `phases/reverse_ir_analysis.py` | Validate and summarize normalized reverse-engineering IR evidence. | run |
| `phases/reverse_sandbox_analysis.py` | Explicit disposable container/QEMU execution owned by TBHM. | run |
| `phases/reverse_static_analysis.py` | Headless static analysis plus normalization into the TBHM universal reverse IR. | _emit_import, _run_r2, _find_ghidra_headless, run |
| `phases/reverse_symbolic_analysis.py` | Bounded CFG, symbolic input synthesis and seed-guided concolic replay. | run |
| `phases/reverse_taint_analysis.py` | Bounded interprocedural source-to-sink analysis over universal reverse IR. | run |
| `phases/reverse_triage.py` | Phase 1: rapid static fingerprinting and reverse-engineering triage (v3.9.2). | _emit, run |
| `phases/safe_plan_execution.py` | Execute only allowlisted, structured, read-only plans. | run |
| `phases/sast_tooling.py` | Opt-in SAST/SCA orchestration and normalized import (v3.7). | _sev, _emit, _import, run |
| `phases/secrets_misc.py` | Phase: secrets_misc - .git/.env, host header injection, security headers, dangerous HTTP methods. | run, _exposed_files, _security_headers, _dangerous_methods, _host_header |
| `phases/session_beacon_import.py` | Import-only authorized session and beacon evidence. | run |
| `phases/smart_crawl.py` | Phase: smart_crawl (ZAP-style stateful crawler) | ApplicationGraph, run, _extract_urls, _extract_forms, _in_scope, _load_sync_playwright, _launch_chromium, _headless_pass |
| `phases/smuggling.py` | Phase: smuggling   (v2.18) | _send_raw, _probe, run |
| `phases/social_engineering_governance.py` | Governed social-engineering, physical and wireless exercise register. | _load, _hash, run |
| `phases/source_orchestration_tooling.py` | Additive source-security orchestrator adapters. | _run_s0, run |
| `phases/spec_scan.py` | Phase: spec_scan   (v2.19) | _FallbackRL, _get, _bases, _parse_spec, _extract_paths, run, _interface_signature |
| `phases/standards_knowledge_sync.py` | Versioned standards/feed readiness phase (offline-first, explicit updates). | run |
| `phases/strict_finding_validation.py` | Apply structured assertions to candidate findings. | run |
| `phases/supply_chain_review.py` | Phase: supply_chain_review   (v3.2) | _edit_distance, _gather_roots, _parse_manifests, run, _local_dependency, _has_workspaces |
| `phases/surface_correlation.py` | Phase: surface_correlation (v3.9.3-new) | _read, _in_scope, run |
| `phases/test_coverage_ledger.py` | Coverage derived from test executions, including negative and blocked tests. | run |
| `phases/toolchain_readiness.py` | Corporate tool-catalog readiness and integration-mode audit (v3.9.5). | run |
| `phases/upload_race.py` | Phase: upload_race - file upload, race conditions, prototype-pollution hints. | run, _upload_probe, _proto_pollution_hints |
| `phases/verify.py` | Finding verification coordinator. | run |
| `phases/visual.py` | Phase: visual | run |
| `phases/vuln_scan.py` | Phase: vuln_scan -- nuclei + subdomain takeover. | run, _nuclei, _takeover, _cwe |
| `phases/vuln_scan_extended.py` | Phase: vuln_scan_extended | run, _run_retire_js, _run_dalfox, _run_nuclei_tech_stack, _run_nuclei_atlassian, _run_wpscan_if_wp, _ingest_nuclei_jsonl |
| `phases/vulnerability_intelligence_enrichment.py` | EPSS/KEV/OSV/CVSS4-aware finding enrichment (v3.9.5). | _pick, _filter, _has_public_exploit, run |
| `phases/waf_evasion_ssrf.py` | Phase: waf_evasion_ssrf | run, _collect_candidates, _probe_param |
| `phases/web3.py` | Web3 observations and offline Slither import; no contract execution. | indicators, _import_slither, run, _scan_js_for_web3, _observe, _probe_rpc, _ipfs_api |
| `phases/web_scanner_tooling.py` | Web scanner orchestration/import adapter with URL/JavaScript feedback. | emit, _urls, import_file_count, import_file, _merge, run |
| `phases/wireless_physical_soc.py` | Wireless/RF, physical/social, and SOC detection planning layer. | _maybe_wireless, run |
| `scripts/broker_pipe_worker.py` | Socket-isolated ID-only pipe adapter; it has no HTTP transport or tool API. | main |
| `scripts/build_compatibility_baseline.py` | Build a local compatibility baseline from previously extracted TBHM trees. | python_tree, cli_flags, phase_order, public_symbols, load_structured, collect_identifiers, structured_identifiers, line_item_sets, meaningful_paths, roots_from, main |
| `scripts/build_evidence_v425.py` | Regenerate release evidence metadata from measured local records. | read, write, sha, table, stats, main |
| `scripts/build_release_manifest.py` | Build or verify the manifest for the central current release identity. | build, main |
| `scripts/build_v3971_compatibility_report.py` | Build v3.9.6 baseline and v3.9.7.2 compatibility manifests. | sha, files, text, phase_order, public_symbols, cli_inventory, nested_keys, structured_keys, profile_phases, manifest, flatten_config, compare, md, main |
| `scripts/build_v3972_release_manifest.py` | Build the clean, self-verifying TBHM v3.9.7.2 release manifest. | sha256, packaged_files, cli_flags, phase_order, unittest_cases, main |
| `scripts/build_v3974_release_manifest.py` | Build the deterministic TBHM v3.9.7.4 release manifest. | sha256, files, cli_flags_from_file, phase_names, build, main |
| `scripts/build_v3975_release_manifest.py` | Build the complete TBHM v3.9.7.5 release manifest. | sha256, release_files, cli_flags, phase_names, generated_at, build, main |
| `scripts/build_v4_release_manifest.py` | Regenerate RELEASE_MANIFEST-v4.2.0.json for the TBHM v4 tree. | sha256_file, build, main |
| `scripts/check_done.py` | Evidence-grounded high-level scanner completion gate; never release QA. | _load, main |
| `scripts/check_release_v425.py` | Measured acceptance for this incremental release, never all-milestone closure. | read, main |
| `scripts/compare_proof_controls_v422.py` | Compare old/new proof control decisions on constructed signed evidence. | main |
| `scripts/compare_release_contracts.py` | Compare source inventory, argparse signatures, phase order and SQLite DDL. | probe, inventory, additive_columns, main |
| `scripts/data/duckdb_export.py` | Isolated DuckDB exporter used by the data-analysis phase. | main |
| `scripts/evaluate_additions_v423.py` | Reproduce local transport counters and known-canary gate outcomes. | fixtures, main |
| `scripts/evaluate_api_authz_v422.py` | Run the packaged paired-account loopback HTTP corpus, not public targets. | main |
| `scripts/evaluate_learning_v425.py` | Reproducible synthetic retrieval comparison and complete governance exercise. | SyntheticSurrogate, execute |
| `scripts/evaluate_proof_fixtures_v421.py` | Measured synthetic proof-contract regression, NOT vulnerability detection recall. | make_case, execute, main |
| `scripts/evaluate_proof_v425.py` | Paired class/behavior evaluation on authenticated owned-loopback captures. | probe, execute |
| `scripts/evaluate_release_v424.py` | Paired local confirmation evaluation against 4.2.3; never field discovery metrics. | execute |
| `scripts/evaluate_taint_fixtures.py` | Reproduce a small regression corpus; this is not a real-world accuracy study. | main |
| `scripts/ida/export_tbhm.py` | Module without a module docstring; inspect definitions. |  |
| `scripts/install_extended_tools.py` | Safely install optional TBHM integrations without contaminating system Python. | _allowed_argv, _version_tuple, _in_range, _find_compatible_python, _tail, _run, _package_tokens, _safe_id, _venv_paths, _install_isolated_python, _normalized_npm, _normalized_cargo, _normalized_gem, _user_tool_bin, _expose_executable, _apt_packages, _install_apt, _already_installed, install_item, build_summary, _progress_run, _write_state, main |
| `scripts/installer_doctor.py` | Offline installer/environment diagnostics for TBHM v3.9.7.5. | _run, _classify_path, collect, main |
| `scripts/inventory_source_v425.py` | Whole-tree structural inventory; deliberately not a universal semantic audit. | inventory |
| `scripts/knowledge_catalog.py` | Import operator-downloaded public CVE/CWE/methodology data; never execute it. | stamp, bounded, paths, descriptions, parse_cve, report_base, run_import, main |
| `scripts/legacy_learning_candidates.py` | Export selected legacy AI observations as pending, permission-bound plans. | connect, export, main |
| `scripts/package_release.py` | Build a reproducible ZIP from a verified current-release manifest. | files, main |
| `scripts/proof_vectors_v424.py` | Run identical legacy proof vectors against a selected source tree. | execute |
| `scripts/repair_legacy_python_environment.py` | Plan or perform a conservative cleanup of legacy TBHM shared-user tools. | _distribution_location, _run, plan, main |
| `scripts/reproduce_security_corrections_v424.py` | Module without a module docstring; inspect definitions. | H, Defects |
| `scripts/reproduce_security_v425.py` | Harmless probes: imported retrieval trust, proposal traversal, missing manifests. | execute |
| `scripts/reverse/angr_triage.py` | Bounded angr CFG, symbolic reachability and seed-guided concolic replay. | _import_angr, _addr, _trace, _result_bytes, _cfg_payload, _symbolic_state, _symbolic, main |
| `scripts/run_tests.py` | Run every packaged regression script in an isolated copy; never install dependencies. | main |
| `scripts/stage_legacy_backup.py` | Inspect/stage a legacy TBHM tar without executing or merging its contents. | digest, db_summary, inspect, main |
| `scripts/tbhm_ai_acceptance.py` | Local TBHM AI experiment. No source patches, imports, approvals or training. | CapturePlan, emit, sha, save, regular, fixture_source, native_control, activate, read_only_store, planner_prompt, worker, plan_shape, metrics, active_scans, experiment, self_test, main |
| `scripts/tbhm_collect_review_bundle.py` | Create a private, bounded, redacted review copy of one TBHM run. | CollectionError, Redactor, sha, utc, checked_path, directory_fd, signature, read_regular, external_bytes, candidates, private_write, json_bytes, make_private_parent, build_snapshot, collect, verify_directory, positive, main |
| `scripts/tbhm_connection_doctor.py` | Read-only loopback inference diagnostics; never installs or controls processes. | diagnose, main |
| `scripts/tbhm_origin_firewall_review.py` | Offline analysis of operator-provided origin candidates and WAF response pairs. | main |
| `scripts/tbhm_release_acceptance.py` | Run every unit-test module in isolation and require a completion receipt. | worker, main |
| `scripts/tbhm_strict_reindex.py` | Build a resumable, strictly Ollama-backed TBHM vector cache. | ContextLimitError, emit, sha, regular, private_dir, atomic_bytes, read_chunks, snapshot, file_state, ensure_idle, model_digest, _embedding_request, embedding, validate_pooling, run, rebuild, main |
| `scripts/update_intel_feeds.py` | Explicit updater for public vulnerability-intelligence caches. | _download, main |
| `scripts/validate_v4_release.py` | Validate the TBHM v4 tree before packaging or shipping. | check_compile, check_imports, check_manifest, check_phase_coverage, main |
