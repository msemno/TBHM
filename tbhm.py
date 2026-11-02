#!/usr/bin/env python3
"""
TBHM v4.2.7 - The Bug Hunter Master
Python orchestrator with profile-based config, hunter memory, scoring algebra,
and 4-audience reporting. Built on the v1.0 architectural design document.

Usage:
    ./tbhm.py -d example.com --profile authorized_safe
    ./tbhm.py -l scope.txt --profile authorized_safe --web3
    ./tbhm.py --help
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

# Python 3.12+ deprecated datetime.utcnow() but it still works fine and avoids
# tz-confusion bugs across the codebase. Silence the noise.
warnings.filterwarnings("ignore", category=DeprecationWarning, module=".*")

# Ensure Go-installed and pipx-installed binaries are reachable from subprocess
# calls, even when this script is launched from a fresh shell where ~/.bashrc
# hasn't been sourced (common when running as root).
_extra_paths = [
    f"{os.path.expanduser('~')}/go/bin",
    "/usr/local/go/bin",
    "/root/go/bin",
    f"{os.path.expanduser('~')}/.local/bin",
    "/root/.local/bin",
]
_current = os.environ.get("PATH", "")
_existing = set(_current.split(os.pathsep))
_to_add = [p for p in _extra_paths if p and p not in _existing and os.path.isdir(p)]
if _to_add and os.environ.get("TBHM_RESPECT_PATH") != "1":
    os.environ["PATH"] = os.pathsep.join(_to_add) + os.pathsep + _current

# Make local packages importable
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from core.version import VERSION, DISPLAY_VERSION  # noqa: E402


from core.config import load_profile, list_profiles, ProfileError  # noqa: E402
from core.storage import Storage  # noqa: E402
from core.safety import HardLimits, ResourceMonitor  # noqa: E402
from core.runner import Runner  # noqa: E402
from core.reporter import Reporter  # noqa: E402

BANNER = r"""
 ████████╗██████╗ ██╗  ██╗███╗   ███╗
 ╚══██╔══╝██╔══██╗██║  ██║████╗ ████║
    ██║   ██████╔╝███████║██╔████╔██║   {release}
    ██║   ██╔══██╗██╔══██║██║╚██╔╝██║
    ██║   ██████╔╝██║  ██║██║ ╚═╝ ██║   The Bug Hunter Master
    ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝   Python Orchestrator
""".replace('{release}', VERSION)


# ──────────────────────────────────────────────────────────────────────────────
# Phase registry — maps phase name to (module, function). Phases are in
# phases/*.py and each exports a `run(ctx)` function.
# ──────────────────────────────────────────────────────────────────────────────
PHASE_ORDER = [
    "preflight",         # legal check, scope validation
    "diagnostics",       # NEW v2.10: tool inventory + nuclei template count + provider config
    "package_verification", # v3.9.7.5: ZIP/tree integrity, manifest and compile verification
    "toolchain_readiness", # v3.9.5: versioned catalog/readiness, registered != operational
    "agentic_control_manifest", # v3.9.6: local non-executing MCP/agentic capability and trust manifest
    "integration_adapter_proposal", # v3.9.7.5: disabled proposal-only adapter design; never installs/executes
    "opsec_preflight",     # v3.9.5: corporate OPSEC/ROE readiness gate; no fingerprint bypass automation
    "engagement_objectives", # v3.9.5: objective/kill-chain state and tested/not-tested register
    "standards_knowledge_sync", # v3.9.5: versioned standards/feed inventory and offline sync status
    "redteam_governance",# v2.22: enterprise red-team coverage matrix + high-risk approval register
    "recon",             # subdomains, alive hosts, tech fingerprint (multi-target)
    "external_perimeter_tooling", # v3.8: perimeter recon/scanner evidence normalization; no phishing/C2/exploit execution
    "corporate_osint",    # v3.9.5: separate company/ownership/identity/document intelligence graph
    "osint_depth_collectors", # v3.9.6: favicon/ASN/BGP/AXFR/dork/import depth collectors with PII/approval gates
    "osint_api_collectors", # v3.9.7.5: bounded native API collectors; RDAP implemented, truthful provider status
    "cname_takeover",    # NEW v2.19: CNAME inventory + dangling-takeover heuristic
    "ports",             # naabu/nmap port scan + service detect
    "honeypot_detection",# v3.2: heuristic deception/honeypot warning (read-only)
    "internal_network_safe", # v2.22: internal CIDR safe discovery + segmentation service review
    "network_firewall_tooling", # v3.7: Nmap/Nessus/Nipper/firewall config evidence normalization and safe audits
    "egress_canary",     # v3.2: safe egress/DLP reachability matrix (opt-in --test-egress-canary)
    "add_service_primitive", # v3.0: Windows service ACL/path execution-primitive review (local Windows, safe by default)
    "ad_identity_safe",  # v2.22: AD/DC read-only checks and residual-risk register
    "add_net_ad",        # v3.0: deeper read-only AD attack-surface review from add-ons
    "lateral_movement_paths", # v3.3: read-only AD attack-path analysis + BloodHound export
    "internal_ad_tooling", # v3.8: BloodHound/ADRecon/etc. evidence normalization, no credential attacks
    "ad_access_assessment", # v3.9: read-only DC/LDAP exposure review + AD evidence import
    "identity_security_tooling", # v3.9.5: AD CS/Entra posture adapters; intrusive actions approval-gated
    "engagement_evidence_review", # v3.9.1: sanitized authorized-exercise evidence import + synthetic instructor scenario
    "session_beacon_import", # v3.9.7.5: import-only authorized session/beacon evidence normalization
    "iot_cctv_safe",     # v2.22: IoT/CCTV/sensor/printer/VoIP/BMS safe inventory
    "ot_ics_safe",       # v3.3: OT/ICS safe discovery (Modbus/DNP3/BACnet/S7, SCADA web) [--ot-enable]
    "wireless_physical_soc", # v2.22: wireless, physical/social and SOC detection checklists
    "passive_wireless_inventory", # v3.9.7.5: passive/import-only observation inventory
    "social_engineering_governance", # v3.9.6: approved campaign/physical/wireless plan and result import; no delivery/attacks
    "discovery",         # URLs, JS analysis, params, secrets in JS
    "smart_crawl",       # v2.3: ZAP-style stateful crawler + app graph
    "backend_map",       # NEW v2.4: page → backend API mapping (find lonely admin APIs)
    "web_scanner_tooling",# ZAP/import URL inventory feeds complete JS analysis
    "js_analysis",        # v3.9.7.5: analyze every discovered in-scope JS and recovered source map
    "content_discovery", # ffuf + SecLists for hidden paths
    "deep_crawl",         # v3.9.3: follow in-scope links/endpoints, score new URLs into the audit queue
    "spec_scan",         # NEW v2.19: OpenAPI/Swagger + SOAP/WSDL/OData/JSON-RPC discovery
    "api_fuzz",          # NEW v2.13: catch-all-aware API endpoint discovery + GET/POST method fuzz
    "code_scan",         # NEW v2.17: static analysis of open-source code (secrets/endpoints/sinks)
    "code_intel",        # NEW v3.1: source-code intelligence map + endpoint→live matching + source→vuln tracing (15 branches)
    "sast_tooling",       # v3.7: Semgrep/Snyk-compatible SAST/SCA orchestration + SARIF/JSON normalization
    "code_security_tooling", # v3.8: SAST/SCA/secrets/IaC unified local adapters + imports
    "source_orchestration_tooling", # v3.9: s0 deterministic adapter + orchestrator result import
    "mobile_scan",       # NEW v2.17: APK/IPA/mobile-source analysis
    "mobile_tooling",     # v3.7: opt-in MobSF/drozer-compatible mobile orchestration and evidence import
    "mobile_reverse_extended", # v3.9.5: jadx/YARA/DIE/objection evidence adapters
    "supply_chain_review", # v3.2: dependency confusion / typosquat / lockfile integrity (static)
    "ci_cd_supply_chain_security", # v3.9.6: local CI/CD trust, runner, build and attestation review
    "firmware_reverse_safe", # firmware identification, validated extraction and confined rootfs audit
    "firmware_tooling_extended", # v3.9.7.5: EMBA, RouterSploit catalog/import and external firmware evidence
    "reverse_triage",       # file/hash/entropy/string/import triage; static only
    "reverse_static_analysis", # Ghidra/IDA/Radare2/Rizin headless static orchestration
    "reverse_ir_analysis", # v3.9.7.5: universal normalized decompiler/P-code IR index
    "reverse_taint_analysis", # v3.9.7.5: bounded interprocedural source-to-sink analysis
    "reverse_cross_language", # v3.9.7.5: JavaScript -> Java/Kotlin -> JNI -> native correlation
    "reverse_sandbox_analysis", # v3.9.7.5: explicitly gated disposable container/QEMU execution
    "reverse_dynamic_evidence", # import controlled debugger/instrumentation/sandbox evidence
    "reverse_dynamic_mapping", # v3.9.7.5: map runtime addresses to decompiled functions
    "reverse_symbolic_analysis", # v3.9.7.5: bounded CFG, symbolic and concolic test-input generation
    "reverse_fuzzing", # v3.9.7.5: automatic harness/dictionary proposals
    "reverse_crash_triage", # v3.9.7.5: crash deduplication and reproduction planning
    "reverse_diff_analysis", # v3.9.7.5: function-level binary patch comparison
    "reverse_campaign_index", # v3.9.7.5: content-addressed campaign deduplication
    "reverse_family_analysis", # v3.9.7.5: UEFI/driver/protocol/hardware evidence management
    "reverse_correlation",  # correlate static/dynamic evidence and prepare narrative
    "reverse_engineering_tooling", # legacy static/import adapter retained for compatibility
    "privesc_audit_tooling", # v3.8: LinPEAS/WinPEAS/etc. evidence normalization, no elevation attempts
    "surface_correlation", # v3.9.3: unify code/mobile/JS/crawl endpoints × live hosts into the audit queue
    "protected_routes",  # NEW v2.4: admin/billing/internal route detection + anon test
    "vuln_scan",         # nuclei templates, takeover
    "nuclei_extended",   # v2.5: 7+ nuclei tag combos (cves, exposures, takeover, etc)
    "custom_nuclei",     # NEW v2.11: bundled TBHM templates — captures low/info findings
    "vuln_scan_extended", # NEW v2.6: retire.js + dalfox + Atlassian/tech-stack nuclei + wpscan
    "infra_exposure",    # NEW v2.7: Spring Boot actuator + Docker registry + K8s/Vault/etcd/ES + Sentry DSN
    "deep_scan",         # nikto + jaeles + wapiti (intensity-gated)
    "audit",             # v2.2: Burp-style active scanner (insertion points + diff + verify)
    "atlassian_audit",   # NEW v2.6: Jira/Confluence IDOR + permission bypass + anon space tests
    "injections",        # XSS, SQLi, SSRF, LFI, redirect (input-driven, faster spray)
    "add_sqli",          # v3.0: focused detection-only SQLi verifier from add-ons
    "waf_evasion_ssrf",  # NEW v2.8: SSRF with decimal/octal/IPv6 IP encoding
    "smuggling",         # NEW v2.18: HTTP request smuggling timing detection (opt-in --smuggle)
    "authenticated_session_model", # v3.9.5: offline HAR/role matrix + BOLA/BFLA workflow modeling
    "access_control",    # IDOR, BAC, CORS (logic-driven)
    "auth_advanced",     # 2FA bypass, JWT, OAuth, session
    "auth_modern_review", # v3.3: JWT/OAuth/OIDC/SAML detection-only review
    "mfa_bypass_safe",   # v3.3: MFA/conditional-access review register + legacy-auth detection
    "api_specific",      # GraphQL, webhooks, mobile API, LLM probing
    "graphql_audit",     # v3.3: GraphQL introspection/suggestions/batching detection
    "interface_probe",   # NEW v2.24: gRPC/Socket.IO/AsyncAPI/JSON:API/SAML/SCIM/MCP read-only discovery (playbook §42/§47/§50)
    "modern_protocols_discovery", # v3.3: mDNS/SSDP passive + WebSocket/graphql-ws/MCP/AsyncAPI/SSE detection
    "ai_redteam_safe",   # v2.22: AI/LLM/RAG/agentic safe coverage catalog
    "ai_llm_tooling",     # v3.7: opt-in Garak/PyRIT-compatible AI assessment adapters + normalized evidence
    "llm_agent_tool_call_abuse", # v3.3: OWASP-LLM safe test catalog + optional benign canary probe
    "upload_race",       # file upload, race conditions, prototype pollution
    "business_logic",    # v2.3: mass assignment, price manipulation, HPP, race flags
    "cache_deception",   # NEW v2.8: Web Cache Deception via extension forcing
    "pdf_injection",     # NEW v2.8: PDF/CSV/Excel export injection candidates
    "cloud_recon",       # v2.3: S3/GCS/Azure bucket enumeration
    "cloud_recon_extended", # NEW v2.6: DO/R2/B2/Lambda/GAE + typo+ownership+billing-dead FP filters
    "iac_drift",         # v3.2: Terraform state vs live inventory drift / shadow-resource detection
    "k8s_recon_safe",    # v3.3: anonymous kube-apiserver/kubelet/etcd read-only checks
    "cloud_inventory_safe", # v3.3: read-only multi-cloud inventory (--cloud-profiles)
    "cloud_posture_tooling", # v3.9.5: Prowler/ScoutSuite/Kubescape/kube-bench adapters
    "cloud_identity_path_analysis", # v3.9.6: read-only AWS/Azure/GCP IAM privilege-path analysis
    "console_leaks",     # v2.4: console.log secrets in JS
    "api_key_pivot",     # v2.4: identify service from key + verify against live API
    "client_platform",   # NEW v2.19: PWA manifest + service-worker checks
    "secrets_misc",      # .git, .env, host header, security headers, methods
    "browser_extension_audit", # v3.3: fleet extension risk review (--browser-extension-audit)
    "visual",            # screenshots (gowitness/aquatone)
    "web3",              # Web3 frontend + RPC checks (gated by --web3 flag)
    "curl_verify",       # v2.5: real-curl re-verification of HIGH/CRITICAL + 7 curl-only probes
    "verify",            # legacy replay now records liveness/inconclusive evidence only
    "local_llm_triage",   # v3.9: local-only metadata extraction/dedup/remediation enrichment
    "exploitability_assessment", # v3.9.2: evidence-grounded confirmation, PoC, steps, impact and remediation
    "vulnerability_intelligence_enrichment", # v3.9.5: EPSS/KEV/OSV enrichment; no status promotion
    "attack_path",       # v3.2: chain correlation + MITRE ATT&CK mapping (--chain-simulate)
    "execution_orchestration_plan", # v3.9.6: single-pane approval/evidence/cleanup state; no exploit/C2 execution
    "safe_plan_execution", # v3.9.7.5: allowlisted read-only structured execution only
    "controlled_validation_plane", # v3.9.5: approval register/import only; never auto-runs C2/exploitation
    "purple_team_validation", # v3.9.5: ATT&CK-to-telemetry/detection evidence loop
    "compliance_coverage", # v3.2: OWASP/CWE/PCI matrix + gap detection
    "compliance_reporting_extended", # v3.9.6: policy-driven PCI/HIPAA/GDPR/ISO/NIST/PTES/OSSTMM/VDP mapping
    "dashboard",         # v2.3: static HTML dashboard
    "fp_review",         # NEW v2.9: write false_positives_review.md so user can re-check dropped findings
    "redteam_final_summary", # v2.22: red-team evidence index and residual-risk summary
    "backup_restore_simulation", # v3.3: backup/ransomware-recovery tabletop (--backup-sim)
    "coverage_map",      # NEW v2.24: ingest full playbook objective taxonomy (42 branches / 632 sub-topics) into governance map
    "playbook_integration", # v3.3: BR-branch coverage_tracker.csv + objective cards + master_coverage.html [--playbook-mode]
    "data_analysis_intelligence", # v3.9.5: separate entity/relationship/timeline analysis phase
    "ai_supervision",      # v3.9.5: advisory supervision + propose-only improvement review
    "ocsf_normalization", # v3.9.6: parallel OCSF-oriented finding event export
    "llm_run_analysis",    # v3.9.5: whole-run advisory after all finding/coverage producers
    "report",            # final layered reports
    "evidence_finalize", # v3.2: SHA256 manifest + redaction scan + ROE stamp + CI/JUnit output
]

# Additive lifecycle phases are kept outside the historical 129-phase constant so
# compatibility consumers retain the exact v3.9.7.3 graph while current profiles
# receive the stricter workflow in deterministic positions.
EXTENSION_PHASE_ANCHORS = {
    "redteam_campaign_control": "redteam_governance",
    "bug_bounty_workspace": "authenticated_session_model",
    "strict_finding_validation": "verify",
    "test_coverage_ledger": "backup_restore_simulation",
}

def expanded_phase_order() -> list[str]:
    order = list(PHASE_ORDER)
    for phase, anchor in EXTENSION_PHASE_ANCHORS.items():
        if phase in order:
            continue
        try:
            order.insert(order.index(anchor) + 1, phase)
        except ValueError:
            order.insert(max(0, len(order) - 2), phase)
    return order

FULL_PHASE_ORDER = expanded_phase_order()

# Profile → list of phases enabled (override per-profile in YAML if needed)
REDTEAM_PHASES = {
    "redteam_governance",
    "internal_network_safe",
    "add_service_primitive",
    "ad_identity_safe",
    "add_net_ad",
    "ad_access_assessment",
    "iot_cctv_safe",
    "wireless_physical_soc",
    "firmware_reverse_safe",
    "firmware_tooling_extended",
    "ai_redteam_safe",
    "redteam_final_summary",
    "coverage_map",
    "opsec_preflight",
    "agentic_control_manifest",
    "engagement_objectives",
    "corporate_osint",
    "osint_depth_collectors",
    "identity_security_tooling",
    "mobile_reverse_extended",
    "authenticated_session_model",
    "cloud_posture_tooling",
    "execution_orchestration_plan",
    "controlled_validation_plane",
    "purple_team_validation",
    "social_engineering_governance",
    "cloud_identity_path_analysis",
    "redteam_campaign_control", "bug_bounty_workspace",
    "strict_finding_validation", "test_coverage_ledger",
}

PROFILE_PHASES = {
    "passive_only":     ["preflight", "recon", "discovery", "secrets_misc", "report"],
    "authorized_safe":  FULL_PHASE_ORDER,
    "authorized_full":  FULL_PHASE_ORDER,
    "authorized_redteam": FULL_PHASE_ORDER,
    "authorized_assumed_breach": FULL_PHASE_ORDER,
    "forensic_recheck": ["preflight", "verify", "report"],
}


def canonicalize_profile_phases(profile_phases: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Canonicalize declarative profile phases against the authoritative graph.

    YAML profiles select a subset; they do not redefine dependency order. Explicit
    ``--phases`` remains an operator override and is intentionally left untouched.
    """
    requested = [str(x).strip() for x in (profile_phases or []) if str(x).strip()]
    known = set(FULL_PHASE_ORDER)
    unknown = list(dict.fromkeys(x for x in requested if x not in known))
    duplicates: list[str] = []
    seen: set[str] = set()
    for phase in requested:
        if phase in seen and phase not in duplicates:
            duplicates.append(phase)
        seen.add(phase)
    selected = {x for x in requested if x in known}
    return [x for x in FULL_PHASE_ORDER if x in selected], unknown, duplicates


# ──────────────────────────────────────────────────────────────────────────────
# v3.6 secret-validation helpers (used by Ctx.save_finding when --validate-secrets)
# ──────────────────────────────────────────────────────────────────────────────
import re as _re_sv


def SV_extract_value(finding: dict) -> str:
    """Pull the literal secret value out of a finding's evidence/match field."""
    try:
        from core.fp_filters import _extract_secret_value
        return _extract_secret_value(finding)
    except Exception:
        ev = finding.get("evidence", "") or finding.get("match", "") or ""
        m = _re_sv.search(r":\d+\s+(\S{6,200})", ev)
        return m.group(1) if m else ""


def _guess_secret_type(finding: dict) -> str:
    """Map a finding title to a secret_validator provider label."""
    t = (finding.get("title", "") or "").lower()
    table = [
        ("aws access key", "AWS Access Key ID"),
        ("github fine-grained", "GitHub Fine-grained PAT"),
        ("github", "GitHub Token"),
        ("slack", "Slack Token"),
        ("google api", "Google API Key"),
        ("stripe", "Stripe Secret Key"),
        ("sendgrid", "SendGrid API Key"),
    ]
    for key, label in table:
        if key in t:
            return label
    return finding.get("secret_type", "") or "unknown"


# ──────────────────────────────────────────────────────────────────────────────
# Context object — passed to every phase
# ──────────────────────────────────────────────────────────────────────────────
class Ctx:
    def __init__(self, args, profile, storage, runner, limits, monitor, output_dir):
        self.args = args
        self.profile = profile
        self.storage = storage
        self.runner = runner
        self.limits = limits
        self.monitor = monitor
        self.output = Path(output_dir)
        self.targets: list[str] = []        # final list of target hostnames/URLs
        self.scope_excludes: list[str] = [] # patterns to exclude
        self.start_ts = datetime.utcnow().isoformat()
        from core.execution_ledger import ExecutionLedger
        from core.evidence_redaction import register_secrets, _SENSITIVE_KEY
        register_secrets(v for k, v in vars(args).items() if _SENSITIVE_KEY.search(k) and isinstance(v, str))
        self.execution_ledger = ExecutionLedger(self.output)
        runner.execution_ledger = self.execution_ledger
        self.phase_state: dict = {}         # phases write intermediate results here
        self.local_llm_runtime = None       # v3.9.1: shared local-only runtime, initialized lazily
        # FIX v2.11: intensity was read via getattr(ctx, "intensity", ...) in
        # nuclei_extended/vuln_scan_extended but never actually set on ctx, so the
        # --quick/--deep/--insane flags were silently ignored for those phases.
        self.intensity = getattr(args, "intensity", "standard")
        # v3.3: global write gate + structured-log toggle
        self.no_destructive = bool(getattr(args, "no_destructive", False))
        self.force_write = bool(getattr(args, "force_write", False))

    def allow_mutation(self) -> bool:
        """v3.3: True if mutating/write operations are permitted this run."""
        if self.force_write:
            return True
        return not self.no_destructive

    def log(self, level, phase, msg):
        from core.evidence_redaction import redact_text
        msg = redact_text(msg)
        ts = datetime.utcnow().strftime("%H:%M:%S")
        # Color codes for terminal
        colors = {"INFO": "\033[36m", "WARN": "\033[33m", "ERR": "\033[31m",
                  "OK": "\033[32m", "FIND": "\033[35m"}
        c = colors.get(level, "")
        end = "\033[0m" if c else ""
        line = f"[{ts}] {c}{level:5}{end} {phase:14} {msg}"
        if not getattr(self.args, "silent", False):
            print(line, flush=True)
        # Always log to file
        with open(self.output / "tbhm.log", "a") as f:
            f.write(f"[{ts}] {level:5} {phase:14} {msg}\n")
        # v3.3: structured JSON line for SIEM/Splunk ingestion
        try:
            with open(self.output / "tbhm.jsonl", "a") as jf:
                jf.write(json.dumps({"ts": datetime.utcnow().isoformat() + "Z",
                                     "level": level, "phase": phase, "msg": msg}) + "\n")
        except Exception:
            pass

    def save_finding(self, finding: dict):
        """Persist a finding via storage layer (handles dedup + scoring)."""
        finding.setdefault("phase", "unknown")
        finding.setdefault("severity", "INFO")
        finding.setdefault("confidence", "MEDIUM")
        finding.setdefault("discovered_at", datetime.utcnow().isoformat())

        # Authorized exercise evidence belongs to enterprise/instructor reporting,
        # not bug-bounty eligibility filtering. It remains a lead but is preserved.
        _exercise_evidence = finding.get("phase") == "engagement_evidence_review"

        # Machine-readable program policy gate. A supplied policy is treated as
        # authoritative: explicit exclusions and unclear assets fail closed.
        policy = getattr(self, "program_policy", None)
        if policy:
            try:
                from core import program_policy as _program_policy
                asset_ref = str(finding.get("url") or finding.get("target") or "")
                if asset_ref and asset_ref != "local-analysis.invalid":
                    decision = _program_policy.evaluate_asset(policy, asset_ref)
                    finding["scope_decision"] = decision.get("decision")
                    finding["policy_id"] = decision.get("policy_id")
                    if decision.get("decision") != "in_scope":
                        reason = f"program policy blocked finding: {decision.get('reason')}"
                        try: self.storage._record_drop(finding, reason, "program_policy")
                        except Exception: pass
                        self.log("WARN", finding["phase"], reason)
                        return None
                vuln_type = str(finding.get("vulnerability_type") or finding.get("cwe") or finding.get("title") or "")
                eligibility = _program_policy.evaluate_vulnerability(policy, vuln_type)
                finding["program_eligibility"] = eligibility
                if eligibility.get("eligible") is False:
                    reason = f"program policy marks finding ineligible: {eligibility.get('reason')}"
                    try: self.storage._record_drop(finding, reason, "program_policy")
                    except Exception: pass
                    return None
            except Exception as exc:
                self.log("WARN", finding["phase"], f"program policy evaluation failed closed: {exc}")
                return None

        # Universal network scope gate at the persistence boundary. Phase-local
        # checks remain useful, but a malformed importer must not be able to save
        # an out-of-scope URL that later phases/reporters treat as eligible. Local
        # source/binary paths are unaffected.
        network_ref = str(finding.get("url") or "").strip()
        if not network_ref.startswith(("http://", "https://")):
            target_ref = str(finding.get("target") or "").strip()
            if target_ref.startswith(("http://", "https://")):
                network_ref = target_ref
        if network_ref:
            try:
                from core.targets import target_scope_allows
                if not target_scope_allows(self, network_ref):
                    reason = f"out-of-scope finding blocked at save boundary: {network_ref}"
                    try:
                        self.storage._record_drop(finding, reason, "scope_boundary")
                    except Exception:
                        pass
                    self.log("WARN", finding["phase"], reason)
                    return None
            except Exception as exc:
                self.log("WARN", finding["phase"], f"scope validation failed closed: {exc}")
                return None

        # v2.12: HackerOne Core-ineligible suppression. Don't delete — tag, archive
        # to dropped_findings, and keep out of the main report. --include-ineligible
        # disables this so they flow through normally.
        if not _exercise_evidence and not getattr(self.args, "include_ineligible", False):
            from core import ineligible_findings
            suppress, reason = ineligible_findings.classify(finding)
            if suppress:
                ineligible_findings.mark_suppressed(finding, reason)
                try:
                    self.storage._record_drop(finding, reason, "hackerone_core_ineligible")
                except Exception:
                    pass
                self._suppressed_count = getattr(self, "_suppressed_count", 0) + 1
                self.log("INFO", finding["phase"],
                         f"[SUPPRESS] {finding.get('title', 'finding')} — Core ineligible")
                return None

        # v3.4: false-positive gate — path context, dummy/low-entropy secrets,
        # keyword-only code leads. Drops are archived (dropped_findings), never
        # silently deleted; downgrades are kept as leads out of the confirmed report.
        if not _exercise_evidence and not getattr(self.args, "no_fp_filter", False):
            try:
                from core import fp_filters
                action, reason, tier = fp_filters.assess(
                    finding,
                    min_entropy=float(getattr(self.args, "secret_min_entropy", 3.0) or 3.0),
                    secret_confidence=getattr(self.args, "secret_confidence", "medium") or "medium",
                    extra_ignores=getattr(self, "_ignore_patterns", None),
                )
                if action == "drop":
                    try:
                        self.storage._record_drop(finding, reason, "fp_filter")
                    except Exception:
                        pass
                    self._fp_dropped = getattr(self, "_fp_dropped", 0) + 1
                    return None
                if action == "downgrade":
                    finding["status"] = "lead"
                    finding["tier"] = tier or "lead"
                    finding["fp_note"] = reason
                    # leads never outrank MEDIUM in the confirmed report
                    if finding.get("severity") in ("HIGH", "CRITICAL", "MEDIUM"):
                        finding["severity"] = "LOW"
            except Exception:
                pass

        # v3.6: optional LIVE credential validation (authorised-only, opt-in).
        # Runs only for surviving secret findings when --validate-secrets is set.
        if getattr(self.args, "validate_secrets", False):
            title = (finding.get("title", "") or "").lower()
            is_secret = ("secret" in title or "hardcoded" in title
                         or "credential" in title or finding.get("cwe") == "CWE-798")
            if is_secret and not finding.get("validation"):
                try:
                    from core import secret_validator as SV
                    stype = finding.get("secret_type") or _guess_secret_type(finding)
                    value = SV_extract_value(finding)
                    if value:
                        state, detail = SV.validate(stype, value,
                                                    finding.get("paired_secret", ""))
                        SV.annotate_finding(finding, state, detail)
                        self.log("INFO", finding.get("phase", "?"),
                                 f"[VALIDATE] {stype}: {state} — {detail}")
                except Exception as e:
                    self.log("WARN", finding.get("phase", "?"),
                             f"secret validation error: {e}")

        # v2.23: tag heuristic findings as unconfirmed LEADS vs CONFIRMED so the
        # report never presents a candidate as a proven vulnerability.
        try:
            from core import finding_class
            finding_class.apply(finding)
        except Exception:
            pass

        fid = self.storage.save_finding(finding)
        if fid is None or fid < 0:
            return None
        # Preserve the pre-finding evidence trail.  This does not imply the phase
        # executed a formal test; it records what the phase observed and keeps a
        # separate candidate/root-cause identity for later validation/dedup.
        try:
            existing = self.storage.conn.execute(
                "SELECT id FROM candidates WHERE finding_id=? LIMIT 1", (fid,)).fetchone()
            if not existing:
                observation_id = self.storage.save_observation(
                    phase=finding["phase"], observation_type=str(finding.get("observation_type") or "phase_finding_record"),
                    target=str(finding.get("url") or finding.get("target") or ""),
                    summary=str(finding.get("title") or "finding"),
                    evidence={"evidence": str(finding.get("evidence") or "")[:12000],
                              "response_present": bool(finding.get("response_raw")),
                              "request_present": bool(finding.get("request_raw"))},
                    test_execution_id=finding.get("test_execution_id"),
                    artifact_sha256=str(finding.get("artifact_sha256") or ""),
                )
                candidate_id = self.storage.save_candidate(
                    finding_id=fid, observation_id=observation_id, finding=finding,
                    state=str(finding.get("finding_class") or "candidate"),
                    hypothesis=str(finding.get("description") or finding.get("title") or ""),
                    required_validation=str(finding.get("validation_required") or ""),
                )
                # Persist the candidate/root-cause IDs without changing the main
                # finding schema used by historical consumers.
                extra = {"candidate_id": candidate_id,
                         "root_cause_fingerprint": self.storage.root_cause_fingerprint(finding)}
                self.storage.update_finding_verification(fid, extra)
        except Exception as exc:
            self.log("WARN", finding["phase"], f"lifecycle ledger warning: {exc}")
        self.log("FIND", finding["phase"],
                 f"[{finding['severity']}] {finding.get('title', 'finding')} (id={fid}, class={finding.get('finding_class')})")
        return fid


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        prog="tbhm",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=BANNER + "\n\nProfile-based bug bounty automation framework.",
        epilog="""
EXAMPLES:
    Quick passive recon (zero-touch):
        ./tbhm.py -d hackerone.com --profile passive_only

    Standard bug bounty scan (default):
        ./tbhm.py -d target.com --profile authorized_safe

    Multiple targets with exclusions:
        ./tbhm.py -l scope.txt --profile authorized_safe --exclude oos.txt

    Web3 / dApp target:
        ./tbhm.py -d uniswap.org --profile authorized_safe --web3

    Re-verify previously found bugs:
        ./tbhm.py -d target.com --profile forensic_recheck

DOCUMENTATION:
    README.md       — Full Arabic documentation
    CHECKLIST.md    — Methodology checklist (Haddix + 2025 + OWASP API)
    profiles/       — YAML profiles (you can create custom ones)
""")

    # Additive input routing for opt-in capabilities; the dispatch loop is unchanged.
    from core.capability_inputs_v423 import CapabilityInput
    g_research = p.add_argument_group('OPTIONAL RESEARCH CAPABILITIES (v4.2.3)')
    g_research.add_argument('--brokered-http-plan', metavar='PATH', action=CapabilityInput, phase_order=FULL_PHASE_ORDER,
        help='Explicit read-only native/isolated-pipe replay plan; requires online mode, target, program policy and --approve-brokered-http.')
    g_research.add_argument('--approve-brokered-http', action='store_true', help='Approve the explicit brokered read-only HTTP plan.')
    g_research.add_argument('--llm-security-input', metavar='PATH', action=CapabilityInput, phase_order=FULL_PHASE_ORDER,
        help='Offline Garak/Promptfoo/normalized-export evidence review; external evaluator output never confirms a vulnerability.')
    g_research.add_argument('--llm-security-format', choices=('garak', 'promptfoo', 'tbhm'), default=None,
        help='Required explicit format for --llm-security-input.')
    g_research.add_argument('--learning-corpus-input', metavar='PATH', action=CapabilityInput, phase_order=FULL_PHASE_ORDER,
        help='Audit operator-declared reuse rights, human labels, sanitized hashes and project/root-cause/data split leakage.')
    g_research.add_argument('--export-retrieval-cards', action='store_true', help='Export only eligible reviewed train records as untrusted retrieval data cards; no training or installation.')
    g_research.add_argument('--delivery-audit-input', metavar='PATH', action=CapabilityInput, phase_order=FULL_PHASE_ORDER,
        help='Audit an existing sealed run delivery for supplied canaries, including bounded ZIP/tar/gzip contents.')
    g_research.add_argument('--privacy-canary-env', default=None, metavar='ENV,ENV', help='Environment-variable names containing privacy audit canaries; values are never emitted.')
    g_research.add_argument('--require-private-delivery', action='store_true', help='Fail the optional audit phase if the prior delivery has hits, integrity failures or incomplete coverage.')

    # Target group (one required)
    g_strict = p.add_argument_group('OPTIONAL STRICT READ VALIDATION (v4.2.5)')
    g_strict.add_argument('--strict-replay-plan', metavar='PATH', action=CapabilityInput, phase_order=FULL_PHASE_ORDER,
        help='Explicit destination-pinned controlled-canary traversal / owned-role BFLA read plan.')
    g_strict.add_argument('--approve-strict-replay', action='store_true', help='Approve the reviewed strict read-only replay plan.')
    g_target = p.add_argument_group("TARGET (one required)")
    g_target.add_argument("-d", "--domain", help="Single domain target")
    g_target.add_argument("-l", "--list", help="File with one domain per line")
    g_target.add_argument("-u", "--url", help="Single URL")
    g_target.add_argument("-U", "--urls", help="File with one URL per line")

    # Profile
    g_profile = p.add_argument_group("PROFILE")
    g_profile.add_argument("--profile", default="authorized_safe",
                           help="Scan profile (default: authorized_safe). "
                                "Options: passive_only, authorized_safe, authorized_full, authorized_redteam, authorized_assumed_breach, forensic_recheck")
    g_profile.add_argument("--list-profiles", action="store_true",
                           help="List available profiles and exit")
    g_profile.add_argument("--web3", action="store_true",
                           help="Enable Web3/dApp specific phases")

    # v2.22: enterprise red-team expansion knobs
    g_rt = p.add_argument_group("ENTERPRISE RED TEAMING (v2.22-safe)")
    g_rt.add_argument("--redteam", action="store_true",
                      help="Enable enterprise red-team posture/reporting mode. Use with --profile authorized_redteam for full coverage.")
    g_rt.add_argument("--corp-cidr", metavar="CIDR[,CIDR]",
                      help="Approved internal CIDR(s) for safe internal discovery, e.g. 10.10.0.0/16,192.168.3.0/24")
    g_rt.add_argument("--corp-cidrs-file", metavar="PATH",
                      help="File with approved internal CIDRs, one per line")
    g_rt.add_argument("--dc-ip", metavar="IP[,IP]",
                      help="Domain controller IP(s) for read-only AD/DC checks")
    g_rt.add_argument("--dc-ips-file", metavar="PATH",
                      help="File with domain controller IPs, one per line")
    g_rt.add_argument("--ad-domain", metavar="DOMAIN",
                      help="AD DNS domain, e.g. corp.local")
    g_rt.add_argument("--ad-user", metavar="USER",
                      help="Optional read-only LDAP bind user. Password is read from --ad-password-env, not CLI history.")
    g_rt.add_argument("--ad-password-env", metavar="ENV", default="TBHM_AD_PASSWORD",
                      help="Environment variable containing the read-only AD password (default: TBHM_AD_PASSWORD)")
    g_rt.add_argument("--wireless-interface", metavar="IFACE",
                      help="Wireless interface for passive SSID inventory where legal, e.g. wlan0")
    g_rt.add_argument("--firmware", metavar="PATH",
                      help="Firmware image for static binwalk/strings review")
    g_rt.add_argument("--firmware-extract", action="store_true",
                      help="Allow binwalk extraction of supplied firmware image. Static only; no device writes.")
    g_rt.add_argument("--firmware-rootfs", metavar="PATH",
                      help="Path to an already-extracted firmware root filesystem to audit directly "
                           "(accounts, services, keys, permissions, web/CGI, ELF inventory and hardening). "
                           "Static read-only; the rootfs is never chrooted into or executed.")
    g_rt.add_argument("--firmware-tooling", action="store_true",
                      help="Enable extended firmware adapters and readiness output (EMBA, RouterSploit catalog/import, FirmAE/FIRMADYNE/FAT/FACT evidence).")
    g_rt.add_argument("--emba", action="store_true",
                      help="Run an installed EMBA default static profile against --firmware. Explicit opt-in; use only in a disposable analysis VM.")
    g_rt.add_argument("--emba-mode", choices=["static", "sbom", "emulation", "full", "import"], default="static",
                      help="EMBA operating mode: static, SBOM-only, emulation/full (isolation confirmation required), or import-only.")
    g_rt.add_argument("--emba-path", metavar="PATH",
                      help="EMBA executable or installation directory (otherwise EMBA_HOME, PATH, /opt/emba and ~/emba are checked).")
    g_rt.add_argument("--emba-profile", metavar="PATH",
                      help="EMBA scan profile; defaults to scan-profiles/default-scan.emba.")
    g_rt.add_argument("--emba-results", metavar="PATH",
                      help="Import an existing EMBA log/report directory without running EMBA.")
    g_rt.add_argument("--emba-timeout", type=int, default=14400, metavar="SECONDS",
                      help="Maximum EMBA runtime (default 14400; bounded to 600-86400).")
    g_rt.add_argument("--emba-sandbox-image", metavar="IMAGE",
                      help="Already-present container image containing EMBA. Required for EMBA emulation/full; images are never pulled automatically.")
    g_rt.add_argument("--emba-sandbox-engine", choices=["auto", "podman", "docker"], default="auto",
                      help="Container backend for isolated EMBA mode (default auto, preferring Podman).")
    g_rt.add_argument("--emba-emulation", action="store_true",
                      help="Use EMBA's emulation profile inside an already-present locked-down container image. Requires --emba-sandbox-image and --confirm-isolated-execution; images are never pulled automatically.")
    g_rt.add_argument("--confirm-isolated-execution", action="store_true",
                      help="Confirm that any explicitly requested firmware emulation runs inside an isolated disposable environment.")
    g_rt.add_argument("--routersploit-root", metavar="PATH",
                      help="RouterSploit source/install root used only to build a local module catalog; no modules are executed.")
    g_rt.add_argument("--routersploit-catalog", action="store_true",
                      help="Inventory installed RouterSploit modules and CVE references without importing or executing them.")
    g_rt.add_argument("--routersploit-results", metavar="PATH",
                      help="Import authorized RouterSploit output as unconfirmed leads. TBHM never launches RouterSploit modules.")
    g_rt.add_argument("--firmware-tool-results", metavar="PATH",
                      help="Import FirmAE, FIRMADYNE, FAT, FACT, QEMU or other firmware-analysis evidence for normalization.")
    g_rt.add_argument("--interface-grpc-ports", metavar="PORTS", default=None,
                      help="Comma-separated ports for gRPC reflection probe "
                           "(default: 443,50051). Read-only `grpcurl list` only.")
    g_rt.add_argument("--ai-endpoints-file", metavar="PATH",
                      help="File with approved AI/LLM/RAG endpoints for header baseline and test catalog")
    g_rt.add_argument("--ai-tooling", action="store_true",
                      help="Enable opt-in AI/LLM tooling adapters (Garak and evidence import).")
    g_rt.add_argument("--ai-generator", metavar="TYPE",
                      help="Approved Garak generator type, e.g. openai.OpenAICompatible; requires --ai-tooling.")
    g_rt.add_argument("--ai-model", metavar="NAME",
                      help="Approved model/deployment name for AI tooling.")
    g_rt.add_argument("--ai-probes", metavar="LIST", default="promptinject,leakreplay",
                      help="Comma-separated conservative Garak probe families (default: promptinject,leakreplay).")
    g_rt.add_argument("--ai-results", metavar="PATH",
                      help="Existing Garak/PyRIT/LLM scanner JSON or JSONL results to normalize; no live attack required.")
    g_rt.add_argument("--sast-tooling", action="store_true",
                      help="Run installed SAST adapters against --code-dir (Semgrep by default).")
    g_rt.add_argument("--sast-results", metavar="PATH",
                      help="Import existing SARIF/JSON SAST results from commercial or open-source scanners.")
    g_rt.add_argument("--mobile-tooling", action="store_true",
                      help="Enable installed mobile scanner adapters for supplied APK/IPA/source.")
    g_rt.add_argument("--mobsf-url", metavar="URL",
                      help="Approved MobSF server URL; API key must be in TBHM_MOBSF_API_KEY.")
    g_rt.add_argument("--mobile-results", metavar="PATH",
                      help="Import existing MobSF/SDK scanner JSON results.")
    g_rt.add_argument("--web-scanner-tooling", action="store_true",
                      help="Enable optional ZAP baseline adapter on approved live targets.")
    g_rt.add_argument("--web-scanner-results", metavar="PATH",
                      help="Import ZAP/Acunetix/Invicti/Qualys-compatible XML, JSON, or SARIF findings.")
    g_rt.add_argument("--zap-max-targets", type=int, default=5, metavar="N",
                      help="Maximum live targets passed to the optional ZAP baseline/AJAX spider adapter (default 5).")
    g_rt.add_argument("--zap-timeout", type=int, default=1800, metavar="SECONDS",
                      help="Per-target ZAP adapter timeout (default 1800).")
    g_rt.add_argument("--no-zap-ajax-spider", dest="zap_ajax_spider", action="store_false", default=True,
                      help="Disable ZAP's AJAX spider when the optional baseline adapter is run.")
    g_rt.add_argument("--js-candidate-results", action="append", default=[], metavar="PATH",
                      help="Additional Katana/ParamSpider/ZAP/crawler JSON, JSONL, HAR or text evidence containing JavaScript URLs; repeatable.")
    g_rt.add_argument("--js-max-files", type=int, default=0, metavar="N",
                      help="Optional cap on unique in-scope JS files analyzed; 0 means analyze every discovered candidate (default 0; maximum 1000000).")
    g_rt.add_argument("--js-max-bytes", type=int, default=15728640, metavar="BYTES",
                      help="Maximum response/map bytes analyzed per JavaScript candidate (default 15 MiB; maximum 100 MiB).")
    g_rt.add_argument("--js-timeout", type=int, default=20, metavar="SECONDS",
                      help="Per-request JavaScript/source-map timeout (default 20; maximum 120).")
    g_rt.add_argument("--js-max-source-maps", type=int, default=250, metavar="N",
                      help="Maximum source-map references processed per JS file (default 250; excess references receive explicit skipped records).")
    g_rt.add_argument("--js-max-recovered-sources", type=int, default=10000, metavar="N",
                      help="Maximum sourcesContent entries analyzed per source map (default 10000; excess entries receive explicit skipped records).")
    g_rt.add_argument("--js-candidate-scan-files", type=int, default=10000, metavar="N",
                      help="Maximum recon/scanner evidence files searched for JS URLs (default 10000).")
    g_rt.add_argument("--network-results", metavar="PATH",
                      help="Import Nmap/Nessus/network scanner XML or JSON results.")
    g_rt.add_argument("--firewall-config", metavar="PATH",
                      help="Router/firewall/switch configuration file or directory for static security review.")
    g_rt.add_argument("--firewall-tooling", action="store_true",
                      help="Enable installed read-only firewall configuration analyzers where available.")
    g_rt.add_argument("--external-tooling", action="store_true",
                      help="Enable additive external-perimeter evidence adapters; no phishing, C2, tunnels, or exploit execution.")
    g_rt.add_argument("--external-results", metavar="PATH",
                      help="Import Amass/Shodan/theHarvester, web/vulnerability scanner, SearchSploit or Metasploit assessment evidence.")
    g_rt.add_argument("--reverse-tooling", action="store_true",
                      help="Enable the v3.9.2 reverse-engineering workflow. Native analysis is static; dynamic evidence is imported from an approved sandbox.")
    g_rt.add_argument("--binary-path", metavar="PATH",
                      help="Authorized binary, package, firmware file, or directory for reverse-engineering analysis.")
    g_rt.add_argument("--reverse-results", metavar="PATH",
                      help="Import IDA/Ghidra/Radare2/Rizin/Binary Ninja/Cutter/capa/DIE/PeStudio/Hopper/Glaurung JSON, JSONL, or SARIF results.")
    g_rt.add_argument("--reverse-static", action="store_true",
                      help="Run available static backends (Ghidra headless, Radare2/Rizin, optional IDA batch) against --binary-path.")
    g_rt.add_argument("--reverse-backends", default="auto", metavar="LIST",
                      help="Comma-separated static backends: auto,ghidra,r2,rizin,ida (default auto).")
    g_rt.add_argument("--reverse-ghidra-home", metavar="PATH",
                      help="Ghidra installation root containing support/analyzeHeadless; defaults to GHIDRA_HOME or PATH.")
    g_rt.add_argument("--reverse-ida-path", metavar="PATH",
                      help="Optional licensed IDA executable for batch static export. IDA is never installed by TBHM.")
    g_rt.add_argument("--reverse-dynamic-results", metavar="PATH",
                      help="Import controlled Frida/GDB/WinDbg/x64dbg/CAPE/Cuckoo/QEMU/Unicorn/online-sandbox evidence. TBHM does not launch the artifact.")
    g_rt.add_argument("--reverse-verification-manifest", metavar="PATH",
                      help="Optional JSON manifest binding dynamic-evidence SHA-256 hashes to an explicit controlled, reproduced verification decision.")
    g_rt.add_argument("--reverse-symbolic", action="store_true",
                      help="Run bounded local angr CFG plus optional analyst-address symbolic/concolic test-input synthesis.")
    g_rt.add_argument("--reverse-symbolic-results", metavar="PATH",
                      help="Import angr/Triton/Unicorn/symbolic-analysis JSON, JSONL, or SARIF evidence.")
    g_rt.add_argument("--reverse-symbolic-timeout", type=int, default=1800, metavar="SECONDS",
                      help="Per-artifact angr timeout (default 1800; capped at 7200).")
    g_rt.add_argument("--reverse-symbolic-max-functions", type=int, default=10000, metavar="N",
                      help="Maximum functions exported by bounded symbolic/CFG triage (default 10000; capped at 50000).")
    g_rt.add_argument("--reverse-max-files", type=int, default=50, metavar="N",
                      help="Maximum binary/evidence files inspected by reverse phases (default 50; hard maximum 1000).")
    g_rt.add_argument("--reverse-max-file-mb", type=int, default=200, metavar="MB",
                      help="Maximum size of one binary artifact (default 200 MB; hard maximum 4096 MB).")
    g_rt.add_argument("--reverse-evidence-max-mb", type=int, default=200, metavar="MB",
                      help="Maximum aggregate dynamic-evidence bytes inspected (default 200 MB; hard maximum 4096 MB).")
    g_rt.add_argument("--reverse-strings-min", type=int, default=8, metavar="N",
                      help="Minimum printable string length for built-in triage (default 8).")
    g_rt.add_argument("--reverse-ir", action="store_true",
                      help="Validate and summarize normalized universal reverse IR generated by static backends.")
    g_rt.add_argument("--reverse-ir-results", metavar="PATH",
                      help="Additional normalized or backend JSON evidence used by IR/taint/diff phases.")
    g_rt.add_argument("--reverse-ir-max-functions", type=int, default=20000, metavar="N",
                      help="Maximum functions exported by the Ghidra universal IR script (default 20000).")
    g_rt.add_argument("--reverse-decompile-timeout", type=int, default=60, metavar="SECONDS",
                      help="Ghidra decompile timeout per function (default 60 seconds).")
    g_rt.add_argument("--reverse-taint", action="store_true",
                      help="Run bounded interprocedural source-to-sink analysis over normalized reverse IR.")
    g_rt.add_argument("--reverse-taint-iterations", type=int, default=20, metavar="N",
                      help="Maximum fixed-point iterations for interprocedural taint summaries (default 20).")
    g_rt.add_argument("--reverse-cross-language", action="store_true",
                      help="Correlate WebView JavaScript bridges through Java/Kotlin and JNI to native functions.")
    g_rt.add_argument("--reverse-cross-language-root", metavar="PATH",
                      help="Decompiled Android/mobile source root used by cross-language correlation.")
    g_rt.add_argument("--reverse-sandbox", action="store_true",
                      help="Run one explicitly supplied command in a TBHM-owned disposable container or QEMU VM; requires isolation confirmation.")
    g_rt.add_argument("--reverse-sandbox-backend", choices=["container", "qemu"], default="container")
    g_rt.add_argument("--reverse-sandbox-image", metavar="IMAGE",
                      help="Pre-existing local container image; TBHM uses --pull=never.")
    g_rt.add_argument("--reverse-sandbox-command", metavar="JSON_OR_PATH",
                      help="Guest command as a JSON argument array; for example: [\"/analyze\", \"/input/artifact\"].")
    g_rt.add_argument("--reverse-sandbox-engine", choices=["auto", "podman", "docker"], default="auto")
    g_rt.add_argument("--reverse-sandbox-timeout", type=int, default=300, metavar="SECONDS")
    g_rt.add_argument("--reverse-sandbox-memory-mb", type=int, default=1024, metavar="MB")
    g_rt.add_argument("--reverse-sandbox-cpus", type=float, default=1.0, metavar="N")
    g_rt.add_argument("--reverse-sandbox-pids", type=int, default=128, metavar="N")
    g_rt.add_argument("--reverse-sandbox-network", choices=["none", "bridge"], default="none")
    g_rt.add_argument("--reverse-vm-image", metavar="PATH", help="Read-only QEMU base image; TBHM creates a temporary qcow2 overlay.")
    g_rt.add_argument("--reverse-qemu-binary", default="qemu-system-x86_64", metavar="COMMAND")
    g_rt.add_argument("--reverse-vm-kernel", metavar="PATH")
    g_rt.add_argument("--reverse-vm-initrd", metavar="PATH")
    g_rt.add_argument("--reverse-vm-append", default="console=ttyS0", metavar="TEXT")
    g_rt.add_argument("--reverse-dynamic-map", action="store_true",
                      help="Map imported runtime addresses/events directly to normalized decompiled functions.")
    g_rt.add_argument("--reverse-symbolic-mode", choices=["cfg", "symbolic", "concolic"], default="cfg")
    g_rt.add_argument("--reverse-symbolic-find", action="append", default=[], metavar="ADDRESS",
                      help="Analyst-supplied target address for bounded symbolic/concolic reachability; repeatable.")
    g_rt.add_argument("--reverse-symbolic-avoid", action="append", default=[], metavar="ADDRESS")
    g_rt.add_argument("--reverse-symbolic-input-kind", choices=["stdin", "argv1"], default="stdin")
    g_rt.add_argument("--reverse-symbolic-max-input-bytes", type=int, default=64, metavar="N")
    g_rt.add_argument("--reverse-symbolic-printable", action="store_true")
    g_rt.add_argument("--reverse-symbolic-seed", metavar="PATH", help="Concrete seed for symbolic/concolic input modeling.")
    g_rt.add_argument("--reverse-symbolic-trace", metavar="PATH", help="JSON address trace for seed-guided angr concolic replay.")
    g_rt.add_argument("--reverse-fuzz-harness", action="store_true",
                      help="Generate bounded libFuzzer-style harness proposals and dictionaries from parser candidates.")
    g_rt.add_argument("--reverse-fuzz-max-harnesses", type=int, default=20, metavar="N")
    g_rt.add_argument("--reverse-crash-results", metavar="PATH",
                      help="Crash logs/dumps directory for stack-signature deduplication and reproduction planning.")
    g_rt.add_argument("--reverse-crash-command", metavar="JSON_OR_PATH",
                      help="Sandbox command JSON array. Use /input/artifact and /input/case placeholders for isolated reproduction.")
    g_rt.add_argument("--reverse-crash-minimize", action="store_true",
                      help="Reproduce and minimize --reverse-crash-input in a locked-down local container. Requires explicit isolation confirmation.")
    g_rt.add_argument("--reverse-crash-input", metavar="PATH", help="Concrete crashing input mounted read-only as /input/case.")
    g_rt.add_argument("--reverse-crash-image", metavar="IMAGE", help="Already-present container image used for crash reproduction; images are never pulled automatically.")
    g_rt.add_argument("--reverse-crash-engine", choices=["auto", "podman", "docker"], default="auto")
    g_rt.add_argument("--reverse-crash-timeout", type=int, default=60, metavar="SECONDS")
    g_rt.add_argument("--reverse-crash-max-tests", type=int, default=100, metavar="N")
    g_rt.add_argument("--reverse-crash-max-files", type=int, default=10000, metavar="N")
    g_rt.add_argument("--reverse-diff-old", metavar="PATH", help="Old normalized/backend IR JSON for function-level comparison.")
    g_rt.add_argument("--reverse-diff-new", metavar="PATH", help="New normalized/backend IR JSON for function-level comparison.")
    g_rt.add_argument("--reverse-diff-threshold", type=float, default=0.72, metavar="FLOAT")
    g_rt.add_argument("--reverse-campaign-store", metavar="PATH", help="Content-addressed campaign artifact store root.")
    g_rt.add_argument("--reverse-campaign-artifacts", metavar="PATH", help="File/directory to index in the campaign store.")
    g_rt.add_argument("--reverse-campaign", default="default", metavar="NAME")
    g_rt.add_argument("--reverse-project", default="default", metavar="NAME")
    g_rt.add_argument("--reverse-product", default="unknown", metavar="NAME")
    g_rt.add_argument("--reverse-product-version", default="unknown", metavar="VERSION")
    g_rt.add_argument("--reverse-campaign-copy", action="store_true", help="Copy artifacts into the content-addressed store instead of indexing only.")
    g_rt.add_argument("--reverse-campaign-max-files", type=int, default=100000, metavar="N")
    g_rt.add_argument("--reverse-family-path", metavar="PATH",
                      help="UEFI image, driver, PCAP, mobile package, hardware dump or directory for managed family inventory.")
    g_rt.add_argument("--reverse-family-tooling", action="store_true",
                      help="Run installed static parsers/decompilers for managed families. Requires --confirm-isolated-execution because parsers consume untrusted artifacts.")
    g_rt.add_argument("--reverse-family-max-files", type=int, default=5000, metavar="N")
    g_rt.add_argument("--reverse-protocol-max-packets", type=int, default=10000, metavar="N")
    g_rt.add_argument("--verify-package", metavar="PATH", help="Verify a TBHM/source ZIP or source tree before other work.")
    g_rt.add_argument("--verify-manifest", metavar="PATH", help="Optional release manifest used by --verify-package on a source tree.")
    g_rt.add_argument("--legacy-shadow-replay", action="store_true",
                      help="Opt-in pre-v4 generic shadow-replay reachability check in the verify phase. Advisory only; never confirms a finding on its own.")
    g_rt.add_argument("--privesc-results", metavar="PATH",
                      help="Import LinPEAS/WinPEAS/LinEnum/PSpy/PowerUp/Seatbelt/SharpUp audit output; never executes elevation.")
    g_rt.add_argument("--ad-results", metavar="PATH",
                      help="Import BloodHound/SharpHound/ADRecon/LDAP/NetExec/Impacket assessment evidence without credential attacks.")
    g_rt.add_argument("--ad-access", action="store_true",
                      help="Run safe read-only AD access/exposure assessment (DC services, SMB signing, LDAP configuration only).")
    g_rt.add_argument("--ad-access-results", metavar="PATH",
                      help="Import BloodHound/LDAPDomainDump/AD assessment JSON, SARIF, LDIF, CSV, XML, HTML, or text evidence as leads.")
    g_rt.add_argument("--ad-access-max-dcs", type=int, default=5, metavar="N",
                      help="Maximum supplied DCs for safe service/signing checks (default 5, hard maximum 20).")
    g_rt.add_argument("--ad-ldap-ca-file", metavar="PATH",
                      help="CA certificate bundle used to validate LDAPS in ad_access_assessment.")
    g_rt.add_argument("--code-security-tooling", action="store_true",
                      help="Run installed read-only SAST/SCA/secret/IaC scanners locally against --code-dir.")
    g_rt.add_argument("--code-security-tools", metavar="LIST",
                      default="bandit,njsscan,gitleaks,trivy,grype,checkov,terrascan,tfsec",
                      help="Comma-separated local code-security adapters to run.")
    g_rt.add_argument("--code-security-results", metavar="PATH",
                      help="Import JSON/JSONL/SARIF from SAST, SCA, secret, IaC, IAST/RASP or AI code-review platforms.")
    g_rt.add_argument("--source-orchestration", action="store_true",
                      help="Run approved local deterministic source orchestrators; s0-cli is forced to --no-llm.")
    g_rt.add_argument("--source-orchestration-tools", metavar="LIST", default="s0",
                      help="Comma-separated source orchestrators (live support: s0; other platforms are import-only).")
    g_rt.add_argument("--source-orchestration-results", metavar="PATH",
                      help="Import orchestrator JSON/JSONL/SARIF from s0, Argus, Mega-Linter, SonarQube, CodeQL, DefectDojo, or compatible tools.")
    g_rt.add_argument("--s0-dir", metavar="PATH",
                      help="Optional local s0-cli project directory for execution through uv when s0 is not on PATH.")

    g_ev = p.add_argument_group("AUTHORIZED EXERCISE EVIDENCE (v3.9.1-safe)")
    g_ev.add_argument("--engagement-evidence", metavar="PATH",
                      help="Import authorized exercise evidence for sanitized normalization; TBHM does not execute the represented activity.")
    g_ev.add_argument("--engagement-evidence-type", default="auto",
                      choices=["auto", "credential-capture", "offline-credential-recovery",
                               "kerberos-ticket-exposure", "pass-the-hash",
                               "remote-command-execution", "directory-replication-exposure",
                               "metasploit-session", "remote-shell", "persistence", "defense-evasion"],
                      help="Optional evidence category filter (default auto).")
    g_ev.add_argument("--engagement-evidence-max-files", type=int, default=200, metavar="N",
                      help="Maximum evidence files/members to inspect (default 200; hard maximum 2000).")
    g_ev.add_argument("--engagement-evidence-max-mb", type=int, default=100, metavar="MB",
                      help="Maximum total evidence bytes to inspect (default 100 MB; hard maximum 1024 MB).")
    g_ev.add_argument("--exercise-simulation", action="store_true",
                      help="Generate a synthetic instructor scenario with no network activity, credentials, commands, or live exploitation.")
    g_ev.add_argument("--exercise-scenario", default="ad-domain-compromise", metavar="NAME",
                      help="Synthetic scenario label used with --exercise-simulation.")

    g_llm = p.add_argument_group("LOCAL LLM INTEGRATION (v3.9.1-safe)")
    g_llm.add_argument("--local-llm", action="store_true",
                       help="Use a local Ollama model only for finding metadata extraction, dedup hints, validation planning, and remediation.")
    g_llm.add_argument("--local-llm-url", default="http://127.0.0.1:11434", metavar="URL",
                       help="Ollama endpoint (default loopback only: http://127.0.0.1:11434).")
    g_llm.add_argument("--local-llm-model", default=os.environ.get("TBHM_LOCAL_LLM_MODEL", "qwen3-cybersec:4b"), metavar="NAME",
                       help="Local Ollama model name (default qwen3-cybersec:4b or TBHM_LOCAL_LLM_MODEL).")
    g_llm.add_argument("--local-llm-context", type=int, default=0, metavar="TOKENS",
                       help="Context size; 0 uses the conservative hardware recommendation (capped at 8192).")
    g_llm.add_argument("--local-llm-timeout", type=int, default=180, metavar="SECONDS",
                       help="Per local-model batch timeout (default 180; capped at 900).")
    g_llm.add_argument("--local-llm-max-findings", type=int, default=100, metavar="N",
                       help="Maximum findings to enrich in one run (default 100; hard maximum 500).")
    g_llm.add_argument("--local-llm-status", action="store_true",
                       help="Show local hardware/Ollama/model readiness and exit; no target required.")
    g_llm.add_argument("--local-llm-setup", action="store_true",
                       help="Explicitly pull the configured Ollama model or create it from --local-llm-modelfile, then exit.")
    g_llm.add_argument("--local-llm-modelfile", metavar="PATH",
                       help="Operator-approved Ollama Modelfile used by --local-llm-setup.")
    g_llm.add_argument("--local-llm-setup-timeout", type=int, default=3600, metavar="SECONDS",
                       help="Local model setup timeout (default 3600; hard maximum 14400).")
    g_llm.add_argument("--local-llm-required", action="store_true",
                       help="Make a missing/unavailable local model a run-level failure while still writing reports.")
    g_llm.add_argument('--llm-refute', action='store_true', help='Add sequential, grounded local-LLM counterevidence review; implies --local-llm and never suppresses/confirms findings.')
    g_llm.add_argument('--llm-refute-max-findings', type=int, default=20, metavar='N', help='Refutation review limit (default 20, maximum 100); no parallel models.')

    # v3.9.4: AI Control Plane — a separate, portable, non-authoritative co-pilot.
    # State lives in $TBHM_AI_HOME (outside the tool tree) so it survives ZIP
    # replacement and laptop moves. The advisor cannot execute, mutate findings,
    # or change scope/severity; it only analyzes and proposes.
    g_ai = p.add_argument_group("AI CONTROL PLANE (v3.9.4 — portable co-pilot)")
    g_ai.add_argument('--ai-learning', metavar='PLAN', help='Execute one bounded scenario-memory, retrieval, evaluation or improvement plan; no scan target required.')
    g_ai.add_argument('--approve-ai-learning', action='store_true', help='Explicit operator approval for a learning-state mutation; grants no scan/proof authority.')
    g_ai.add_argument('--ai-learning-output', metavar='FILE', help='Create a sanitized learning result or dashboard file; refuses overwrite.')
    g_ai.add_argument('--ai-scenario-context', metavar='FILE', help='Opt-in run-to-scenario capture with explicit project, scope, license and reuse permission; requires the AI observer.')
    g_ai.add_argument("--ai-home", metavar="DIR",
                      help="Override the portable AI home (default $TBHM_AI_HOME or ~/.local/share/tbhm-ai).")
    g_ai.add_argument('--ai-knowledge-db', metavar='FILE', help='Optional SQLite/FTS5 public CVE/CWE/methodology catalog; default AI home/knowledge/public-catalog.sqlite3. Reference data has no proof authority.')
    g_ai.add_argument('--no-ai-knowledge', action='store_true', help='Disable public catalog retrieval for a baseline comparison; reviewed memory and source retrieval keep their existing controls.')
    g_ai.add_argument("--ai-advisor-model", metavar="NAME",
                      help="Co-pilot advisor model for --ai-init (defaults to --local-llm-model). "
                           "Note: --ai-model is a different, pre-existing flag for AI red-team target testing.")
    g_ai.add_argument("--ai-embedding-model", default="nomic-embed-text", metavar="NAME",
                      help="Local embedding model for retrieval (default nomic-embed-text).")
    g_ai.add_argument("--ai-embedding-workers", type=int, default=2, metavar="N",
                      help="bounded concurrent local embedding requests (1-8; default: 2)")
    g_ai.add_argument("--ai-init", action="store_true",
                      help="First-time setup: create home, init DB, pull models, index the tool, then exit.")
    g_ai.add_argument("--ai-no-pull", action="store_true",
                      help="During --ai-init, do not pull models (index/DB only).")
    g_ai.add_argument("--ai-doctor", action="store_true",
                      help="Print AI-plane health (DB, index, model, source drift, audit) and exit.")
    g_ai.add_argument("--ai-status", action="store_true", help="Alias of --ai-doctor.")
    g_ai.add_argument("--ai-index-tool", action="store_true",
                      help="Full (re)index of the current TBHM source/docs into the AI store, then exit.")
    g_ai.add_argument("--ai-sync-tool", action="store_true",
                      help="Delta re-index: only changed files. Use after any code change, then exit.")
    g_ai.add_argument("--ai-review-delta", action="store_true",
                      help="Delta re-index and ask the advisor to review the change (advisory), then exit.")
    g_ai.add_argument("--ai-propose-delta", action="store_true",
                      help="Delta re-index, review the real bounded diff, and archive a pending proposal; never applies code.")
    g_ai.add_argument("--ai-baseline", action="store_true",
                      help="Write a baseline snapshot of tracked files + counts, then exit.")
    g_ai.add_argument("--ai-migrate", action="store_true",
                      help="After a new ZIP / new laptop: migrate schema and resync source delta, then exit.")
    g_ai.add_argument("--ai-regression-check", action="store_true",
                      help="Verify home/DB/index/source-sync/audit integrity, then exit.")
    g_ai.add_argument("--ai-backup", action="store_true",
                      help="Consistent DB snapshot + portable tarball of durable state, then exit.")
    g_ai.add_argument("--ai-restore", metavar="ARCHIVE",
                      help="Restore a backup tarball into the AI home and rebuild the index, then exit.")
    g_ai.add_argument("--ai-ingest-resource", metavar="FILE",
                      help="Teach the co-pilot from a methodology/report file (stored as knowledge; no code change).")
    g_ai.add_argument("--ai-ingest-note", metavar="FILE",
                      help="Teach the co-pilot from an operator note (stored as knowledge; no code change).")
    g_ai.add_argument("--ai-ingest-folder", metavar="DIR",
                      help="Ingest all supported files in a folder as knowledge, then exit.")
    g_ai.add_argument("--ai-observe", action="store_true",
                      help="Enable the run-lifecycle observer during a scan (records events, writes a whole-run advisory).")
    g_ai.add_argument("--no-ai-observe", action="store_true",
                      help="Disable profile-enabled local run learning/observation for this scan.")
    g_ai.add_argument("--ai-control", choices=("observe", "adaptive"), default="observe",
                      help="Adaptive: let the local model prioritize already-authorized independent phase windows during this run. No scope expansion or proof authority.")
    g_ai.add_argument("--ai-control-max-decisions", type=int, choices=range(1, 9), default=3,
                      metavar="1..8", help="Maximum model scheduling decisions per invocation (default 3).")
    g_ai.add_argument("--ai-proposals", action="store_true",
                      help="List pending AI change proposals, then exit.")
    g_ai.add_argument("--ai-approve", metavar="ID", help="Approve (archive) a proposal by ID, then exit.")
    g_ai.add_argument("--ai-reject", metavar="ID", help="Reject (archive) a proposal by ID, then exit.")
    g_ai.add_argument("--ai-verify-audit", action="store_true",
                      help="Verify the tamper-evident AI audit hash-chain, then exit.")
    g_ai.add_argument("--ai-mistakes", action="store_true",
                      help="List the cross-run mistake/false-positive ledger, then exit.")
    g_ai.add_argument("--ai-lesson-approve", metavar="ID",
                      help="Approve a lesson candidate by numeric ID (promotes it to an approved lesson), then exit.")
    g_ai.add_argument("--ai-apply-plan", action="store_true",
                      help="Opt-in: narrow this run to the phases recommended by the most recent APPROVED AI next-step plan. "
                           "Only selects among phases the profile already authorizes; never expands scope or adds unsafe phases.")

    # v3.9.5: corporate intelligence, standards, data analysis and approval-gated validation.
    g_corp = p.add_argument_group("CORPORATE INTELLIGENCE & GOVERNANCE (v3.9.5)")
    g_corp.add_argument("--tool-catalog", metavar="PATH",
                        help="Override the versioned external-tool catalog JSON.")
    g_corp.add_argument("--tool-readiness", action="store_true",
                        help="Inventory registered integrations and installed executables; does not run them.")
    g_corp.add_argument("--tool-categories", metavar="LIST",
                        help="Comma-separated catalog categories for readiness/install planning.")
    g_corp.add_argument("--opsec-manifest", metavar="PATH",
                        help="Corporate OPSEC readiness manifest (YAML/JSON); records egress/persona/evidence controls without bypassing attribution controls.")
    g_corp.add_argument("--require-opsec", action="store_true",
                        help="Fail the opsec_preflight phase when required corporate OPSEC controls are incomplete.")
    g_corp.add_argument("--engagement-plan", metavar="PATH",
                        help="YAML/JSON engagement objectives, crown jewels, success criteria and stop conditions.")
    g_corp.add_argument("--approval-manifest", metavar="PATH",
                        help="Human-approved engagement manifest for approval-gated collectors/validation imports.")
    g_corp.add_argument("--standards-sync", action="store_true",
                        help="Inventory/sync the local versioned standards and intelligence knowledge directory.")
    g_corp.add_argument("--intel-enrichment", action="store_true",
                        help="Decorate CVE findings from local EPSS/KEV/OSV feeds without changing confirmation status.")
    g_corp.add_argument("--intel-dir", metavar="DIR",
                        help="Directory containing epss.csv[.gz], known_exploited_vulnerabilities.json and OSV JSON.")
    g_corp.add_argument("--intel-online", action="store_true",
                        help="Allow the explicit feed-update helper to retrieve public standards/intelligence feeds; phases remain offline by default.")

    g_osint = p.add_argument_group("CORPORATE OSINT (v3.9.5 — separate from recon/enumeration)")
    g_osint.add_argument("--corporate-osint", action="store_true",
                         help="Enable company/ownership/code/document/identity intelligence collection as candidate evidence only.")
    g_osint.add_argument("--organization-name", metavar="NAME",
                         help="Legal or trading company name used as the root OSINT entity.")
    g_osint.add_argument("--organization-aliases", metavar="LIST",
                         help="Comma-separated company names, brands or prior names.")
    g_osint.add_argument("--organization-domains-file", metavar="PATH",
                         help="Known company domains, one per line. Discovered domains never become active scope automatically.")
    g_osint.add_argument("--osint-seeds", metavar="PATH",
                         help="JSON/YAML/CSV/text seed evidence for corporate entity resolution.")
    g_osint.add_argument("--osint-results", metavar="PATH",
                         help="Import results from SpiderFoot, BBOT, Recon-ng, theHarvester, Maltego, Shodan/Censys/etc.")
    g_osint.add_argument("--osint-docs", metavar="PATH",
                         help="Directory of lawfully collected company documents for metadata extraction.")
    g_osint.add_argument("--osint-usernames", metavar="PATH",
                         help="Approved usernames/handles for person-exposure collection; requires --osint-person-collection and --osint-pii-policy.")
    g_osint.add_argument("--osint-emails", metavar="PATH",
                         help="Approved corporate emails for exposure checks; requires --osint-person-collection and --osint-pii-policy.")
    g_osint.add_argument("--osint-tools", metavar="LIST", default="asnmap,theharvester",
                         help="Comma-separated bounded live adapters (asnmap,theharvester,sherlock,maigret,exiftool). BBOT/SpiderFoot/Maltego are supported through evidence import/readiness planning.")
    g_osint.add_argument("--osint-live", action="store_true",
                         help="Run installed passive/read-only OSINT adapters against approved company seeds.")
    g_osint.add_argument("--osint-sources", metavar="LIST",
                         help="Optional source allowlist for API/manual collectors (e.g. rdap,ct,gleif,edgar,opencorporates).")
    g_osint.add_argument("--osint-max-domains", type=int, default=200, metavar="N",
                         help="Maximum candidate domains retained (default 200; hard cap 5000).")
    g_osint.add_argument("--osint-person-collection", action="store_true",
                         help="Explicitly enable approved person/identity-exposure collection with data minimization.")
    g_osint.add_argument("--osint-pii-policy", metavar="PATH",
                         help="Required PII purpose, sources, retention and prohibited-data policy for person collection.")

    g_data = p.add_argument_group("DATA & ENTITY ANALYSIS (v3.9.5)")
    g_data.add_argument("--data-analysis", action="store_true",
                        help="Run entity/relationship/timeline/confidence analysis as a separate phase.")
    g_data.add_argument("--data-input", metavar="PATH",
                        help="Additional CSV/JSON/JSONL evidence to normalize into the analytical graph.")
    g_data.add_argument("--session-har", metavar="PATH",
                        help="Offline HAR capture(s) for authenticated workflow/session modeling.")
    g_data.add_argument("--role-matrix", metavar="PATH",
                        help="YAML/JSON role/tenant/object authorization matrix for BOLA/BFLA analysis.")

    g_ext = p.add_argument_group("EXTENDED SAFE ADAPTERS (v3.9.5)")
    g_ext.add_argument("--identity-security", action="store_true",
                       help="Enable AD CS/Entra posture adapter planning and approved read-only collection.")
    g_ext.add_argument("--identity-results", metavar="PATH",
                       help="Import Certipy/PingCastle/PurpleKnight/ROADtools/Maester/ScubaGear-compatible evidence.")
    g_ext.add_argument("--identity-live", action="store_true",
                       help="Run installed read-only identity posture collectors only when the approval manifest authorizes identity-readonly.")
    g_ext.add_argument("--cloud-posture", action="store_true",
                       help="Enable cloud/Kubernetes posture adapter planning or evidence import.")
    g_ext.add_argument("--cloud-posture-results", metavar="PATH",
                       help="Import Prowler/ScoutSuite/Steampipe/Kubescape/kube-bench results.")
    g_ext.add_argument("--cloud-posture-live", action="store_true",
                       help="Run installed read-only cloud posture tools using operator-selected profiles.")
    g_ext.add_argument("--cloud-posture-tools", metavar="LIST", default="prowler,scoutsuite",
                       help="Comma-separated read-only cloud/Kubernetes posture adapters.")
    g_ext.add_argument("--k8s-manifests", metavar="PATH",
                       help="Kubernetes manifest directory for offline kube-linter/policy review.")
    g_ext.add_argument("--mobile-reverse-extended", action="store_true",
                       help="Enable JADX/YARA/DIE/objection-compatible mobile/reverse adapters.")
    g_ext.add_argument("--mobile-reverse-results", metavar="PATH",
                       help="Import extended mobile/reverse JSON/SARIF/text evidence.")
    g_ext.add_argument("--yara-rules", metavar="PATH",
                       help="Operator-approved YARA rule file/directory for local artifact triage.")

    g_validate = p.add_argument_group("PURPLE TEAM & APPROVAL-GATED VALIDATION (v3.9.5)")
    g_validate.add_argument("--purple-team", action="store_true",
                            help="Create/import ATT&CK-to-telemetry detection-validation evidence; no autonomous technique execution.")
    g_validate.add_argument("--purple-plan", metavar="PATH",
                            help="YAML/JSON technique, expected telemetry, detection and cleanup plan.")
    g_validate.add_argument("--purple-results", metavar="PATH",
                            help="Import SIEM/EDR/Sigma/YARA/Atomic/CALDERA/Stratus validation results.")
    g_validate.add_argument("--controlled-validation", action="store_true",
                            help="Enable the approval register/import plane. TBHM never auto-runs C2, phishing, coercion or disruptive actions.")
    g_validate.add_argument("--validation-plan", metavar="PATH",
                            help="YAML/JSON operator-layer action plan requiring --approval-manifest.")
    g_validate.add_argument("--validation-results", metavar="PATH",
                            help="Import signed/hashed results and cleanup status from separately executed approved actions.")
    g_validate.add_argument("--ai-supervise", action="store_true",
                            help="Ask the local non-authoritative co-pilot to review run/tool/coverage gaps.")
    g_validate.add_argument("--ai-propose-improvements", action="store_true",
                            help="Allow AI supervision to archive a proposal record for human review; never applies code.")

    g_v396 = p.add_argument_group("ENTERPRISE CONTROL PLANE & DEPTH MODULES (v3.9.6)")
    g_v396.add_argument("--agentic-manifest", action="store_true",
                        help="Generate the local non-executing MCP/agent capability and trust manifest.")
    g_v396.add_argument("--execution-orchestration", action="store_true",
                        help="Build the approval/evidence/cleanup execution state machine; never launches exploits, C2, credential attacks, phishing or persistence.")
    g_v396.add_argument("--execution-registry", metavar="PATH",
                        help="Override the declarative execution adapter registry.")
    g_v396.add_argument("--execution-plan", metavar="PATH",
                        help="YAML/JSON high-impact operator action plan. Commands/payloads are not generated by TBHM.")
    g_v396.add_argument("--execution-results", metavar="PATH",
                        help="Import signed/hashed result and cleanup records from separately approved operator infrastructure.")
    g_v396.add_argument("--execution-from-findings", action="store_true",
                        help="Create plan-only validation tasks from suitable findings; never executes the tasks.")
    g_v396.add_argument("--social-engineering", action="store_true",
                        help="Validate social/physical/wireless exercise governance and import metrics; no delivery, credential capture, MFA interception or attacks.")
    g_v396.add_argument("--social-engineering-plan", metavar="PATH",
                        help="Approved exercise plan requiring synthetic credentials, notification, takedown and cleanup controls.")
    g_v396.add_argument("--social-engineering-results", metavar="PATH",
                        help="Import sanitized GoPhish/physical/wireless exercise metrics.")
    g_v396.add_argument("--osint-depth", action="store_true",
                        help="Run/import bounded corporate OSINT depth collectors separate from recon/enumeration.")
    g_v396.add_argument("--osint-depth-results", metavar="PATH",
                        help="Import FOFA/Quake/BinaryEdge/Shodan/Censys/BGP/RDAP/job/paste/provider results.")
    g_v396.add_argument("--osint-favicon-urls", metavar="PATH",
                        help="In-scope URL list for bounded favicon hash collection.")
    g_v396.add_argument("--osint-google-dorks", action="store_true",
                        help="Generate a reviewable search-query plan; TBHM does not automate search-engine requests.")
    g_v396.add_argument("--osint-axfr", action="store_true",
                        help="Attempt bounded in-scope DNS AXFR checks only when osint_active_dns is approved.")
    g_v396.add_argument("--osint-request-budget", type=int, default=50, metavar="N",
                        help="Hard request budget for v3.9.6 live OSINT depth collectors (default 50, max 500).")
    g_v396.add_argument("--cicd-security", action="store_true",
                        help="Review local CI/CD workflows, runners, build scripts and attestation evidence.")
    g_v396.add_argument("--cicd-results", metavar="PATH",
                        help="Import actionlint/zizmor/Trivy/Checkov/SLSA/cosign-compatible evidence.")
    g_v396.add_argument("--attestation-dir", metavar="PATH",
                        help="Directory containing SLSA/in-toto/Sigstore/VEX/attestation evidence for inventory.")
    g_v396.add_argument("--cloud-identity-paths", action="store_true",
                        help="Analyze operator-supplied AWS/Azure/GCP IAM inventories for potential privilege paths, read-only.")
    g_v396.add_argument("--cloud-iam-input", metavar="PATH",
                        help="JSON file/directory containing cloud IAM policies, roles, trusts and assignments.")
    g_v396.add_argument("--compliance-catalog", metavar="PATH",
                        help="Override/extend the policy-driven compliance catalog with official or organization-specific controls.")
    g_v396.add_argument("--compliance-frameworks", metavar="LIST",
                        help="Comma-separated framework IDs to include (pci-dss,hipaa,gdpr,iso27001,nist-800-53,ptes,osstmm,vdp).")
    g_v396.add_argument("--no-ocsf", action="store_true",
                        help="Disable the parallel OCSF-oriented JSONL export.")

    g_v3971 = p.add_argument_group("CAPABILITY DEPTH & COMPATIBILITY (v3.9.7.5)")
    g_v3971.add_argument("--capability-status", nargs="?", const="all", metavar="ID[,ID]",
                         help="Print truthful capability availability and exit. Optionally filter by capability ID.")
    g_v3971.add_argument("--capability-registry", metavar="PATH",
                         help="Override the v3.9.7.5 capability registry JSON.")
    g_v3971.add_argument("--doctor", action="store_true",
                         help="Run environment/configuration/dependency diagnostics and exit.")
    g_v3971.add_argument("--doctor-output", metavar="PATH",
                         help="Also write doctor JSON to this path.")
    g_v3971.add_argument("--doctor-policy", action="append", default=[], metavar="PATH",
                         help="Validate an additional JSON/YAML policy file (repeatable).")
    g_v3971.add_argument("--doctor-evidence-store", metavar="PATH",
                         help="Check readability of an evidence-store path.")
    g_v3971.add_argument("--doctor-probe-services", action="store_true",
                         help="Perform bounded TCP availability checks for configured optional local services.")
    g_v3971.add_argument("--safe-plan", metavar="PATH",
                         help="Structured JSON plan containing only allowlisted read-only actions.")
    g_v3971.add_argument("--safe-plan-dry-run", action="store_true",
                         help="Validate and render allowlisted plan actions without executing them.")
    g_v3971.add_argument("--safe-plan-timeout", type=int, default=120, metavar="SECONDS",
                         help="Per-action timeout for safe-plan operations (1-900; default 120).")
    g_v3971.add_argument("--session-evidence", metavar="PATH",
                         help="Import authorized session/beacon JSON or CSV evidence; import-only, no C2 control.")
    g_v3971.add_argument("--session-redact-usernames", action="store_true",
                         help="Hash and redact usernames in imported session evidence.")
    g_v3971.add_argument("--session-max-records", type=int, default=10000, metavar="N",
                         help="Maximum normalized session records (default 10000, hard max 100000).")
    g_v3971.add_argument("--osint-api-provider", metavar="NAME",
                         help="Run a genuinely implemented native OSINT collector (currently: rdap).")
    g_v3971.add_argument("--osint-api-query", metavar="VALUE[,VALUE]",
                         help="Explicit domain/IP queries for the selected OSINT API provider.")
    g_v3971.add_argument("--osint-api-queries-file", metavar="PATH",
                         help="File containing one OSINT API query per line.")
    g_v3971.add_argument("--osint-api-max-queries", type=int, default=50, metavar="N",
                         help="Maximum OSINT API queries (default 50, hard max 500).")
    g_v3971.add_argument("--osint-api-timeout", type=int, default=20, metavar="SECONDS",
                         help="OSINT provider request timeout (default 20).")
    g_v3971.add_argument("--osint-api-retries", type=int, default=2, metavar="N",
                         help="Bounded OSINT provider retries (default 2).")
    g_v3971.add_argument("--osint-api-include-pii", action="store_true",
                         help="Retain provider PII fields when policy/authorization allows; redacted by default.")
    g_v3971.add_argument("--cloud-iam-max-files", type=int, default=1000, metavar="N",
                         help="Maximum IAM input files to normalize (default 1000).")
    g_v3971.add_argument("--cicd-max-files", type=int, default=5000, metavar="N",
                         help="Maximum CI/CD files to analyze (default 5000).")
    g_v3971.add_argument("--wireless-observations", metavar="PATH",
                         help="Import passive wireless observation JSON/CSV evidence.")
    g_v3971.add_argument("--wireless-location-label", default="", metavar="LABEL",
                         help="Operator-supplied location label for passive observations.")
    g_v3971.add_argument("--wireless-max-records", type=int, default=50000, metavar="N",
                         help="Maximum wireless observations (default 50000, hard max 200000).")
    g_v3971.add_argument("--adapter-definition", metavar="PATH",
                         help="Generate an unapproved proposal-only adapter design from JSON; never activates it.")

    g_add = p.add_argument_group("V3 ADD-ONS")
    g_add.add_argument("--no-addons", action="store_true",
                       help="Disable the v3 add-on phases: add_sqli, add_net_ad, add_service_primitive")
    g_add.add_argument("--addon-sqli-target", metavar="URL",
                       help="Specific parameterized URL for ADD-SQLI, e.g. https://app/path?id=1")
    g_add.add_argument("--addon-sqli-max-urls", type=int, default=30, metavar="N",
                       help="Max discovered parameterized URLs to test with ADD-SQLI when no specific URL is supplied (default: 30)")
    g_add.add_argument("--addon-sqli-delay", type=float, default=1.0, metavar="SECONDS",
                       help="Delay between ADD-SQLI HTTP requests (default: 1.0)")
    g_add.add_argument("--addon-sqli-time-delay", type=int, default=5, metavar="SECONDS",
                       help="Sleep length used by ADD-SQLI time-blind probes (default: 5)")
    g_add.add_argument("--addon-sqli-sqlmap", action="store_true",
                       help="Optional conservative sqlmap confirmation after a firm ADD-SQLI hit; no dump flags")
    g_add.add_argument("--addon-sqli-no-tls-verify", action="store_true",
                       help="Disable TLS certificate verification inside the ADD-SQLI requests engine")
    g_add.add_argument("--ad-base-dn", metavar="DN",
                       help="Base DN for ADD-NETAD read-only LDAP review, e.g. DC=corp,DC=local")
    g_add.add_argument("--ad-ldaps", action="store_true",
                       help="Use LDAPS for ADD-NETAD LDAP bind")
    g_add.add_argument("--addon-nmap-timing", default="-T3", metavar="TEMPLATE",
                       help="nmap timing template for ADD-NETAD discovery/fingerprint (default: -T3)")
    g_add.add_argument("--svc-prove-writable", action="store_true",
                       help="For ADD-SVCPRIM, prove writable paths with a temporary inert .txt marker; also requires --allow-writes")

    # Authorization (REQUIRED for non-passive profiles)
    g_auth = p.add_argument_group("AUTHORIZATION")
    g_auth.add_argument("--scope", help="File with in-scope patterns (one per line)")
    g_auth.add_argument("--exclude", help="File with out-of-scope patterns")
    g_auth.add_argument("-y", "--yes-i-am-authorized", action="store_true",
                        help="Confirm you are authorized to test the target(s)")
    g_auth.add_argument("--bug-bounty-program",
                        help="URL to the bug bounty program scope page (recorded in audit log)")

    # Output
    g_out = p.add_argument_group("OUTPUT")
    g_out.add_argument("-o", "--output", help="Output directory "
                       "(default: results/<target>_<timestamp>)")
    g_out.add_argument("-s", "--silent", action="store_true",
                       help="Suppress banner & verbose stdout")
    g_out.add_argument("--no-html", action="store_true", help="Skip HTML reports")
    g_out.add_argument("--no-exploitability-assessment", action="store_true",
                       help="Disable the default v3.9.2 evidence-grounded confirmation/exploitability enrichment.")

    # Execution control
    g_exec = p.add_argument_group("EXECUTION")
    g_exec.add_argument("--skip-recon", action="store_true",
                        help="Skip recon phase (use existing recon data in --output)")
    g_exec.add_argument("--phases", help="Comma-separated phase names to run "
                                         "(overrides profile selection)")
    g_exec.add_argument("--resume", action="store_true",
                        help="Resume an interrupted scan (requires --output to point at existing run)")
    g_exec.add_argument("--notify", help="HTTPS Discord/Slack-compatible webhook for a sanitized end-of-run summary")
    g_exec.add_argument("--dry-run", action="store_true",
                        help="Print plan and exit without running anything")
    g_exec.add_argument("--background", action="store_true",
                        help="Run detached from terminal — survives screen-off / "
                             "ssh disconnect / laptop sleep. Output goes to "
                             "<output>/run.log; tail it to follow progress.")
    g_exec.add_argument("--allow-writes", action="store_true",
                        help="Allow non-GET HTTP methods (POST/PUT/DELETE). "
                             "Default: blocked, to prevent damaging backend state.")

    # v2.11: setup / tuning knobs
    g_setup = p.add_argument_group("SETUP & TUNING (v2.11)")
    g_setup.add_argument("--setup", action="store_true",
                         help="Download/refresh nuclei templates + SecLists, then exit. "
                              "Fixes the #1 'nuclei finds nothing' cause.")
    g_setup.add_argument("--update-templates", action="store_true",
                         help="Force 'nuclei -update-templates' before scanning.")
    g_setup.add_argument("--no-bootstrap", action="store_true",
                         help="Skip the automatic template/SecLists self-heal at scan start.")
    g_setup.add_argument("--nuclei-severity", metavar="LIST",
                         help="Override nuclei severities, e.g. 'info,low,medium,high,critical'. "
                              "Applies to vuln_scan, nuclei_extended and custom_nuclei.")
    g_setup.add_argument("--nuclei-tags", metavar="LIST",
                         help="Extra nuclei tags to add to the vuln_scan sweep.")
    g_setup.add_argument("--custom-templates", metavar="DIR",
                         help="Additional nuclei template directory to run alongside the bundled set.")
    g_setup.add_argument("--include-info", action="store_true",
                         help="Capture INFO/LOW nuclei findings in vuln_scan too "
                              "(default keeps the profile floor; custom_nuclei always captures them).")
    g_setup.add_argument("--rate-limit", "--rps", type=int, dest="rate_limit_override", metavar="N",
                         help="Override global requests/sec (capped by hard limits).")
    g_setup.add_argument("--proxy", metavar="URL",
                         help="Route nuclei/HTTP probes through a proxy, e.g. http://127.0.0.1:8080 (Burp).")
    g_setup.add_argument("--threads", type=int, metavar="N",
                         help="Hint for tool concurrency where supported (capped by hard limits).")
    g_setup.add_argument("--no-cloud", action="store_true",
                         help="Skip cloud_recon + cloud_recon_extended (the slowest phases — "
                              "hundreds of bucket permutations). Useful when the target has no cloud assets.")
    g_setup.add_argument("--only-nuclei", action="store_true",
                         help="Shortcut: run only recon + the three nuclei phases + report. "
                              "Fastest path to template-based findings.")
    g_setup.add_argument("--include-ineligible", action="store_true",
                         help="Keep HackerOne Core-ineligible findings (missing headers, "
                              "cookie flags, empty buckets, SPF/DMARC, etc.) in the main report. "
                              "Default: tagged SUPPRESS and moved to the dropped-findings archive.")

    # v2.13: API fuzzing knobs
    g_api = p.add_argument_group("API FUZZING (v2.13)")
    g_api.add_argument('--api-authz-plan', metavar='PATH', help='JSON plan of explicit owned-account/object GET cases; requires target, program policy and --approve-api-authz.')
    g_api.add_argument('--approve-api-authz', action='store_true', help='Approve read-only authorization replay using the owned accounts and objects in --api-authz-plan.')
    g_api.add_argument("--api-base", metavar="URL",
                       help="Point api_fuzz directly at one API base URL "
                            "(e.g. https://api.target.com). Skips recon dependency.")
    g_api.add_argument("--api-rate", type=float, metavar="RPS", default=None,
                       help="Requests/sec for api_fuzz (default 2.0 — matches typical "
                            "'automated tool: 2 req/sec' program limits).")
    g_api.add_argument("--api-methods", metavar="LIST", default=None,
                       help="HTTP methods to fuzz per path (default GET,POST). "
                            "Write methods need --allow-writes.")
    g_api.add_argument("--api-wordlist", metavar="PATH",
                       help="Custom API path wordlist (added to the bundled one).")
    g_api.add_argument("--api-budget", type=int, metavar="N", default=None,
                       help="Max total api_fuzz requests safeguard (default 6000).")
    g_api.add_argument('--openapi-input', metavar='PATH', help='Offline Swagger 2.0/OpenAPI 3.0/3.1 JSON/YAML inventory; no server or external reference is fetched.')
    g_api.add_argument('--openapi-baseline', metavar='PATH', help='Previous API contract for an operation/security/schema diff; requires --openapi-input.')
    g_api.add_argument('--api-observations', metavar='PATH', help='HAR to compare with --openapi-input; observation coverage never implies security coverage.')
    g_api.add_argument('--web3-results', metavar='PATH', help='Import existing Slither JSON results as static review leads; no compiler or contract execution.')
    g_api.add_argument('--evaluate-labels', metavar='PATH', help='Evaluate explicit labeled fixtures (JSON array: id, vulnerable boolean, optional category); no target required.')
    g_api.add_argument('--evaluate-predictions', metavar='PATH', help='JSON array of fixture id and detected boolean; requires --evaluate-labels.')
    g_api.add_argument('--evaluation-output', metavar='PATH', help='Write labeled-fixture evaluation JSON to this path.')

    # v2.17: source-code & mobile static analysis
    g_code = p.add_argument_group("CODE & MOBILE ANALYSIS (v2.17)")
    g_code.add_argument("--code-dir", metavar="PATH",
                        help="Scan an already-downloaded source tree (open-source target/SDK) "
                             "for secrets, endpoints, and dangerous code patterns.")
    g_code.add_argument("--code-repos", metavar="URL,URL",
                        help="Comma-separated git repo URLs to clone (shallow) and scan.")
    g_code.add_argument("--code-repos-file", metavar="PATH",
                        help="File with one git repo URL per line to clone and scan.")
    g_code.add_argument("--code-scan-data-files", action="store_true",
                        help="Opt in to v2.21-compatible secret/sink scanning for JSON, XML, HTML, TXT and Markdown. Findings are prefiltered, redacted and retained only as static leads.")
    g_code.add_argument("--code-scan-extra-extensions", metavar="LIST",
                        help="Comma-separated additional text extensions to scan fully, e.g. conf,tmpl. Explicit opt-in; findings remain static leads where appropriate.")

    # v3.1: source-code intelligence (code_intel phase)
    g_ci = p.add_argument_group("SOURCE-CODE INTELLIGENCE (v3.1 — code_intel)")
    g_ci.add_argument("--github-token-env", metavar="ENV", default=None,
                      help="Env var holding a GitHub token, used to clone private --code-repos.")
    g_ci.add_argument("--domains-file", metavar="PATH",
                      help="File of in-scope domains; also used as live-map targets for code_intel.")
    g_ci.add_argument("--urls-file", metavar="PATH",
                      help="File of in-scope URLs; also used as live-map targets for code_intel.")
    g_ci.add_argument("--code-branches", metavar="LIST", default="all",
                      help="Which source branches to run: 'all' (default) or a comma list "
                           "(code_secrets,code_routes,code_auth,code_injection,code_payments,...).")
    g_ci.add_argument("--map-code-to-live", action="store_true",
                      help="Map extracted code routes onto the live domains and check reachability "
                           "(single safe request per endpoint — no payloads). Auto-on for active profiles.")
    g_ci.add_argument("--code-live-budget", type=int, default=200, metavar="N",
                      help="Max endpoint×host reachability probes for code_intel (default 200).")
    # additive --include-* switches (each enables its branch; harmless if 'all')
    for _flag, _help in [
        ("--include-dependencies", "dependency/SBOM CVE branch"),
        ("--include-ci-cd", "CI/CD pipeline risk branch"),
        ("--include-secrets", "hardcoded-secret branch"),
        ("--include-business-logic", "business-logic (price/quantity) branch"),
        ("--include-access-control", "roles/permissions branch"),
        ("--include-admin-routes", "admin-surface branch"),
        ("--include-api-routes", "route/endpoint branch"),
        ("--include-payment-flows", "payment-flow branch"),
        ("--include-upload-flows", "file-upload branch"),
        ("--include-webhook-flows", "webhook branch"),
        ("--include-auth-flows", "auth-flow branch"),
        ("--include-cloud-config", "cloud/IAM branch"),
        ("--include-mobile-api", "mobile-API branch"),
    ]:
        g_ci.add_argument(_flag, action="store_true", help=f"Enable the {_help} in code_intel.")

    # v3.2: red-team analysis, supply-chain, egress, IaC, evidence, CI
    g_v32 = p.add_argument_group("RED-TEAM ANALYSIS & OPS (v3.2)")
    g_v32.add_argument("--chain-simulate", action="store_true",
                       help="Correlate findings into multi-stage attack chains and write "
                            "chained_attack_path.md (attack_path phase; MITRE map runs regardless).")
    g_v32.add_argument("--test-egress-canary", action="store_true",
                       help="Run the safe egress/DLP reachability matrix (canary tokens only, "
                            "no data exfiltrated).")
    g_v32.add_argument("--egress-canary-host", metavar="HOST",
                       help="Your interactsh/canarytokens listener for DNS/HTTP/ICMP egress tests.")
    g_v32.add_argument("--terraform-state", metavar="PATH",
                       help="terraform.tfstate JSON for IaC drift detection (read-only).")
    g_v32.add_argument("--live-inventory", metavar="PATH",
                       help="Live cloud inventory JSON to compare against IaC (read-only).")
    g_v32.add_argument("--evidence-manifest", action="store_true",
                       help="Write a SHA256 evidence manifest + redaction scan at end of run.")
    g_v32.add_argument("--roe-ticket", metavar="ID",
                       help="Rules-of-engagement / authorization ticket ID; stamped into the run.")
    g_v32.add_argument("--ci", action="store_true",
                       help="Emit ci_summary.json + junit.xml and exit non-zero if any "
                            "CRITICAL/HIGH finding exists (pipeline gate).")

    # v3.3: coverage phases + ops
    g_v33 = p.add_argument_group("COVERAGE & SCENARIO MODULES (v3.3)")
    g_v33.add_argument("--graphql-url", metavar="URL",
                       help="Explicit GraphQL endpoint for graphql_audit (else auto-discovered).")
    g_v33.add_argument("--jwt", metavar="TOKEN",
                       help="A JWT to review in auth_modern_review (detection-only).")
    g_v33.add_argument("--saml-metadata", metavar="PATH",
                       help="SAML IdP/SP metadata XML for auth_modern_review (detection-only).")
    g_v33.add_argument("--k8s-api", metavar="URL[,URL]",
                       help="Kubernetes apiserver/kubelet base URL(s) for k8s_recon_safe.")
    g_v33.add_argument("--llm-endpoint", metavar="URL",
                       help="Authorized LLM endpoint for a benign canary prompt-injection probe.")
    g_v33.add_argument("--ad-graph", metavar="PATH",
                       help="BloodHound-style nodes/edges JSON for lateral_movement_paths.")
    g_v33.add_argument("--ot-enable", action="store_true",
                       help="Enable OT/ICS safe discovery (ot_ics_safe) — connect-only, needs approval.")
    g_v33.add_argument("--lan-discovery", action="store_true",
                       help="Enable passive mDNS/SSDP discovery in modern_protocols_discovery.")
    g_v33.add_argument('--gcp-project', help='Explicit project for read-only GCP inventory (or TBHM_GCP_PROJECT).')
    g_v33.add_argument("--cloud-profiles", metavar="LIST",
                       help="Comma list of cloud providers to inventory read-only: aws,gcp,azure.")
    g_v33.add_argument("--browser-extension-audit", metavar="PATH",
                       help="Browser-extension fleet inventory JSON to risk-review.")
    g_v33.add_argument("--ext-allowlist", metavar="PATH",
                       help="Allow-listed extension IDs for browser_extension_audit.")
    g_v33.add_argument("--ext-blocklist", metavar="PATH",
                       help="Known-bad extension IDs for browser_extension_audit.")
    g_v33.add_argument("--backup-sim", action="store_true",
                       help="Generate the backup/restore resilience tabletop (backup_restore_simulation).")
    g_v33.add_argument("--playbook-mode", action="store_true",
                       help="Emit BR-branch coverage_tracker.csv + objective cards + master_coverage.html.")

    g_ops = p.add_argument_group("OPS & SAFETY (v3.3)")
    g_ops.add_argument("--no-destructive", action="store_true",
                       help="Global gate: block mutating HTTP methods (POST/PUT/PATCH/DELETE) in "
                            "v3.3 network phases unless --force-write is also set.")
    g_ops.add_argument("--force-write", action="store_true",
                       help="Explicitly permit write/mutating operations (overrides --no-destructive).")
    g_ops.add_argument("--recheck-only", metavar="REPORT",
                       help="Remediation validation: re-run only phases tied to findings in a prior "
                            "results dir / findings JSON.")
    g_ops.add_argument("--update", action="store_true",
                       help="Self-upgrade: refresh templates/wordlists via the bootstrap step, then exit.")

    # v3.4: false-positive reduction
    g_fp = p.add_argument_group("FALSE-POSITIVE REDUCTION (v3.4)")
    g_fp.add_argument("--secret-confidence", choices=["low", "medium", "high"],
                      default="medium",
                      help="high = generic/low-entropy secrets become leads, not report findings.")
    g_fp.add_argument("--secret-min-entropy", type=float, default=3.0, metavar="BITS",
                      help="Minimum Shannon entropy for a generic secret value (default 3.0).")
    g_fp.add_argument("--exclude-tests", action="store_true", default=True,
                      help="Exclude test/mock/fixture/docs/vendor paths from code scanning (default on).")
    g_fp.add_argument("--include-tests", dest="exclude_tests", action="store_false",
                      help="Re-include test/mock/docs paths in code scanning (noisier).")
    g_fp.add_argument("--ignore-patterns-file", metavar="PATH",
                      help="File of path substrings to drop from code findings (also reads .tbhmignore).")
    g_fp.add_argument("--secret-ignore-list", metavar="PATH",
                      help="File of secret values/patterns to always suppress.")
    g_fp.add_argument("--reachable-only", action="store_true",
                      help="Downgrade code findings whose route is not in the live reachable map.")
    g_fp.add_argument("--sca-prod-only", action="store_true", default=True,
                      help="Drop devDependency CVEs; keep production deps only (default on).")
    g_fp.add_argument("--include-dev-deps", dest="sca_prod_only", action="store_false",
                      help="Include devDependency CVEs (noisier).")
    g_fp.add_argument("--dep-filter", metavar="EXPR", default=None,
                      help="Dependency gate, e.g. 'epss>=0.1 OR kev OR has_public_exploit'.")
    g_fp.add_argument("--confidence-threshold", type=float, default=0.0, metavar="N",
                      help="Only surface findings at/above this confidence (0-1) in the confirmed report.")
    g_fp.add_argument("--validate-secrets", action="store_true",
                      help="v3.6: LIVE-validate secrets that pass the static gate by making a "
                           "single read-only identity call to the provider (GitHub /user, "
                           "Slack auth.test, Stripe balance, AWS STS GetCallerIdentity, etc.). "
                           "Touches third-party APIs with found keys — AUTHORISED USE ONLY. "
                           "LIVE promotes to confirmed; DEAD downgrades to INFO.")
    g_fp.add_argument("--no-fp-filter", action="store_true",
                      help="Disable the v3.4 false-positive gate (emit everything).")
    g_fp.add_argument("--fp-review", action="store_true",
                      help="Force the fp_review phase to emit false_positives.md + dropped_findings.jsonl.")
    # per-branch disables mirroring --include-* (doc uses --no-include-<branch>)
    for _f in ("dependencies", "ci-cd", "secrets", "business-logic", "access-control",
               "admin-routes", "api-routes", "payment-flows", "upload-flows",
               "webhook-flows", "auth-flows", "cloud-config", "mobile-api"):
        g_fp.add_argument(f"--no-include-{_f}", dest=f"no_include_{_f.replace('-', '_')}",
                          action="store_true", help=f"Disable the code_intel {_f} branch.")

    g_code.add_argument("--apk", metavar="PATH",
                        help="Android .apk to analyze (strings, manifest, hardcoded keys/endpoints).")
    g_code.add_argument("--ipa", metavar="PATH",
                        help="iOS .ipa to analyze (Info.plist, binary strings, keys/endpoints).")
    g_code.add_argument("--mobile-src", metavar="PATH",
                        help="Mobile app source tree to scan (open-source app).")
    g_code.add_argument("--network-scope", metavar="PATH",
                        help="Explicit authorized IP/CIDR allowlist for port scanning. DNS association alone is insufficient; program-policy exclusions still win.")
    g_code.add_argument("--port-rate", type=int, default=10, metavar="PPS",
                        help="Port discovery packet-rate ceiling, separate from HTTP RPS (default 10, max 100).")
    g_code.add_argument("--smuggle", action="store_true",
                        help="Enable HTTP request smuggling detection (CL.TE/TE.CL timing probes). "
                             "Opt-in — detection only, but touches request parsing; confirm it's "
                             "permitted by the program first.")
    g_code.add_argument("--spec-fuzz", action="store_true",
                        help="If an OpenAPI spec is found AND schemathesis is installed, run bounded "
                             "schema-conformance fuzzing. Staging/authorized only. Opt-in.")

    # v3.9.7.3+ strict finding lifecycle, bug-bounty workspace and campaign control
    g_lifecycle = p.add_argument_group("STRICT EVIDENCE / BUG-BOUNTY / RED-TEAM CAMPAIGN")
    g_lifecycle.add_argument("--program-policy", metavar="PATH",
                             help="Reviewed JSON/YAML program policy: explicit assets, prohibited actions, methods, rates and eligibility.")
    g_lifecycle.add_argument("--identity-plan", metavar="PATH",
                             help="JSON/YAML test identity contexts (labels/roles/tenants only; never passwords or tokens).")
    g_lifecycle.add_argument("--workflow-plan", metavar="PATH",
                             help="JSON/YAML workflow invariants and planned authorization/business-logic tests.")
    g_lifecycle.add_argument("--workspace-max-requests", type=int, default=5000, metavar="N",
                             help="Maximum HAR requests imported into the redacted request workspace (default 5000).")
    g_lifecycle.add_argument("--campaign-plan", metavar="PATH",
                             help="Typed red-team campaign plan. High-impact operations remain external/import-only.")
    g_lifecycle.add_argument("--campaign-results", metavar="PATH",
                             help="Directory/file of approved, hashed, cleaned-up operation result JSON records.")
    g_lifecycle.add_argument("--redteam-campaign", action="store_true",
                             help="Enable the typed campaign register even when no campaign plan is supplied.")
    g_lifecycle.add_argument("--executor-backend", choices=("python", "go", "auto"), default="python",
                             help="Subprocess executor: streaming Python (default), optional Go helper, or automatic fallback.")
    g_lifecycle.add_argument("--max-parallel-tools", type=int, default=4, metavar="N",
                             help="Bounded independent external-tool worker pool size (default 4; still clamped by --threads).")

    # Intensity (overlay on top of profile)
    g_int = p.add_argument_group("INTENSITY (overlay on top of --profile)")
    g_int_grp = g_int.add_mutually_exclusive_group()
    g_int_grp.add_argument("--quick", action="store_const", dest="intensity", const="quick",
                           help="Quick: ~10-20 min. Critical/high nuclei only, 5K subdomain list, top-100 ports.")
    g_int_grp.add_argument("--standard", action="store_const", dest="intensity", const="standard",
                           help="Standard (default): ~1-3 hr. 20K subdomain list, top-1000 ports, jaeles.")
    g_int_grp.add_argument("--deep", action="store_const", dest="intensity", const="deep",
                           help="Deep: ~6-12 hr. 110K subdomain list, top-5000 ports, nikto + jaeles + wapiti.")
    g_int_grp.add_argument("--insane", action="store_const", dest="intensity", const="insane",
                           help="Insane: 12+ hr. 1M subdomain list, all 65K ports. Only for sanctioned pentest.")
    g_int.set_defaults(intensity="standard")

    p.add_argument("--offline", action="store_true", help="Linux x86-64 kernel-isolated local analysis; deny network sockets, including local model services. Fail closed if isolation is unavailable.")
    p.add_argument("--allow-external-enrichment", action="store_true", help="Opt in to OSV metadata queries; disabled in offline mode.")
    p.add_argument("--version", action="version", version=VERSION)
    parsed = p.parse_args()
    # Defaults must not silently defeat the portable model lock; an explicit
    # CLI model selection must not silently be ignored by that lock either.
    parsed._local_llm_model_explicit = any(a == '--local-llm-model' or a.startswith('--local-llm-model=') for a in sys.argv[1:])
    parsed._ai_advisor_model_explicit = any(a == '--ai-advisor-model' or a.startswith('--ai-advisor-model=') for a in sys.argv[1:])
    parsed._ai_embedding_model_explicit = any(a == '--ai-embedding-model' or a.startswith('--ai-embedding-model=') for a in sys.argv[1:])
    return parsed


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def collect_targets(args) -> list[str]:
    """Build the final target list from CLI flags."""
    targets = []
    if args.domain:
        targets.append(args.domain.strip().lower())
    if args.url:
        targets.append(args.url.strip())
    if args.list:
        with open(args.list) as f:
            for line in f:
                t = line.strip()
                if t and not t.startswith("#"):
                    targets.append(t.lower())
    if args.urls:
        with open(args.urls) as f:
            for line in f:
                u = line.strip()
                if u and not u.startswith("#"):
                    targets.append(u)
    # v3.1: --domains-file / --urls-file also seed targets (used by code_intel live map)
    for attr in ("domains_file", "urls_file"):
        path = getattr(args, attr, None)
        if path and os.path.isfile(path):
            with open(path) as f:
                for line in f:
                    t = line.strip()
                    if t and not t.startswith("#"):
                        targets.append(t if t.startswith("http") else t.lower())
    # Deduplicate while preserving order
    seen = set(); out = []
    dupes = 0
    for t in targets:
        if t not in seen:
            seen.add(t); out.append(t)
        else:
            dupes += 1
    # v3.3: input validation — surface duplicate/invalid entries
    if dupes:
        print(f"\033[33m[WARN]\033[0m input validation: {dupes} duplicate target entry(ies) ignored")
    import re as _re
    bad = [t for t in out if not t.startswith("http")
           and not _re.match(r"^[a-z0-9.\-*_/:]+$", t)]
    if bad:
        print(f"\033[33m[WARN]\033[0m input validation: {len(bad)} target(s) look malformed: {bad[:3]}")
    return out


def _phases_from_prior(path: str) -> list[str]:
    """v3.3: resolve which phases produced findings in a prior run.
    Accepts a results directory (with tbhm.db) or a findings JSON/JSONL file."""
    import json as _json
    import sqlite3
    p = Path(path)
    phases = set()
    try:
        if p.is_dir():
            db = p / "tbhm.db"
            if db.exists():
                conn = sqlite3.connect(str(db))
                for (ph,) in conn.execute("SELECT DISTINCT phase FROM findings"):
                    if ph:
                        phases.add(ph)
                conn.close()
        elif p.suffix in (".json", ".jsonl") and p.exists():
            text = p.read_text()
            try:
                data = _json.loads(text)
                items = data if isinstance(data, list) else data.get("findings", [])
            except Exception:
                items = [_json.loads(l) for l in text.splitlines() if l.strip()]
            for it in items:
                if isinstance(it, dict) and it.get("phase"):
                    phases.add(it["phase"])
    except Exception:
        pass
    return sorted(phases)


def collect_excludes(args) -> list[str]:
    if not args.exclude:
        return []
    with open(args.exclude) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def collect_includes(args) -> list[str]:
    # v2.15: --scope in-scope allowlist (was parsed but never enforced).
    if not getattr(args, "scope", None):
        return []
    with open(args.scope) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def _detach_and_exit(args):
    """
    v2.4: respawn ourselves detached from the controlling terminal so that:
      - laptop sleep / screen-off does NOT pause us (SIGSTOP from session)
      - ssh disconnect does NOT kill us (SIGHUP)
      - terminal close does NOT kill us
    Implementation: setsid + fork + redirect stdio to a log file.
    Also runs caffeinate (macOS) / systemd-inhibit (Linux) to prevent sleep
    of the laptop itself if applicable.
    """
    import sys
    import subprocess

    # Build the output dir up-front so we can predict where logs go
    if args.output:
        out_dir = Path(args.output)
    else:
        # Mirror make_output_dir logic enough to find the path
        target_arg = args.domain or args.url or "scan"
        slug = target_arg.replace("https://", "").replace("http://", "").split("/")[0]
        slug = re.sub(r"[^\w.\-]", "_", slug)
        out_dir = Path("results") / f"{slug}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "run.log"

    # Rebuild the command without --background
    cmd = [sys.executable, str(Path(__file__).resolve())]
    skip_next = False
    for arg in sys.argv[1:]:
        if skip_next:
            skip_next = False
            continue
        if arg == "--background":
            continue
        cmd.append(arg)
    # Ensure output is fixed so user can find logs
    if "-o" not in cmd and "--output" not in cmd:
        cmd += ["-o", str(out_dir)]

    # Prefix with sleep-inhibitor for the OS (best effort)
    if sys.platform == "darwin":
        if subprocess.run(["which", "caffeinate"], capture_output=True).returncode == 0:
            cmd = ["caffeinate", "-i", "-w", "$$"] + cmd   # -i: prevent idle sleep
    elif sys.platform.startswith("linux"):
        if subprocess.run(["which", "systemd-inhibit"], capture_output=True).returncode == 0:
            cmd = ["systemd-inhibit",
                   "--what=sleep:idle",
                   "--who=TBHM",
                   "--why=long-running security scan",
                   "--mode=block"] + cmd

    # Open log and double-fork to fully detach
    env = dict(os.environ)
    env["TBHM_DETACHED"] = "1"
    logfile = open(log_path, "a", buffering=1)
    logfile.write(f"\n==== TBHM background scan started {datetime.utcnow().isoformat()} ====\n")
    logfile.write(f"command: {' '.join(cmd)}\n\n")
    logfile.flush()

    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=logfile, stderr=subprocess.STDOUT,
            start_new_session=True,        # setsid — fully detached
            env=env, close_fds=True,
        )
    except FileNotFoundError as e:
        print(f"\033[31m[ERR]\033[0m background spawn failed: {e}", file=sys.stderr)
        sys.exit(2)

    print(f"\033[32m[✓]\033[0m TBHM running in background (PID {proc.pid})")
    print(f"    Log:     tail -f {log_path}")
    print(f"    Results: {out_dir}")
    print(f"    Stop:    kill {proc.pid}")
    print()
    print("    This scan will survive:")
    print("      • screen-off / lid close")
    print("      • SSH disconnect")
    print("      • terminal close")
    sys.exit(0)


def _apply_thread_override(args, profile: dict) -> int:
    """Return the effective bounded tool-concurrency hint.

    The option is deliberately a hint because each external tool has different
    semantics.  It is capped independently of profile data and forced to one
    for passive/zero-touch profiles.
    """
    requested = getattr(args, "threads", None)
    hard = profile.get("hard_limits", {}) or {}
    maximum = max(1, min(int(hard.get("max_threads", 50) or 50), 100))
    default = max(1, min(int((profile.get("runtime", {}) or {}).get("threads", 10) or 10), maximum))
    rate = profile.get("rate_limit", {}) or {}
    passive = (str(profile.get("name", "")).lower() == "passive_only"
               or profile.get("active_probes") is False
               or float(rate.get("global_rps", 0) or 0) <= 0)
    if passive:
        effective = 1
    elif requested is None:
        effective = default
    else:
        effective = max(1, min(int(requested), maximum))
        if int(requested) != effective and not getattr(args, "silent", False):
            print(f"\033[33m[WARN]\033[0m requested threads {requested} clamped to {effective}")
    profile.setdefault("runtime", {})["threads"] = effective
    return effective


def _apply_rate_limit_override(args, profile: dict) -> dict:
    """Apply an operator rate ceiling without defeating framework maximums.

    Returns the profile for convenient unit testing. Passive/zero-touch profiles
    remain at zero even when the option is supplied.
    """
    if getattr(args, "rate_limit_override", None) is None:
        return profile
    rate = profile.setdefault("rate_limit", {})
    requested = max(1, int(args.rate_limit_override))
    hard = profile.get("hard_limits", {}) or {}
    max_global = max(1, int(hard.get("max_global_rps", 50)))
    max_target = max(1, int(hard.get("max_per_target_rps", 20)))
    passive = (str(profile.get("name", "")).lower() == "passive_only"
               or float(rate.get("global_rps", 0) or 0) <= 0
               or profile.get("active_probes") is False)
    if passive:
        rate["global_rps"] = 0
        rate["per_target_rps"] = 0
        rate["hard_cap"] = 0
        if not getattr(args, "silent", False):
            print("\033[33m[WARN]\033[0m --rate-limit ignored because the selected profile is passive/zero-touch")
        return profile
    effective = min(requested, max_global)
    existing_target = int(rate.get("per_target_rps", effective) or effective)
    rate["global_rps"] = effective
    rate["hard_cap"] = effective
    rate["per_target_rps"] = max(1, min(existing_target, effective, max_target))
    if requested != effective and not getattr(args, "silent", False):
        print(f"\033[33m[WARN]\033[0m requested rate {requested} rps clamped to framework maximum {effective} rps")
    return profile


_LOCAL_ONLY_PHASES = {
    'spec_scan', 'web3', 'attack_path',
    "preflight", "diagnostics", "package_verification", "code_scan", "code_intel", "sast_tooling",
    "code_security_tooling", "source_orchestration_tooling", "mobile_scan",
    "mobile_tooling", "supply_chain_review", "firmware_reverse_safe", "firmware_tooling_extended",
    "reverse_triage", "reverse_static_analysis", "reverse_ir_analysis", "reverse_taint_analysis",
    "reverse_cross_language", "reverse_sandbox_analysis", "reverse_dynamic_evidence",
    "reverse_dynamic_mapping", "reverse_symbolic_analysis", "reverse_fuzzing",
    "reverse_crash_triage", "reverse_diff_analysis", "reverse_campaign_index",
    "reverse_family_analysis", "reverse_correlation",
    "reverse_engineering_tooling", "privesc_audit_tooling",
    "engagement_evidence_review", "local_llm_triage",
    "exploitability_assessment", "correlation", "verify", "fp_review",
    "llm_run_analysis", "ai_supervision", "toolchain_readiness",
    "standards_knowledge_sync", "engagement_objectives", "opsec_preflight",
    "corporate_osint", "osint_depth_collectors", "authenticated_session_model", "identity_security_tooling",
    "cloud_posture_tooling", "cloud_identity_path_analysis", "mobile_reverse_extended",
    "vulnerability_intelligence_enrichment", "data_analysis_intelligence",
    "purple_team_validation", "execution_orchestration_plan", "controlled_validation_plane",
    "redteam_campaign_control", "redteam_final_summary", "bug_bounty_workspace",
    "strict_finding_validation", "test_coverage_ledger",
    "social_engineering_governance", "ci_cd_supply_chain_security",
    "compliance_reporting_extended", "ocsf_normalization", "agentic_control_manifest",
    "integration_adapter_proposal", "session_beacon_import", "passive_wireless_inventory",
    "safe_plan_execution", "osint_api_collectors", "report", "evidence_finalize",
}


def _local_only_target(args) -> str | None:
    """Permit explicit local artifact/source workflows without a fake web target.

    The exception is deliberately narrow: the operator must supply --phases and
    every selected phase must be in the local/import/report allowlist.  This
    prevents a default full profile from accidentally running network phases
    against the placeholder label.
    """
    raw = str(getattr(args, "phases", "") or "")
    phases = {p.strip() for p in raw.split(",") if p.strip()}
    if not phases:
        # Explicit local/import feature flags are strong enough intent to build a
        # narrow local phase subset. This avoids requiring a fake network target
        # while preventing the default full profile from running against the
        # placeholder label.
        # Build additive local reverse/firmware workflows from the supplied
        # artifact flags. Unlike a user-authored --phases override, this
        # automatically generated set must include every requested adapter.
        selected_set = {"preflight", "report", "evidence_finalize"}
        for requested, selected in (
            ('openapi_input', {'spec_scan'}), ('web3_results', {'web3'}),
            ('code_dir', {'code_scan', 'code_intel'}), ('code_repos', {'code_scan', 'code_intel'}),
            ('code_repos_file', {'code_scan', 'code_intel'}),
            ('mobile_src', {'mobile_scan'}), ('apk', {'mobile_scan'}), ('ipa', {'mobile_scan'})):
            if getattr(args, requested, None):
                selected_set.update(selected)
        firmware_local = any([
            getattr(args, "firmware", None), getattr(args, "firmware_rootfs", None),
            getattr(args, "firmware_extract", False),
        ])
        firmware_tools_local = any([
            getattr(args, "firmware_tooling", False), getattr(args, "emba", False),
            getattr(args, "emba_results", None), getattr(args, "routersploit_root", None),
            getattr(args, "routersploit_catalog", False), getattr(args, "routersploit_results", None),
            getattr(args, "firmware_tool_results", None),
        ])
        reverse_local = any([
            getattr(args, "binary_path", None), getattr(args, "reverse_results", None),
            getattr(args, "reverse_ir_results", None), getattr(args, "reverse_dynamic_results", None),
            getattr(args, "reverse_symbolic_results", None), getattr(args, "reverse_tooling", False),
            getattr(args, "reverse_static", False), getattr(args, "reverse_ir", False),
            getattr(args, "reverse_taint", False), getattr(args, "reverse_cross_language", False),
            getattr(args, "reverse_sandbox", False), getattr(args, "reverse_dynamic_map", False),
            getattr(args, "reverse_symbolic", False), getattr(args, "reverse_fuzz_harness", False),
            getattr(args, "reverse_crash_results", None), getattr(args, "reverse_diff_old", None),
            getattr(args, "reverse_diff_new", None), getattr(args, "reverse_campaign_store", None),
            getattr(args, "reverse_family_path", None),
        ])
        if firmware_local:
            selected_set.add("firmware_reverse_safe")
        if len(selected_set) > 3 and getattr(args, 'local_llm', False):
            selected_set.add('local_llm_triage')
        if len(selected_set) > 3 and getattr(args, 'chain_simulate', False):
            selected_set.add('attack_path')
        if firmware_tools_local:
            selected_set.add("firmware_tooling_extended")
        if reverse_local:
            selected_set.update({
                "reverse_triage", "reverse_static_analysis", "reverse_ir_analysis", "reverse_taint_analysis",
                "reverse_cross_language", "reverse_sandbox_analysis", "reverse_dynamic_evidence",
                "reverse_dynamic_mapping", "reverse_symbolic_analysis", "reverse_fuzzing",
                "reverse_crash_triage", "reverse_diff_analysis", "reverse_campaign_index",
                "reverse_family_analysis", "reverse_correlation", "reverse_engineering_tooling",
            })
        if len(selected_set) > 3:
            selected = [name for name in PHASE_ORDER if name in selected_set]
            args.phases = ",".join(selected)
            args._auto_local_phases = True
            phases = set(selected)
        else:
            direct_phase_sets = [
                ('openapi_input', ['preflight', 'spec_scan', 'report', 'evidence_finalize']),
                ('web3_results', ['preflight', 'web3', 'report', 'evidence_finalize']),
                ('code_dir', ['preflight', 'code_scan', 'code_intel', 'report', 'evidence_finalize']),
                ('code_repos', ['preflight', 'code_scan', 'code_intel', 'report', 'evidence_finalize']),
                ('code_repos_file', ['preflight', 'code_scan', 'code_intel', 'report', 'evidence_finalize']),
                ('mobile_src', ['preflight', 'mobile_scan', 'report', 'evidence_finalize']),
                ('apk', ['preflight', 'mobile_scan', 'report', 'evidence_finalize']),
                ('ipa', ['preflight', 'mobile_scan', 'report', 'evidence_finalize']),
                ("campaign_plan", ["preflight", "redteam_campaign_control", "redteam_final_summary",
                                   "test_coverage_ledger", "report", "evidence_finalize"]),
                ("campaign_results", ["preflight", "redteam_campaign_control", "redteam_final_summary",
                                      "test_coverage_ledger", "report", "evidence_finalize"]),
                ("workflow_plan", ["preflight", "bug_bounty_workspace", "test_coverage_ledger",
                                   "report", "evidence_finalize"]),
                ("identity_plan", ["preflight", "bug_bounty_workspace", "test_coverage_ledger",
                                   "report", "evidence_finalize"]),
                ("program_policy", ["preflight", "bug_bounty_workspace", "test_coverage_ledger",
                                    "report", "evidence_finalize"]),
                ("verify_package", ["preflight", "package_verification", "report", "evidence_finalize"]),
                ("safe_plan", ["preflight", "safe_plan_execution", "report", "evidence_finalize"]),
                ("session_evidence", ["preflight", "session_beacon_import", "report", "evidence_finalize"]),
                ("wireless_observations", ["preflight", "passive_wireless_inventory", "report", "evidence_finalize"]),
                ("adapter_definition", ["preflight", "integration_adapter_proposal", "report", "evidence_finalize"]),
                ("cloud_iam_input", ["preflight", "cloud_identity_path_analysis", "report", "evidence_finalize"]),
                ("cicd_results", ["preflight", "ci_cd_supply_chain_security", "report", "evidence_finalize"]),
                ("attestation_dir", ["preflight", "ci_cd_supply_chain_security", "report", "evidence_finalize"]),
                ("osint_api_provider", ["preflight", "osint_api_collectors", "report", "evidence_finalize"]),
                ("emba_results", ["preflight", "firmware_tooling_extended", "report", "evidence_finalize"]),
                ("routersploit_results", ["preflight", "firmware_tooling_extended", "report", "evidence_finalize"]),
                ("firmware_tool_results", ["preflight", "firmware_tooling_extended", "report", "evidence_finalize"]),
            ]
            for attribute, selected in direct_phase_sets:
                if getattr(args, attribute, None):
                    args.phases = ",".join(selected)
                    args._auto_local_phases = True
                    phases = set(selected)
                    break
    if not phases or not phases.issubset(_LOCAL_ONLY_PHASES):
        return None
    local_inputs = any(getattr(args, name, None) for name in (
        "code_dir", "code_repos", "code_repos_file", "apk", "ipa", "mobile_src",
        'openapi_input', 'web3_results',
        "firmware", "binary_path", "reverse_results", "reverse_ir_results",
        "reverse_dynamic_results", "reverse_symbolic_results", "reverse_cross_language_root",
        "reverse_vm_image", "reverse_crash_results", "reverse_diff_old", "reverse_diff_new",
        "reverse_campaign_store", "reverse_campaign_artifacts", "reverse_family_path", "verify_package",
        "sast_results", "code_security_results",
        "source_orchestration_results", "mobile_results",
        "privesc_results", "engagement_evidence", "tool_catalog",
        "opsec_manifest", "engagement_plan", "intel_dir", "osint_seeds",
        "osint_results", "osint_docs", "data_input", "session_har", "role_matrix",
        "identity_results", "cloud_posture_results", "k8s_manifests",
        "mobile_reverse_results", "purple_plan", "purple_results",
        "validation_plan", "validation_results", "execution_plan", "execution_results",
        "social_engineering_plan", "social_engineering_results", "osint_depth_results",
        "osint_favicon_urls", "cicd_results", "attestation_dir", "cloud_iam_input",
        "compliance_catalog", "safe_plan", "session_evidence", "wireless_observations",
        "adapter_definition", "osint_api_queries_file", "program_policy", "identity_plan",
        "workflow_plan", "campaign_plan", "campaign_results", "firmware_rootfs", "emba_results",
        "routersploit_results", "firmware_tool_results", "routersploit_root",
    ))
    return "local-analysis.invalid" if local_inputs else None


def make_output_dir(args, targets) -> Path:
    if args.output:
        out = Path(args.output)
    else:
        slug = targets[0].replace("https://", "").replace("http://", "")
        slug = slug.replace("/", "_").replace(":", "_")[:60]
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        out = Path("results") / f"{slug}_{ts}"
    out.mkdir(parents=True, exist_ok=True)
    try:
        out.chmod(0o700)
    except Exception:
        pass
    for sub in ("findings", "recon", "scans", "evidence", "repro", "logs", "PER-FINDING"):
        child = out / sub
        child.mkdir(exist_ok=True)
        try:
            child.chmod(0o700)
        except Exception:
            pass
    return out


def import_phase(name):
    """Lazy import a phase module — keeps startup snappy and missing tools soft-fail."""
    try:
        mod = __import__(f"phases.{name}", fromlist=["run"])
        return mod
    except Exception as e:
        print(f"\033[31m[ERR]\033[0m failed to load phase '{name}': {e}", file=sys.stderr)
        return None


def _load_approved_plan_phases(args) -> list:
    """Return recommended_next_phases from the most recent APPROVED AI next-step
    plan, or []. Reads only operator-approved proposals from the portable AI home;
    it never runs the model and never returns anything the operator did not approve."""
    import json as _json
    from core.ai_plane import home as _home
    ai_home = _home.get(getattr(args, "ai_home", None), create=False)
    accepted = ai_home.proposals_accepted
    if not accepted.exists():
        return []
    newest = None
    newest_mtime = -1.0
    for pj in accepted.glob("AI-PROP-*/proposal.json"):
        try:
            data = _json.loads(pj.read_text())
        except Exception:
            continue
        if "next-step" not in (data.get("problem", "").lower()) and "direction" not in (data.get("problem", "").lower()):
            continue
        mt = pj.stat().st_mtime
        if mt > newest_mtime:
            newest_mtime, newest = mt, data
    if not newest:
        return []
    phases: list[str] = []
    for item in newest.get("evidence", []):
        if isinstance(item, dict) and "recommended_next_phases" in item:
            vals = item.get("recommended_next_phases") or []
            phases = [str(v) for v in vals if isinstance(v, str)]
            break
    return phases


# ──────────────────────────────────────────────────────────────────────────────
# Pre-flight legal check (Section 8.1 of the design doc)
# ──────────────────────────────────────────────────────────────────────────────
def preflight_legal_check(args, profile, targets):
    """
    Section 8.1: required inputs before any active scan.
    Implements K1 (Hard Limits coded in) and K3 (Pre-action permission prompt).
    """
    if profile["name"] == "passive_only":
        return  # zero-touch — no auth needed
    if not args.yes_i_am_authorized:
        print("\033[31m[LEGAL]\033[0m Active profile requires explicit authorization.")
        print("       Pass -y / --yes-i-am-authorized AND ideally --bug-bounty-program <url>")
        print("       Or use --profile passive_only for zero-touch reconnaissance.")
        sys.exit(2)
    print(f"\033[32m[LEGAL]\033[0m Authorization confirmed by user.")
    if args.bug_bounty_program:
        print(f"        Program: {args.bug_bounty_program}")
    print(f"        Targets: {len(targets)}  Profile: {profile['name']}")
    print(f"        Hard limits ENFORCED (no destructive payloads, no DoS, no real data exfil, no credential theft/persistence).")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    if args.ai_control == 'adaptive' and args.no_ai_observe:
        print('ERROR: --ai-control adaptive requires the audited AI plane; remove --no-ai-observe.', file=sys.stderr)
        return 2
    if getattr(args, 'api_authz_plan', None):
        if not (args.domain or args.list or args.url or args.urls):
            print('ERROR: --api-authz-plan requires an explicit target.', file=sys.stderr)
            return 2
        if not args.approve_api_authz or not args.program_policy or args.offline:
            print('ERROR: authorization replay requires --approve-api-authz, --program-policy and online mode.', file=sys.stderr)
            return 2
        if not args.phases:
            args.phases = 'preflight,authenticated_session_model,strict_finding_validation,test_coverage_ledger,compliance_coverage,report,evidence_finalize'
    if getattr(args, 'offline', False):
        try:
            from core.offline_isolation import install
            install()
        except Exception as exc:
            print('ERROR: offline isolation unavailable: '+str(exc), file=sys.stderr)
            return 77
    if getattr(args, 'evaluate_labels', None) or getattr(args, 'evaluate_predictions', None):
        try:
            if not args.evaluate_labels or not args.evaluate_predictions:
                raise ValueError('both --evaluate-labels and --evaluate-predictions are required')
            from core.evaluation import evaluate
            payload = evaluate(args.evaluate_labels, args.evaluate_predictions)
            encoded = json.dumps(payload, indent=2)+'\n'
            if args.evaluation_output:
                Path(args.evaluation_output).expanduser().write_text(encoded, encoding='utf-8')
            print(encoded)
            return 0 if payload['status'] == 'complete' else 2
        except Exception as exc:
            print(json.dumps({'evaluation_error': str(exc)}))
            return 2
    if getattr(args, 'llm_refute', False):
        args.local_llm = True
    if getattr(args, 'web3_results', None):
        args.web3 = True
    if (getattr(args, 'openapi_baseline', None) or getattr(args, 'api_observations', None)) and not getattr(args, 'openapi_input', None):
        print('ERROR: API baseline/observations require --openapi-input.', file=sys.stderr)
        return 2
    # Maintenance runs precede the scan broker, so enforce offline intent here.
    if getattr(args, 'offline', False):
        args.ai_no_pull = True
        if any(getattr(args, name, False) for name in ('setup', 'update', 'local_llm_setup')):
            print('ERROR: --offline cannot be combined with a network setup/update/model-pull command.', file=sys.stderr)
            return 2

    if args.list_profiles:
        for name, meta in list_profiles(ROOT / "profiles").items():
            print(f"  \033[36m{name:20}\033[0m {meta.get('description', '')}")
        return 0

    if getattr(args, "capability_status", None):
        try:
            from core import capability_registry as _capreg
            registry = _capreg.load(getattr(args, "capability_registry", None))
            raw = str(args.capability_status or "all")
            wanted = [] if raw.lower() == "all" else [x.strip() for x in raw.split(",") if x.strip()]
            payload = _capreg.summary(registry, capability_ids=wanted)
            if wanted and not payload.get("capabilities"):
                payload["error"] = "no requested capability IDs were found"
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return 0 if not payload.get("error") else 2
        except Exception as exc:
            print(json.dumps({"capability_registry_error": f"{type(exc).__name__}: {exc}"}, indent=2))
            return 2

    if getattr(args, "doctor", False):
        try:
            from core import doctor as _doctor
            payload = _doctor.run(
                output_dir=getattr(args, "output", None),
                capability_path=getattr(args, "capability_registry", None),
                policy_files=getattr(args, "doctor_policy", None),
                evidence_store=getattr(args, "doctor_evidence_store", None),
                probe_services=bool(getattr(args, "doctor_probe_services", False)),
            )
            destination = getattr(args, "doctor_output", None)
            if destination:
                out_path = Path(destination).expanduser()
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return 0 if payload.get("ok") else 2
        except Exception as exc:
            print(json.dumps({"doctor_error": f"{type(exc).__name__}: {exc}"}, indent=2))
            return 2

    # v3.9.1: local model management is part of TBHM itself and does not
    # require a scan target. Model weights remain local and operator-managed.
    if getattr(args, "local_llm_status", False) or getattr(args, "local_llm_setup", False):
        from core.llm_local import local_llm_status, setup_local_model
        if getattr(args, "local_llm_setup", False):
            result = setup_local_model(args)
            print(json.dumps({"setup": result}, indent=2, ensure_ascii=False))
            if not result.get("ok"):
                return 2
        status = local_llm_status(args)
        print(json.dumps({"local_llm": status}, indent=2, ensure_ascii=False))
        return 0 if status.get("ready") else 2

    # v3.9.4: AI Control Plane maintenance/knowledge commands. Like the local-LLM
    # management above, these do not require a scan target. State lives in the
    # portable $TBHM_AI_HOME; the advisor is non-authoritative and never executes.
    try:
        from core.ai_plane import cli as _ai_cli
        if _ai_cli.requested(args):
            return _ai_cli.handle(args, ROOT)
    except Exception as _ai_exc:
        print(json.dumps({"ai_plane_error": str(_ai_exc)}, indent=2))
        return 2

    # v2.11: --setup downloads/refreshes nuclei templates + SecLists then exits.
    # v3.3: --update is an alias for the same self-heal refresh.
    if args.setup or getattr(args, "update", False):
        from core import bootstrap
        if not args.silent:
            print(BANNER)
        def _setup_log(level, phase, msg):
            colors = {"INFO": "\033[36m", "WARN": "\033[33m", "ERR": "\033[31m",
                      "OK": "\033[32m"}
            c = colors.get(level, ""); end = "\033[0m" if c else ""
            print(f"  {c}{level:5}{end} {msg}")
        print("\033[36m[SETUP]\033[0m Self-healing nuclei templates + SecLists…\n")
        status = bootstrap.bootstrap_all(log=_setup_log, force=True)
        nt = status["nuclei_templates"]
        print()
        print(f"  nuclei templates : {nt.get('count')} ({nt.get('action')})")
        print(f"  seclists         : {status['seclists'].get('path')} ({status['seclists'].get('action')})")
        print(f"  custom templates : {status['custom_templates'].get('count')} bundled")
        print("\n\033[32m[SETUP]\033[0m Done. Re-run your scan normally now.")
        return 0

    # v2.4: detach from terminal so screen-off / ssh disconnect doesn't kill us
    if args.background and not os.environ.get("TBHM_DETACHED"):
        _detach_and_exit(args)
        return 0   # never reached

    if not args.silent:
        print(BANNER)

    # Load profile
    try:
        profile = load_profile(ROOT / "profiles", args.profile)
    except ProfileError as e:
        print(f"\033[31m[ERR]\033[0m {e}", file=sys.stderr)
        return 2

    # Apply intensity overlay
    from core import intensity as _intensity
    profile = _intensity.apply(profile, args.intensity)

    # v2.23: set the process-wide safe-writes policy ONCE, so context-free core
    # helpers (diff_engine, verifier, etc.) also enforce the gate. This is what
    # makes the README's "mutating methods blocked by default" true globally.
    from core import safe_writes as _sw
    _sw.configure(bool(getattr(args, "allow_writes", False)), profile.get("name", "authorized_safe"))

    # v3.9.4.1: user rate is a ceiling, not a replacement for independent
    # framework maximums; passive profiles remain zero-touch.
    profile = _apply_rate_limit_override(args, profile)
    effective_threads = _apply_thread_override(args, profile)
    profile.setdefault("runtime", {})
    profile["runtime"]["threads"] = effective_threads
    profile["runtime"]["executor_backend"] = getattr(args, "executor_backend", "python")
    profile["runtime"]["max_parallel_tools"] = max(1, min(
        int(getattr(args, "max_parallel_tools", 4) or 4), effective_threads))

    profile.setdefault('runtime', {})['offline'] = bool(getattr(args, 'offline', False))
    if getattr(args, 'offline', False):
        profile['active_probes'] = False
        profile['send_payloads'] = False
    # Collect targets
    try:
        targets = collect_targets(args)
        input_excludes = collect_excludes(args)
        input_includes = collect_includes(args)
    except (OSError, UnicodeError) as exc:
        print(f"ERROR: Cannot read target/scope input: {exc}. "
              "Create the referenced file or use -u with an explicit authorized URL.", file=sys.stderr)
        return 2
    if not targets:
        local_label = _local_only_target(args)
        if local_label:
            targets = [local_label]
            if not args.silent:
                print("\033[36m[LOCAL]\033[0m explicit local-only phase set accepted without a network target")
        else:
            print("\033[31m[ERR]\033[0m No target specified. Use -d / -l / -u / -U, or an explicit local-only --phases set with a local artifact/source input.", file=sys.stderr)
            return 2

    # Pre-flight legal check
    preflight_legal_check(args, profile, targets)

    # Setup output dir
    output_dir = make_output_dir(args, targets)

    # Initialize core systems
    limits = HardLimits(profile)
    storage = Storage(output_dir / "tbhm.db")
    monitor = ResourceMonitor()
    runner = Runner(profile, limits, monitor, output_dir)
    runner.threads = effective_threads

    # Build context
    ctx = Ctx(args, profile, storage, runner, limits, monitor, output_dir)
    ctx.threads = effective_threads
    ctx.targets = targets
    ctx.program_policy = None
    if getattr(args, "program_policy", None):
        try:
            from core import program_policy as _program_policy
            ctx.program_policy = _program_policy.load(args.program_policy)
            storage.save_program_policy(ctx.program_policy)
            # A program's reviewed limit is another ceiling, never an increase.
            policy_rps = float(ctx.program_policy.get("max_requests_per_second") or 0)
            if policy_rps > 0:
                current_rps = float(profile.get("rate_limit", {}).get("global_rps", policy_rps) or policy_rps)
                profile.setdefault("rate_limit", {})["global_rps"] = min(current_rps, policy_rps)
            ctx.log("OK", "program_policy", f"loaded policy {ctx.program_policy.get('policy_id')}")
        except Exception as exc:
            ctx.log("ERR", "program_policy", f"policy rejected; active execution remains fail-closed: {exc}")
            return 2
    # v3.4: preload ignore patterns (--ignore-patterns-file / .tbhmignore / --secret-ignore-list)
    try:
        from core import fp_filters
        code_roots = []
        if getattr(args, "code_dir", None):
            code_roots.append(args.code_dir)
        ctx._ignore_patterns = fp_filters.load_ignore_patterns(args, code_roots)
        if ctx._ignore_patterns:
            ctx.log("INFO", "main", f"FP ignore patterns loaded: {len(ctx._ignore_patterns)}")
    except Exception:
        ctx._ignore_patterns = []
    ctx.scope_excludes = input_excludes
    ctx.scope_includes = input_includes
    from core.scope import Scope
    ctx.scope = Scope(ctx.scope_includes, ctx.scope_excludes)
    if ctx.scope_includes:
        ctx.log("INFO", "scope",
                f"in-scope allowlist active ({len(ctx.scope_includes)} pattern(s)) — "
                f"hosts not matching will be skipped")
    if ctx.scope_excludes:
        ctx.log("INFO", "scope",
                f"out-of-scope denylist active ({len(ctx.scope_excludes)} pattern(s))")

    # v2.4: tell storage which hosts are in-scope so noise_filter spares them
    try:
        from core.targets import get_root_domains, get_domains
        ctx._in_scope_hosts_temp = set(get_root_domains(ctx)) | set(get_domains(ctx))
        storage._in_scope_hosts = ctx._in_scope_hosts_temp
    except Exception:
        pass

    # Persist run metadata
    storage.save_run({
        "started_at": ctx.start_ts,
        "profile": profile["name"],
        "targets": targets,
        "excludes": ctx.scope_excludes,
        "args": vars(args),
        "bug_bounty_program": args.bug_bounty_program or "",
    })

    # Determine phase list
    if args.phases:
        phases = [p.strip() for p in args.phases.split(",") if p.strip()]
    else:
        # v2.8: profile YAML can override the phase list via a top-level `phases:` key
        profile_phases = profile.get("phases") if isinstance(profile, dict) else None
        if profile_phases and isinstance(profile_phases, list):
            phases, unknown_profile_phases, duplicate_profile_phases = canonicalize_profile_phases(profile_phases)
            ctx.log("INFO", "main", f"  (profile defines a canonicalized phase subset: {len(phases)} phases)")
            if unknown_profile_phases:
                ctx.log("WARN", "main", "profile contains unknown phase(s), ignored: " + ", ".join(unknown_profile_phases))
            if duplicate_profile_phases:
                ctx.log("WARN", "main", "profile contains duplicate phase(s), de-duplicated: " + ", ".join(duplicate_profile_phases))
        else:
            phases = PROFILE_PHASES.get(profile["name"], PHASE_ORDER)
        if not args.web3 and "web3" in phases:
            phases = [p for p in phases if p != "web3"]
        if args.skip_recon:
            phases = [p for p in phases if p not in ("recon", "discovery")]
        # v2.11: optional phase gates
        if getattr(args, "no_cloud", False):
            phases = [p for p in phases if p not in ("cloud_recon", "cloud_recon_extended")]
        if getattr(args, "only_nuclei", False):
            keep = ("recon", "discovery", "vuln_scan", "nuclei_extended",
                    "custom_nuclei", "report")
            phases = [p for p in phases if p in keep]
        if getattr(args, "no_addons", False):
            phases = [p for p in phases if p not in ("add_sqli", "add_net_ad", "add_service_primitive")]

        # v2.22/v3.0: keep old web/API behavior clean. Enterprise red-team phases run
        # only with --profile authorized_redteam or explicit --redteam. If the user
        # supplies --phases, we do not filter because they asked directly.
        if profile.get("name") not in {"authorized_redteam", "authorized_assumed_breach"} and not getattr(args, "redteam", False):
            phases = [p for p in phases if p not in REDTEAM_PHASES]

        # v3.9 additive opt-in phases. Explicit feature flags should work even
        # with compact/custom profiles, while --phases remains the final manual
        # override and is therefore not modified here.
        def _insert_before_report(name: str, after: str | None = None):
            if name in phases:
                return
            if after and after in phases:
                phases.insert(phases.index(after) + 1, name)
            elif "report" in phases:
                phases.insert(phases.index("report"), name)
            else:
                phases.append(name)

        if getattr(args, "ad_access", False) or getattr(args, "ad_access_results", None):
            _insert_before_report("ad_access_assessment", "internal_ad_tooling")
        if getattr(args, "engagement_evidence", None) or getattr(args, "exercise_simulation", False):
            _insert_before_report("engagement_evidence_review", "ad_access_assessment")
        if getattr(args, "session_evidence", None):
            _insert_before_report("session_beacon_import", "engagement_evidence_review")
        if getattr(args, "source_orchestration", False) or getattr(args, "source_orchestration_results", None):
            _insert_before_report("source_orchestration_tooling", "code_security_tooling")
        if getattr(args, "verify_package", None):
            _insert_before_report("package_verification", "diagnostics")
        if getattr(args, "tool_readiness", False):
            _insert_before_report("toolchain_readiness", "diagnostics")
        if getattr(args, "opsec_manifest", None) or getattr(args, "require_opsec", False):
            _insert_before_report("opsec_preflight", "toolchain_readiness")
        if getattr(args, "engagement_plan", None):
            _insert_before_report("engagement_objectives", "opsec_preflight")
        if getattr(args, "standards_sync", False):
            _insert_before_report("standards_knowledge_sync", "engagement_objectives")
        if (getattr(args, "corporate_osint", False) or getattr(args, "osint_results", None)
                or getattr(args, "osint_seeds", None) or getattr(args, "osint_docs", None)):
            _insert_before_report("corporate_osint", "external_perimeter_tooling")
        if (getattr(args, "osint_depth", False) or getattr(args, "osint_depth_results", None)
                or getattr(args, "osint_favicon_urls", None) or getattr(args, "osint_google_dorks", False)
                or getattr(args, "osint_axfr", False)):
            _insert_before_report("osint_depth_collectors", "corporate_osint")
        if getattr(args, "osint_api_provider", None):
            _insert_before_report("osint_api_collectors", "osint_depth_collectors")
        if getattr(args, "identity_security", False) or getattr(args, "identity_results", None):
            _insert_before_report("identity_security_tooling", "ad_access_assessment")
        if getattr(args, "mobile_reverse_extended", False) or getattr(args, "mobile_reverse_results", None):
            _insert_before_report("mobile_reverse_extended", "mobile_tooling")
        if getattr(args, "cicd_security", False) or getattr(args, "cicd_results", None) or getattr(args, "attestation_dir", None):
            _insert_before_report("ci_cd_supply_chain_security", "supply_chain_review")
        if getattr(args, "session_har", None) or getattr(args, "role_matrix", None) or getattr(args, 'api_authz_plan', None):
            _insert_before_report("authenticated_session_model", "smuggling")
        if (getattr(args, "cloud_posture", False) or getattr(args, "cloud_posture_results", None)
                or getattr(args, "k8s_manifests", None)):
            _insert_before_report("cloud_posture_tooling", "cloud_inventory_safe")
        if getattr(args, "cloud_identity_paths", False) or getattr(args, "cloud_iam_input", None):
            _insert_before_report("cloud_identity_path_analysis", "cloud_posture_tooling")
        if (getattr(args, "execution_orchestration", False) or getattr(args, "execution_plan", None)
                or getattr(args, "execution_results", None) or getattr(args, "execution_from_findings", False)):
            _insert_before_report("execution_orchestration_plan", "attack_path")
        if getattr(args, "safe_plan", None):
            _insert_before_report("safe_plan_execution", "execution_orchestration_plan")
        if getattr(args, "controlled_validation", False) or getattr(args, "validation_plan", None) or getattr(args, "validation_results", None):
            _insert_before_report("controlled_validation_plane", "execution_orchestration_plan")
        if getattr(args, "purple_team", False) or getattr(args, "purple_plan", None) or getattr(args, "purple_results", None):
            _insert_before_report("purple_team_validation", "controlled_validation_plane")
        if (getattr(args, "social_engineering", False) or getattr(args, "social_engineering_plan", None)
                or getattr(args, "social_engineering_results", None)):
            _insert_before_report("social_engineering_governance", "wireless_physical_soc")
        if getattr(args, "wireless_observations", None):
            _insert_before_report("passive_wireless_inventory", "wireless_physical_soc")
        _insert_before_report("compliance_reporting_extended", "compliance_coverage")
        if getattr(args, "data_analysis", False) or getattr(args, "data_input", None):
            _insert_before_report("data_analysis_intelligence", "playbook_integration")
        if getattr(args, "agentic_manifest", False):
            _insert_before_report("agentic_control_manifest", "toolchain_readiness")
        if getattr(args, "adapter_definition", None):
            _insert_before_report("integration_adapter_proposal", "agentic_control_manifest")
        if not getattr(args, "no_ocsf", False):
            _insert_before_report("ocsf_normalization", "ai_supervision")
        if getattr(args, "ai_supervise", False) or getattr(args, "ai_propose_improvements", False):
            _insert_before_report("ai_supervision", "data_analysis_intelligence")
        firmware_requested = any([
            getattr(args, "firmware", None), getattr(args, "firmware_rootfs", None),
            getattr(args, "firmware_extract", False),
        ])
        if firmware_requested:
            _insert_before_report("firmware_reverse_safe", "supply_chain_review")
        firmware_tooling_requested = any([
            getattr(args, "firmware_tooling", False), getattr(args, "emba", False),
            getattr(args, "emba_results", None), getattr(args, "routersploit_catalog", False),
            getattr(args, "routersploit_results", None), getattr(args, "firmware_tool_results", None),
        ])
        if firmware_tooling_requested:
            _insert_before_report("firmware_tooling_extended", "firmware_reverse_safe")

        reverse_requested = any([
            getattr(args, "binary_path", None), getattr(args, "reverse_results", None),
            getattr(args, "reverse_ir_results", None), getattr(args, "reverse_dynamic_results", None),
            getattr(args, "reverse_symbolic_results", None), getattr(args, "reverse_tooling", False),
            getattr(args, "reverse_static", False), getattr(args, "reverse_ir", False),
            getattr(args, "reverse_taint", False), getattr(args, "reverse_cross_language", False),
            getattr(args, "reverse_sandbox", False), getattr(args, "reverse_dynamic_map", False),
            getattr(args, "reverse_symbolic", False), getattr(args, "reverse_fuzz_harness", False),
            getattr(args, "reverse_crash_results", None), getattr(args, "reverse_diff_old", None),
            getattr(args, "reverse_diff_new", None), getattr(args, "reverse_campaign_store", None),
            getattr(args, "reverse_family_path", None),
        ])
        if reverse_requested:
            for _name, _after in [
                ("reverse_triage", "firmware_tooling_extended" if "firmware_tooling_extended" in phases else "firmware_reverse_safe"),
                ("reverse_static_analysis", "reverse_triage"),
                ("reverse_ir_analysis", "reverse_static_analysis"),
                ("reverse_taint_analysis", "reverse_ir_analysis"),
                ("reverse_cross_language", "reverse_taint_analysis"),
                ("reverse_sandbox_analysis", "reverse_cross_language"),
                ("reverse_dynamic_evidence", "reverse_sandbox_analysis"),
                ("reverse_dynamic_mapping", "reverse_dynamic_evidence"),
                ("reverse_symbolic_analysis", "reverse_dynamic_mapping"),
                ("reverse_fuzzing", "reverse_symbolic_analysis"),
                ("reverse_crash_triage", "reverse_fuzzing"),
                ("reverse_diff_analysis", "reverse_crash_triage"),
                ("reverse_campaign_index", "reverse_diff_analysis"),
                ("reverse_family_analysis", "reverse_campaign_index"),
                ("reverse_correlation", "reverse_family_analysis"),
                ("reverse_engineering_tooling", "reverse_correlation"),
            ]:
                _insert_before_report(_name, _after)
        if getattr(args, "local_llm", False):
            _insert_before_report("local_llm_triage", "verify")
        if getattr(args, 'openapi_input', None):
            _insert_before_report('spec_scan', 'code_intel')
        if getattr(args, 'web3_results', None):
            _insert_before_report('web3', 'correlation')
        if not getattr(args, "no_exploitability_assessment", False):
            _insert_before_report("exploitability_assessment", "local_llm_triage" if getattr(args, "local_llm", False) else "verify")
        if getattr(args, "intel_enrichment", False) or getattr(args, "intel_dir", None):
            _insert_before_report("vulnerability_intelligence_enrichment", "exploitability_assessment")
        if getattr(args, "fp_review", False):
            _insert_before_report("fp_review", "exploitability_assessment")

        phases, _runtime_unknown, _runtime_duplicates = canonicalize_profile_phases(phases)
        if _runtime_unknown:
            ctx.log("WARN", "main", "runtime phase selection contains unknown phase(s): " + ", ".join(_runtime_unknown))

    # v3.3: --recheck-only — re-run only the phases that produced findings in a
    # prior run, plus verify/report, for remediation validation.
    recheck = getattr(args, "recheck_only", None)
    if recheck:
        prior_phases = _phases_from_prior(recheck)
        if prior_phases:
            keep = set(prior_phases) | {"preflight", "recon", "verify", "report",
                                        "evidence_finalize"}
            phases = [p for p in phases if p in keep]
            ctx.log("INFO", "main",
                    f"  (--recheck-only: {len(prior_phases)} phase(s) from prior findings)")
        else:
            ctx.log("ERR", "main", f"--recheck-only: no phases resolved from {recheck}; execution blocked")
            return 2

    # v4: opt-in application of an APPROVED AI next-step plan. This can only
    # narrow/reorder among phases the profile already authorizes — it never adds
    # a phase that was not already in the authorized set, never expands scope, and
    # never enables high-impact actions. Two human actions are required: approving
    # the plan proposal, and passing --ai-apply-plan.
    if getattr(args, "ai_apply_plan", False) and not args.phases:
        try:
            recommended = _load_approved_plan_phases(args)
        except Exception as _pe:
            recommended = []
            ctx.log("WARN", "main", f"--ai-apply-plan: could not load approved plan: {_pe}")
        if recommended:
            authorized = set(phases)
            always = {"preflight", "report", "evidence_finalize"}
            applied = [p for p in phases if p in (set(recommended) | always)]
            dropped = [p for p in phases if p not in applied]
            skipped_unauth = [p for p in recommended if p not in authorized]
            if applied:
                phases = applied
                ctx.log("INFO", "main",
                        f"  (--ai-apply-plan: narrowed to {len(applied)} approved-plan phase(s); "
                        f"dropped {len(dropped)})")
                if skipped_unauth:
                    ctx.log("WARN", "main",
                            "--ai-apply-plan: ignored plan phase(s) not authorized by this profile/scope: "
                            + ", ".join(skipped_unauth))
        else:
            ctx.log("INFO", "main", "--ai-apply-plan: no approved plan found; using normal phase selection")

    ctx.log("INFO", "main", f"Output dir : {output_dir}")
    ctx.log("INFO", "main", f"Profile    : {profile['name']}")
    ctx.log("INFO", "main", f"Intensity  : {args.intensity}  "
            f"({_intensity.INTENSITIES[args.intensity]['description']})")
    ctx.log("INFO", "main", f"Targets    : {len(targets)}")
    ctx.log("INFO", "main", f"Phases     : {' → '.join(phases)}")

    from core.execution_ledger import input_fingerprint
    effective_fingerprint = input_fingerprint(args, profile, targets)
    old_context = storage.conn.execute("SELECT status FROM phase_state WHERE phase='__context_v410'").fetchone()
    resume_compatible = bool(old_context and old_context['status'] == effective_fingerprint)
    ctx.execution_ledger.context_fingerprint = effective_fingerprint
    if not args.dry_run:
        storage.set_phase_state('__context_v410', effective_fingerprint)
    ctx.execution_ledger.plan = list(phases)
    ctx.execution_ledger.flush()
    if args.dry_run:
        ctx.log("INFO", "main", "DRY RUN — exiting without execution.")
        return 0

    # A required gate precedes bootstrap, observers and every optional phase,
    # even under --phases/--resume. Do not route the partial report through
    # phases.report: its optional enrichment can invoke the local model.
    required_opsec_done = False
    if getattr(args, "require_opsec", False):
        try:
            mandatory = import_phase("opsec_preflight")
            if mandatory is None or not callable(getattr(mandatory, "run", None)):
                raise RuntimeError("required OPSEC module unavailable")
            mandatory.run(ctx)
            storage.mark_phase_done("opsec_preflight")
            required_opsec_done = True
        except Exception as exc:
            storage.set_phase_state("opsec_preflight", "failed")
            (output_dir / "PARTIAL_RUN.json").write_text(json.dumps({
                "status": "incomplete", "failed_gate": "opsec_preflight",
                "reason": str(exc), "exit_code": 2,
            }, indent=2))
            ctx.log("ERR", "opsec_preflight", f"required control failed: {exc}")
            try:
                Reporter(ctx).write_all()
            except Exception as report_exc:
                ctx.log("ERR", "report", f"partial report failed: {report_exc}")
            return 2

    # v2.11: auto self-heal — make sure nuclei templates + SecLists exist before
    # any scanning phase runs. This is the fix for "nuclei finds nothing".
    if not args.no_bootstrap and not args.offline and getattr(args, "update_templates", False) and "passive_only" != profile["name"]:
        from core import bootstrap
        force_tpl = bool(getattr(args, "update_templates", False))
        try:
            bootstrap.ensure_nuclei_templates(log=ctx.log, force=force_tpl)
            bootstrap.ensure_seclists(log=ctx.log)
            bootstrap.ensure_custom_templates(log=ctx.log)
        except Exception as e:
            ctx.log("WARN", "bootstrap", f"self-heal skipped: {e}")

    # Install signal handler so Ctrl+C still writes a partial report
    interrupted = {"flag": False}
    def _sigint(signum, frame):
        interrupted["flag"] = True
        try: ctx.runner.cancel()
        except Exception: pass
        ctx.log("WARN", "main", "Interrupt received — cancelling active tools and finalizing safely…")
    signal.signal(signal.SIGINT, _sigint)

    # v4: the co-pilot observer is ON BY DEFAULT so every run is recorded and
    # learned from. It is fully defensive: with no local model configured it still
    # records structured events, ingests the (sanitized) run log, and updates the
    # cross-run mistake ledger — only the model-written advisories are skipped.
    # It never mutates findings, severity, confirmation, scope, or code.
    from core.request_guard import activate as activate_request_guard
    activate_request_guard(ctx)
    ai_obs = None
    _plane = None
    ai_observe_enabled = not bool(getattr(args, "no_ai_observe", False))
    if ai_observe_enabled:
        try:
            from core.ai_plane import build_plane
            from core.ai_plane.observer import RunObserver
            _plane = build_plane(args, create=True, need_runtime=True)
            ai_obs = RunObserver(
                store=_plane.store, embedder=_plane.embedder,
                vector_index=_plane.vector_index, advisor=_plane.advisor,
                proposal_gate=_plane.gate, audit=_plane.audit, runtime=_plane.runtime,
                log=ctx.log)
            ctx._ai_tbhm_version = DISPLAY_VERSION
            ai_obs.on_run_start(ctx)
        except Exception as _oe:
            ctx.log("WARN", "ai-observer", f"disabled: {_oe}")
            ai_obs = None

    # Explicit opt-in: the controller only prioritizes ready, already-selected
    # phase IDs. The ordinary dispatcher and authorization gates still execute.
    from core.ai_plane.runtime_control import RuntimeController
    ai_controller = RuntimeController(ctx, _plane, ai_obs)

    # Execute phases
    phase_timings = {}
    phase_details = {}
    run_wall_started = time.monotonic()
    phase_failures = []
    pending_phases = list(phases)
    while pending_phases:
        try:
            ph = ai_controller.choose(pending_phases)
        except Exception as exc:
            ctx.log('WARN', 'ai-control', f'decision persistence failed; original order retained: {type(exc).__name__}')
            ph = pending_phases[0]
        pending_phases.remove(ph)
        if ph == "opsec_preflight" and required_opsec_done:
            continue
        if ph == "evidence_finalize":
            continue  # Finalize once, after every producer and the CI completeness gate.
        if interrupted["flag"]:
            ctx.log("WARN", "main", f"Skipping remaining phases due to interrupt.")
            break
        ctx.execution_ledger.current_phase = ph
        if ph == "preflight":
            continue  # already done
        # v2.20: --resume skips phases already marked done in this output's DB.
        # v4-fix: reporting/aggregation phases read the WHOLE findings DB, so on a
        # resumed run they must ALWAYS regenerate — otherwise the report reflects the
        # pre-resume state and omits everything the resumed phases just found.
        _ALWAYS_RERUN_ON_RESUME = {
            # Core reporting/aggregation — always regenerate against the full DB.
            "report", "evidence_finalize", "dashboard", "fp_review",
            "exploitability_assessment", "strict_finding_validation",
            "test_coverage_ledger", "ocsf_normalization",
            "compliance_reporting_extended",
            # Derived/post-processing phases that also read the WHOLE findings DB;
            # if any upstream scan phase re-ran under --resume, these are stale too.
            "attack_path", "compliance_coverage", "coverage_map",
            "playbook_integration", "data_analysis_intelligence",
            "ai_supervision", "llm_run_analysis", "local_llm_triage",
            "vulnerability_intelligence_enrichment", "execution_orchestration_plan",
        }
        if (getattr(args, "resume", False) and resume_compatible and storage.is_phase_done(ph)
                and ph not in _ALWAYS_RERUN_ON_RESUME):
            ctx.execution_ledger.record(kind="phase", status="resumed", reason="previous successful completion")
            ctx.log("INFO", ph, "── skipped (already done, --resume) ──")
            continue
        mod = import_phase(ph)
        if not mod or not hasattr(mod, "run"):
            ctx.log("WARN", ph, "phase module not implemented yet — skipping")
            phase_failures.append(ph)
            continue
        ctx.log("INFO", ph, "── starting ──")
        phase_wall_started = time.monotonic()
        ctx.execution_ledger.record(kind='phase_state', status='RUNNING')
        if ai_obs:
            try: ai_obs.before_phase(ctx, ph)
            except Exception: pass
        t0 = time.monotonic()
        phase_budget = max(1, min(86400, float(profile.get('runtime', {}).get('phase_timeout_seconds', 3600))))
        ctx._phase_deadline = ctx.runner._phase_deadline = t0+phase_budget
        ctx._phase_lifecycle_active = ctx.runner._phase_lifecycle_active = True
        stop_state = None
        # v3.9.4 fix: distinguish success from failure. A crashed phase must NOT
        # be marked done, otherwise --resume silently skips it on the next run.
        phase_ok = True
        from core.lifecycle import PhaseStopped
        try:
            mod.run(ctx)
            from core.execution_ledger import sanitize_output
            sanitize_output(ctx.output)
            if ctx.execution_ledger.issues(ph):
                phase_ok = False
                phase_failures.append(ph)
        except PhaseStopped as e:
            phase_ok = False
            stop_state = e.state
            phase_failures.append(ph)
            ctx.execution_ledger.record(kind='phase_stop', status=e.state.lower(), reason=e.reason)
            ctx.log('WARN', ph, e.reason)
        except Exception as e:
            phase_ok = False
            phase_failures.append(ph)
            ctx.log("ERR", ph, f"phase crashed: {e}")
            # H1: tool health — log and continue, don't kill the run
        finally:
            ctx._phase_lifecycle_active = ctx.runner._phase_lifecycle_active = False
            ctx._phase_deadline = ctx.runner._phase_deadline = None
        elapsed = time.monotonic() - t0
        phase_timings[ph] = round(elapsed, 2)
        if ai_obs:
            try: ai_obs.after_phase(ctx, ph, phase_ok, elapsed)
            except Exception: pass
        if ctx.execution_ledger.issues(ph) or interrupted['flag']:
            phase_ok = False
            if ph not in phase_failures:
                phase_failures.append(ph)
        wall = time.monotonic()-phase_wall_started
        phase_details[ph] = {'body_seconds':round(elapsed, 3),
            'observer_and_dispatch_seconds':round(max(0, wall-elapsed), 3),
            'wall_seconds':round(wall, 3),
            'state':stop_state or ('CANCELLED' if interrupted['flag'] else ('COMPLETED' if phase_ok else 'PARTIAL')),
            'issue_count':len(ctx.execution_ledger.issues(ph))}
        ctx.phase_state['phase_outcomes'] = phase_details
        ctx.phase_state['run_status'] = 'interrupted' if interrupted['flag'] else ('partial' if phase_failures else 'running')
        ctx.execution_ledger.record(kind="phase", status="executed" if phase_ok else "partial", seconds=round(elapsed, 3))
        if phase_ok:
            ctx.log("OK", ph, f"── done ({elapsed:.1f}s) ──")
            storage.mark_phase_done(ph)
        else:
            ctx.log("WARN", ph,
                    f"── failed ({elapsed:.1f}s) — not marked done; --resume will retry ──")
            try:
                storage.set_phase_state(ph, "failed")
            except Exception:
                pass

        try:
            ai_controller.completed(ph)
        except OSError as exc:
            ctx.log('WARN', 'ai-control', f'execution receipt could not be updated: {type(exc).__name__}')

    # v3.3: performance profile for large engagements
    try:
        ranked = dict(sorted(phase_timings.items(), key=lambda kv: kv[1], reverse=True))
        (output_dir / "phase_timings.json").write_text(json.dumps(
            {"total_seconds": round(sum(phase_timings.values()), 2),
             "per_phase": ranked, 'per_phase_details':phase_details,
             'phase_loop_wall_seconds':round(time.monotonic()-run_wall_started, 3),
             'ai_runtime_control_seconds':round(sum(d['seconds'] for d in ai_controller.decisions), 3),
             'semantics':'total_seconds/per_phase retain body time; per_phase_details include observer work'}, indent=2))
    except Exception:
        pass

    # Always run report at the end (even after interrupt)
    if "report" not in [p for p in phases if not interrupted["flag"]]:
        ctx.execution_ledger.current_phase = 'report'
        try:
            mod = import_phase("report")
            if mod and hasattr(mod, "run"):
                mod.run(ctx)
        except Exception as e:
            ctx.log("ERR", "report", f"report failed: {e}")
            phase_failures.append("report")

    # v3.9.4: AI observer end-of-run — mirror confirmed findings into the portable
    # store, write the whole-run advisory, and record lesson candidates. Advisory
    # only; never mutates findings/scope/code. Runs after report by design.
    if ai_obs:
        ctx.execution_ledger.current_phase = 'evidence_finalize'
        try:
            ai_obs.on_run_end(ctx, 'interrupted' if interrupted['flag'] else ('incomplete' if phase_failures else 'awaiting_finalization'))
        except Exception as _oe:
            ctx.log("WARN", "ai-observer", f"on_run_end skipped: {_oe}")

    # Summary
    counts = storage.severity_counts()
    print()
    print("┌─ SCAN SUMMARY " + "─" * 44 + "┐")
    print(f"│ Output:   {str(output_dir):<55}│")
    print(f"│ Targets:  {len(targets):<55}│")
    print(f"│ Findings: {sum(counts.values()):<55}│")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if counts.get(sev):
            print(f"│   {sev:<10} {counts[sev]:<48}│")
    _sup = getattr(ctx, "_suppressed_count", 0)
    if _sup:
        print(f"│   {'SUPPRESS':<10} {str(_sup) + ' (HackerOne Core-ineligible, in archive)':<48}│")
    print("└" + "─" * 60 + "┘")
    if _sup:
        print(f"  {_sup} ineligible finding(s) archived → see dropped_findings.jsonl "
              f"(re-include with --include-ineligible)")
    print()
    print(f"Open the HTML report: file://{(output_dir / 'REPORT.html').resolve()}")
    if getattr(args, "notify", None):
        try:
            from core.notifier import send_completion
            _n_ok, _n_detail = send_completion(
                args.notify, version=VERSION,
                profile=profile.get("name", "unknown"),
                status='interrupted' if interrupted['flag'] else ('incomplete' if phase_failures else 'awaiting_finalization'),
                counts=counts,
            )
            ctx.log("OK" if _n_ok else "WARN", "notify", _n_detail)
        except Exception as _ne:
            ctx.log("WARN", "notify", f"notification skipped: {type(_ne).__name__}")
    if getattr(args, "local_llm_required", False) and ctx.phase_state.get("local_llm_required_failed"):
        phase_failures.append("local_llm_required")
    from phases import evidence_finalize
    exit_code = 2 if phase_failures or interrupted["flag"] else 0
    try:
        evidence_finalize.run(ctx)
        if getattr(args, "ci", False):
            if interrupted["flag"]:
                phase_failures.append("interrupted")
            if evidence_finalize._incomplete_gate(ctx, phase_failures):
                print("CI gate: scan incomplete — exiting non-zero.")
                exit_code = 2
            if ctx.phase_state.get("ci_gate_fail"):
                print("CI gate: confirmed CRITICAL/HIGH findings present — exiting non-zero.")
                exit_code = 2
        storage.complete_run()
        from core.execution_ledger import sanitize_output
        sanitize_output(ctx.output)
        ctx.execution_ledger.current_phase = "evidence_finalize"
        ctx.execution_ledger.record(kind="run", status="completed" if exit_code == 0 else "incomplete", exit_code=exit_code)
        from core.evidence_manifest import build_manifest, verify_manifest
        manifest = build_manifest(ctx.output, roe_ticket=getattr(args, "roe_ticket", "") or "")
        if not verify_manifest(ctx.output)["passed"]:
            raise RuntimeError("delivery snapshot failed its integrity check")
        print(f"Delivery snapshot: {ctx.output / manifest['snapshot_dir']}")
    except Exception as exc:
        ctx.log("ERR", "evidence_finalize", f"delivery failed: {exc}")
        exit_code = 2
    finally:
        if ai_obs:
            try:
                ai_obs.finalize_status('interrupted' if interrupted['flag'] else ('completed' if exit_code == 0 else 'incomplete'))
            except Exception as exc:
                ctx.log('WARN', 'ai-observer', f'final status could not be persisted: {exc}')
            finally:
                _plane.close()
        from core.request_guard import deactivate
        deactivate()
        storage.close()
    return exit_code



if __name__ == "__main__":
    sys.exit(main())
