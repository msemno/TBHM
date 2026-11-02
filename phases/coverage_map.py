"""Phase: coverage_map — ingest the FULL field-playbook objective taxonomy so the
governance matrix reflects every branch AND every sub-topic in the .md, not only
the 34 branch titles.

The playbook's Section 5 / 5B / additive appendices define, per branch, a set of
sub-topics; each sub-topic is worked through the Section-4 loop. That is the real
coverage skeleton (42 branch groups, 632 distinct sub-topics). This phase embeds
that skeleton verbatim (auto-extracted from the playbook) and:

  1. writes redteam/00_governance/objective_coverage_map.{json,csv} listing every
     (branch, subtopic) pair with an automation hint and an evidence status;
  2. cross-references which sub-topics an automated TBHM phase actually exercised
     in this run (via SUBTOPIC_PHASE_MAP) so the report can show, sub-topic by
     sub-topic, what was automatically touched vs. what is manual-only;
  3. augments branch_matrix.json (additively — existing keys untouched) with the
     per-branch sub-topic list and counts so the reporter can render deeper detail.

Nothing here is intrusive. It is pure bookkeeping/coverage accounting. It never
marks anything "Safe": untouched sub-topics are "Not Tested — manual".
"""
from __future__ import annotations
import json
from core import redteam_utils as RT

PLAYBOOK_TAXONOMY = {
    "BR01": ("Pre-Engagement, ROE, Legal, and Safety Control", ["authorization", "scope boundaries", "rules of engagement", "third-party permissions", "testing windows", "data handling", "emergency contacts", "stakeholder map", "stop conditions", "change freeze", "executive alignment", "client evidence approval", "insurance and legal", "privacy constraints", "communication cadence", "site access", "credential handling", "tool approval", "intrusive action approvals", "final acceptance"]),
    "BR02": ("Program Management, Planning, and Coverage Matrix", ["work breakdown", "branch prioritization", "risk-based scheduling", "resource plan", "test calendar", "daily standup", "coverage tracker", "evidence tracker", "asset owner mapping", "dependency mapping", "blocked item tracking", "change log", "quality gate", "finding triage", "severity calibration", "defect lifecycle", "purple-team slots", "report milestones", "executive updates", "closure readiness"]),
    "BR03": ("Physical Security and On-Site Operations", ["reception access", "visitor process", "badge checks", "escort process", "floor access", "server room access", "tailgating controls", "clean desk", "unlocked screens", "printer areas", "network jack exposure", "meeting room devices", "shipping/receiving", "trash/recycling handling", "restricted zones", "after-hours process", "emergency exits", "contractor process", "evidence photography"]),
    "BR04": ("Network Architecture and Segmentation", ["network diagrams", "routing", "firewalls", "management networks", "guest networks", "camera networks", "server networks", "user networks", "printer networks", "egress controls", "segmentation validation"]),
    "BR05": ("Asset Inventory and Service Discovery", ["service discovery", "certificate inventory", "web title inventory", "management interface discovery", "unknown asset review", "shadow IT", "external exposure", "device ownership", "asset criticality", "unsupported systems", "duplicate IPs", "rogue DHCP", "rogue DNS", "list hygiene", "baseline snapshots", "inventory reconciliation"]),
    "BR06": ("Active Directory and Identity Security", ["domain inventory", "forest/trust inventory", "user inventory", "group inventory", "admin group review", "service accounts", "password policy", "lockout policy", "delegation review", "local admin model", "privileged access process", "stale accounts", "tiering model", "identity evidence"]),
    "BR07": ("Endpoint and User Machine Security", ["macOS endpoints", "patch state", "local firewall", "disk encryption", "local admin", "browser security", "remote tools", "screen lock", "software inventory", "browser extensions", "credential storage review", "shared folders", "logging", "hardening baseline", "user behavior observation"]),
    "BR08": ("Windows and Linux Server Infrastructure", ["patch state", "services", "local users", "admin model", "remote access", "web services", "database clients", "scheduled tasks", "backup agents", "monitoring agents", "certificates", "logging", "configuration drift", "hardening baseline", "server evidence"]),
    "BR09": ("Web Applications", ["asset mapping", "technology fingerprinting", "authentication", "authorization", "session management", "input validation", "file upload", "business logic", "headers", "rate limits", "error handling", "admin panels", "payment flows", "content security policy", "logging", "privacy"]),
    "BR10": ("APIs and Microservices", ["authentication", "authorization", "rate limits", "object IDs", "tenant isolation", "schema validation", "mass assignment", "excessive data exposure", "error handling", "webhooks", "service-to-service auth", "logging"]),
    "BR11": ("Mobile Applications", ["iOS app inventory", "static analysis", "manifest/plist", "permissions", "hardcoded endpoints", "secrets review", "network security config", "certificate validation", "local storage", "logs", "deep links", "authentication", "authorization", "session management", "privacy", "obfuscation", "dependency review"]),
    "BR12": ("Wireless, Bluetooth, and RF Surface", ["encryption", "guest Wi-Fi", "enterprise auth", "rogue AP review", "signal coverage", "channel plan", "wireless printers", "camera wireless", "management SSIDs", "default SSIDs", "wireless logs", "passive evidence"]),
    "BR13": ("IoT Devices and Sensors", ["device inventory", "vendor mapping", "firmware versions", "management interfaces", "default settings", "authentication", "authorization", "transport security", "update process", "cloud pairing", "local APIs", "physical ports", "debug interfaces", "sensor integrity", "network segmentation", "logging"]),
    "BR14": ("CCTV, Cameras, DVR/NVR, Access Control", ["camera inventory", "video management system", "web management", "firmware state", "default settings", "user roles", "stream access", "recording retention", "remote viewing", "mobile viewer apps", "segmentation", "physical tamper", "time sync", "privacy zones", "logs", "backup/export process", "camera evidence"]),
    "BR15": ("Printers, MFPs, and Peripheral Devices", ["printer inventory", "firmware", "print protocols", "scan-to-email", "address books", "stored documents", "default settings", "fax features", "job logs", "admin roles", "certificates", "segmentation", "physical access", "printer evidence"]),
    "BR16": ("Cloud, SaaS, Email, and Collaboration Platforms", ["tenant inventory", "identity provider", "conditional access", "mail security", "sharing policies", "admin roles", "audit logs", "service principals", "storage buckets", "key vaults", "secrets", "cloud networking", "public exposure", "backup", "retention", "external users", "cloud evidence"]),
    "BR17": ("Containers, Kubernetes, DevOps, and CI/CD", ["repository inventory", "runner security", "build secrets", "container images", "base images", "dependency scanning", "network policies", "secrets", "admission control", "registries", "artifact signing", "deployment approvals", "environment separation", "logs", "supply chain"]),
    "BR18": ("Source Code, Secrets, and Software Supply Chain", ["repo access", "branch protection", "code owners", "secret scanning", "dependency manifests", "license risk", "critical code paths", "auth code", "crypto code", "logging code", "error handling", "deserialization", "file handling", "admin routes", "third-party SDKs", "release process", "code evidence"]),
    "BR19": ("Reverse Engineering, Firmware, and Binaries", ["binary inventory", "firmware images", "hashing", "metadata", "strings review", "packed/encrypted hints", "configuration extraction", "hardcoded endpoint review", "hardcoded secret review", "library versions", "certificate bundles", "update mechanism", "signature checks", "debug symbols", "mobile binaries", "desktop binaries", "safe emulation", "vendor disclosure", "artifact evidence"]),
    "BR20": ("AI, LLM, Automation, and Data Science Systems", ["model inventory", "prompt flows", "system prompts", "tool access", "agent permissions", "vector stores", "training data", "output handling", "prompt injection testing", "data leakage checks", "excessive agency", "model DoS review", "supply chain", "human approval gates", "monitoring"]),
    "BR21": ("Email, Awareness, and Social Engineering Readiness", ["scope approval", "target population", "pretext approval", "training alignment", "mail controls", "phishing simulation process", "reporting button", "helpdesk process", "verification calls", "visitor process", "sensitive request workflow", "executive assistants", "finance approvals", "payload-free testing", "metrics", "lessons learned", "awareness evidence"]),
    "BR22": ("Data Security, Databases, and File Shares", ["data classification", "critical databases", "file shares", "permissions", "sensitive data locations", "finance data", "customer data", "database exposure", "backup copies", "exports", "reports", "temporary files", "logs with secrets", "retention", "encryption", "access review", "data evidence"]),
    "BR23": ("Backup, Disaster Recovery, and Ransomware Resilience", ["backup inventory", "backup scope", "restore testing", "offline copies", "immutable storage", "admin separation", "backup credentials", "backup network", "retention", "critical system recovery", "database recovery", "cloud recovery", "endpoint recovery", "runbooks", "monitoring", "tabletop"]),
    "BR24": ("Logging, SIEM, SOC, and Detection Validation", ["log source inventory", "firewall logs", "proxy logs", "cloud logs", "web logs", "camera logs", "alert routing", "triage process", "retention", "coverage gaps", "purple-team evidence"]),
    "BR25": ("External Attack Surface and Third-Party Exposure", ["domain inventory", "subdomains", "public IPs", "cloud assets", "certificates", "exposed panels", "mail gateways", "third-party portals", "vendor access", "brand impersonation", "leaked credentials handling", "public repos", "paste exposure", "storage exposure", "public documentation", "external evidence"]),
    "BR26": ("Reporting, Remediation, Retesting, and Executive Closure", ["finding quality", "evidence quality", "business impact", "technical impact", "likelihood", "severity", "attack path narrative", "remediation", "quick wins", "strategic fixes", "owner assignment", "retest plan", "executive summary", "technical appendix", "evidence appendix", "risk acceptance", "closure meeting", "final archive"]),
    "BR27": ("Operational Technology, ICS, SCADA, and Safety Systems", ["asset owner and safety authority", "process criticality mapping", "network segmentation from IT", "engineering workstation review", "historian access", "protocol inventory (Modbus/DNP3/S7/OPC)", "remote access paths", "vendor maintenance access", "firmware and patch state", "default credentials review", "safety instrumented system boundary", "passive traffic capture", "wireless field devices", "time sync", "logging and alarms", "change control", "physical enclosure access", "incident and stop procedure"]),
    "BR28": ("Kubernetes Runtime, Service Mesh, and Workload Identity", ["cluster inventory", "namespace isolation", "pod security standards", "network policies", "service mesh mTLS", "ingress and gateway config", "secrets mounting", "workload identity binding", "admission controllers", "image provenance", "runtime privilege review", "host mount review", "etcd exposure", "kubelet exposure", "sidecar review", "audit logging", "resource limits and DoS", "cluster upgrade state"]),
    "BR29": ("PKI, Certificate, Secret, and Key Lifecycle", ["certificate authority inventory", "issuance process", "private key storage", "key rotation policy", "certificate expiry", "weak algorithm review", "wildcard and SAN scope", "revocation process", "internal CA trust", "code-signing keys", "secret manager inventory", "secret rotation", "hardcoded secret sweep", "mTLS client certs", "certificate transparency review", "token lifetime review", "secret access logging"]),
    "BR30": ("Identity Federation, SSO, OAuth, and Conditional Access", ["identity provider inventory", "federation trust review", "redirect URI validation", "scope review", "token validation", "refresh token handling", "conditional access policy", "session lifetime", "device trust", "legacy protocol exposure", "guest and external identity", "service principal review", "consent grant review", "break-glass account review", "impersonation controls"]),
    "BR31": ("Container Image Supply Chain and Build Provenance", ["registry inventory", "base image trust", "image signing verification", "vulnerability scan of images", "build pipeline isolation", "build secret handling", "dependency pinning", "artifact provenance (SLSA)", "reproducible build review", "third-party action review", "cache poisoning risk", "tag immutability", "image retention", "malicious package review", "internal mirror review", "runtime pull policy", "admission signature check", "release approval gate", "provenance logging"]),
    "BR32": ("Data Pipeline, Warehouse, and ML-Ops Security", ["pipeline inventory", "data source authorization", "ingestion exposure", "warehouse access model", "row and column security", "encryption at rest", "encryption in transit", "notebook environment review", "feature store access", "model registry access", "training data provenance", "model artifact integrity", "scheduled job review", "service account scope", "external sharing review", "lineage and audit", "secret handling in jobs", "cost and DoS review", "retention and deletion"]),
    "BR33": ("Insider Threat, DLP, and Egress Simulation", ["data classification coverage", "endpoint DLP review", "email DLP review", "cloud DLP review", "egress channel inventory", "removable media control", "printing controls", "synthetic canary placement", "canary egress simulation", "shadow SaaS review", "personal cloud sync review", "privileged user monitoring", "download volume baselining", "clipboard and screenshot", "collaboration oversharing", "offboarding data access", "third-party data flow", "alert tuning review", "insider response runbook"]),
    "BR34": ("Purple Team, Detection Engineering, and Response Validation", ["detection coverage matrix", "log source completeness", "benign indicator test", "alert fidelity review", "detection rule inventory", "use-case backlog", "false-positive rate review", "mean-time-to-detect baseline", "mean-time-to-respond baseline", "playbook inventory", "containment validation", "escalation path test", "threat intel integration", "detection-as-code review", "tabletop scenario", "purple-team exercise log", "gap remediation tracking", "continuous validation cadence"]),
    "BR39": ("Zero Trust, SASE, and Non-Human Identity", ["workload identity ownership", "service-principal privilege", "cloud workload federation", "certificate-based identity", "device posture enforcement"]),
    "BR40": ("Physical Security, Hardware Implants, PACS, and BMS", ["site authorization", "visitor process", "reception controls", "server room access", "network closet access", "badge lifecycle", "anti-passback policy", "rogue device detection", "network tap detection", "branch office controls", "contractor/vendor access", "facility incident response"]),
    "BR41": ("UCaaS, Collaboration Platforms, Meetings, and Webhooks", ["external guest access", "cross-tenant collaboration", "bot/app permissions", "incoming webhooks", "outgoing webhooks", "chat file-sharing", "meeting lobby controls", "recordings and transcripts", "eDiscovery/audit logging", "executive meeting protection"]),
    "BR42": ("Internal DevSecOps, CI/CD, and Package Registries", ["internal npm registry", "internal PyPI registry", "dependency-confusion prevention", "runner token lifecycle", "pipeline secret exposure", "artifact signing", "deployment approvals", "container registry controls"]),
    "BR43": ("Advanced EDR Control Validation, OOB Management, and MDM/UEM", ["policy exception review", "driver blocklist review", "credential protection review", "iLO/iDRAC/BMC exposure", "mobile app protection", "endpoint incident response"]),
    "BR44": ("AI-Enhanced Social Engineering and Human-Process Resilience", ["deepfake vishing readiness", "voice-clone consent controls", "helpdesk reset resistance", "executive fraud tabletop", "quishing email simulation", "physical QR simulation", "chat impersonation realism", "finance payment approval", "vendor onboarding pretext", "meeting impersonation", "call-back verification", "training feedback loop", "simulation governance"]),
    "BR45": ("Advanced Data Exfiltration, DLP Egress, and Shadow IT", ["data classification", "network DLP policy", "personal cloud storage", "web file converters", "steganography marker review", "email DLP marker", "chat DLP marker", "print/screenshot path", "browser sync leakage", "unsanctioned SaaS discovery", "exfiltration incident response"]),
    "BR46": ("M&A Orphaned Infrastructure and Inherited Shadow Estate", ["acquisition scope map", "legacy domain inventory", "cloud account inheritance", "shadow SaaS tenants", "legacy AD forests", "identity trust relationships", "abandoned applications", "orphaned certificates", "legacy code repositories", "package registries", "third-party vendors", "asset owner mapping"]),
}

# ── Which automated phases exercise which (branch, subtopic) pairs ────────────
# Best-effort mapping. A sub-topic listed here is partially exercised by the
# named phase(s) when that phase produced any evidence this run. Everything not
# listed is treated as manual/checklist-only and reported as "Not Tested — manual".
# Keys are "BRxx:subtopic". Values are lists of phase names.
SUBTOPIC_PHASE_MAP = {
    # BR05 asset/service discovery
    "BR05:service discovery": ["recon", "ports"],
    "BR05:web title inventory": ["recon", "visual"],
    "BR05:management interface discovery": ["ports", "protected_routes"],
    "BR05:certificate inventory": ["recon", "ports"],
    "BR05:external exposure": ["recon", "infra_exposure"],
    # BR04 network/segmentation
    "BR04:firewalls": ["internal_network_safe"],
    "BR04:segmentation validation": ["internal_network_safe"],
    "BR04:routing": ["internal_network_safe"],
    # BR06 AD/identity
    "BR06:domain inventory": ["ad_identity_safe"],
    "BR06:user inventory": ["ad_identity_safe"],
    "BR06:group inventory": ["ad_identity_safe"],
    "BR06:admin group review": ["ad_identity_safe"],
    "BR06:service accounts": ["ad_identity_safe"],
    # BR09 web app
    "BR09:asset mapping": ["discovery", "smart_crawl", "backend_map"],
    "BR09:technology fingerprinting": ["recon", "vuln_scan_extended"],
    "BR09:authentication": ["auth_advanced"],
    "BR09:authorization": ["access_control", "protected_routes"],
    "BR09:business logic": ["business_logic", "upload_race"],
    "BR09:input validation": ["injections", "audit"],
    "BR09:file upload": ["upload_race"],
    "BR09:headers": ["secrets_misc"],
    "BR09:content security policy": ["secrets_misc", "custom_nuclei"],
    "BR09:error handling": ["audit", "injections"],
    "BR09:session management": ["auth_advanced"],
    "BR09:admin panels": ["protected_routes"],
    # BR10 API/microservices
    "BR10:authentication": ["auth_advanced", "api_specific"],
    "BR10:authorization": ["access_control", "atlassian_audit"],
    "BR10:object IDs": ["access_control"],
    "BR10:mass assignment": ["business_logic"],
    "BR10:excessive data exposure": ["api_fuzz", "spec_scan"],
    "BR10:rate limits": ["api_fuzz"],
    "BR10:schema validation": ["spec_scan", "interface_probe"],
    "BR10:webhooks": ["api_specific"],
    "BR10:service-to-service auth": ["interface_probe"],
    "BR10:tenant isolation": ["access_control", "interface_probe"],
    # BR11 mobile
    "BR11:static analysis": ["mobile_scan", "code_scan"],
    "BR11:manifest/plist": ["mobile_scan"],
    "BR11:hardcoded endpoints": ["mobile_scan", "code_scan"],
    "BR11:secrets review": ["mobile_scan", "code_scan", "secrets_misc"],
    "BR11:network security config": ["mobile_scan"],
    # BR12 wireless
    "BR12:rogue AP review": ["wireless_physical_soc"],
    "BR12:passive evidence": ["wireless_physical_soc"],
    # BR13 IoT
    "BR13:device inventory": ["iot_cctv_safe"],
    "BR13:management interfaces": ["iot_cctv_safe", "ports"],
    "BR13:transport security": ["iot_cctv_safe"],
    "BR13:default settings": ["iot_cctv_safe"],
    # BR14 CCTV / BR15 printers -> iot_cctv_safe inventory
    "BR14:camera inventory": ["iot_cctv_safe"],
    "BR14:web management": ["iot_cctv_safe"],
    "BR15:printer inventory": ["iot_cctv_safe"],
    "BR15:print protocols": ["iot_cctv_safe", "ports"],
    # BR16 cloud/SaaS
    "BR16:storage buckets": ["cloud_recon", "cloud_recon_extended"],
    "BR16:public exposure": ["cloud_recon", "infra_exposure"],
    "BR16:secrets": ["secrets_misc", "console_leaks", "api_key_pivot"],
    "BR16:identity provider": ["interface_probe"],
    "BR16:conditional access": ["interface_probe"],
    # BR17/BR18 code & supply chain
    "BR17:container images": ["infra_exposure"],
    "BR17:registries": ["infra_exposure"],
    "BR17:secrets": ["secrets_misc", "console_leaks"],
    "BR18:secret scanning": ["code_scan", "secrets_misc", "console_leaks", "api_key_pivot"],
    "BR18:dependency manifests": ["code_scan"],
    "BR18:critical code paths": ["code_scan"],
    "BR18:crypto code": ["code_scan"],
    "BR18:deserialization": ["code_scan"],
    # BR19 reverse engineering
    "BR19:firmware images": ["firmware_reverse_safe", "firmware_tooling_extended"],
    "BR19:strings review": ["firmware_reverse_safe", "firmware_tooling_extended", "mobile_scan"],
    "BR19:hardcoded secret review": ["firmware_reverse_safe", "firmware_tooling_extended", "code_scan"],
    "BR19:hardcoded endpoint review": ["firmware_reverse_safe", "firmware_tooling_extended", "code_scan"],
    # BR20 AI/LLM
    "BR20:model inventory": ["ai_redteam_safe", "api_specific"],
    "BR20:prompt injection testing": ["api_specific", "ai_redteam_safe"],
    "BR20:tool access": ["interface_probe", "ai_redteam_safe"],
    "BR20:system prompts": ["api_specific"],
    "BR20:output handling": ["ai_redteam_safe"],
    "BR20:supply chain": ["interface_probe"],
    # BR25 external attack surface
    "BR25:subdomains": ["recon"],
    "BR25:domain inventory": ["recon"],
    "BR25:cloud assets": ["cloud_recon", "cloud_recon_extended"],
    "BR25:exposed panels": ["protected_routes", "infra_exposure"],
    "BR25:certificates": ["recon"],
    "BR25:storage exposure": ["cloud_recon"],
    # BR30 identity federation
    "BR30:redirect URI validation": ["auth_advanced"],
    "BR30:federation trust review": ["interface_probe"],
    "BR30:identity provider inventory": ["interface_probe"],
    "BR30:scope review": ["auth_advanced", "interface_probe"],
    # ── Additive appendix branches (BR28/BR31/BR39/BR41/BR42/BR46) ────────────
    "BR28:etcd exposure": ["infra_exposure"],
    "BR28:kubelet exposure": ["infra_exposure"],
    "BR28:cluster inventory": ["infra_exposure"],
    "BR28:ingress and gateway config": ["infra_exposure"],
    "BR31:registry inventory": ["infra_exposure"],
    "BR31:vulnerability scan of images": ["infra_exposure"],
    "BR31:internal mirror review": ["infra_exposure"],
    "BR39:workload identity ownership": ["interface_probe"],
    "BR39:service-principal privilege": ["interface_probe"],
    "BR39:cloud workload federation": ["interface_probe"],
    "BR39:certificate-based identity": ["interface_probe"],
    "BR41:incoming webhooks": ["api_specific"],
    "BR41:outgoing webhooks": ["api_specific"],
    "BR41:bot/app permissions": ["interface_probe"],
    "BR42:internal npm registry": ["infra_exposure"],
    "BR42:internal PyPI registry": ["infra_exposure"],
    "BR42:container registry controls": ["infra_exposure"],
    "BR42:artifact signing": ["infra_exposure"],
    "BR46:legacy domain inventory": ["recon"],
    "BR46:cloud account inheritance": ["cloud_recon", "cloud_recon_extended"],
    "BR46:shadow SaaS tenants": ["cloud_recon", "interface_probe"],
    "BR46:orphaned certificates": ["recon"],
    "BR46:package registries": ["infra_exposure"],
    "BR46:abandoned applications": ["recon", "protected_routes"],
}


def _touched_phases(ctx) -> set:
    """Phases that produced at least one finding this run."""
    touched = set()
    try:
        for f in ctx.storage.all_findings():
            p = f.get("phase")
            if p:
                touched.add(p)
    except Exception:
        pass
    return touched


def run(ctx):
    out = RT.evidence_dir(ctx, "00_governance")
    touched = _touched_phases(ctx)

    rows = []
    per_branch_counts = {}
    auto_touched = 0
    for bid, (title, subs) in PLAYBOOK_TAXONOMY.items():
        per_branch_counts[bid] = len(subs)
        for sub in subs:
            key = f"{bid}:{sub}"
            mapped = SUBTOPIC_PHASE_MAP.get(key, [])
            active = [p for p in mapped if p in touched]
            if active:
                status = "Tested (partial, automated)"
                auto_touched += 1
            elif mapped:
                status = "Not Tested — automation available, no evidence yet"
            else:
                status = "Not Tested — manual/checklist only"
            rows.append({
                "branch_id": bid,
                "branch_title": title,
                "subtopic": sub,
                "automation": "partial" if mapped else "manual",
                "mapped_phases": "|".join(mapped),
                "phases_with_evidence": "|".join(active),
                "status": status,
                "report_rule": "Never mark Safe.",
            })

    RT.write_csv(out / "objective_coverage_map.csv", rows)
    total_sub = len(rows)
    RT.save_json(out / "objective_coverage_map.json", {
        "n_branches": len(PLAYBOOK_TAXONOMY),
        "n_subtopics": total_sub,
        "subtopics_with_automated_evidence": auto_touched,
        "per_branch_subtopic_counts": per_branch_counts,
        "rows": rows,
    })

    # Additively enrich branch_matrix.json (do not remove existing keys).
    mpath = out / "branch_matrix.json"
    if mpath.is_file():
        try:
            matrix = json.loads(mpath.read_text())
            sub_by_branch = {b: {"subtopics": subs, "subtopic_count": len(subs)}
                             for b, (t, subs) in PLAYBOOK_TAXONOMY.items()}
            for br in matrix.get("branches", []):
                extra = sub_by_branch.get(br.get("id"))
                if extra:
                    br["subtopics"] = extra["subtopics"]
                    br["subtopic_count"] = extra["subtopic_count"]
            matrix["playbook_taxonomy_branches"] = len(PLAYBOOK_TAXONOMY)
            matrix["playbook_taxonomy_subtopics"] = total_sub
            matrix["subtopics_with_automated_evidence"] = auto_touched
            mpath.write_text(json.dumps(matrix, indent=2, sort_keys=True), encoding="utf-8")
        except Exception as e:
            ctx.log("WARN", "coverage_map", f"could not enrich branch_matrix.json: {e}")

    RT.add_control_finding(
        ctx, "coverage_map",
        f"Full playbook objective taxonomy ingested ({len(PLAYBOOK_TAXONOMY)} branches, {total_sub} sub-topics)",
        "INFO",
        f"Ingested the complete field-playbook coverage skeleton: {len(PLAYBOOK_TAXONOMY)} branch "
        f"groups and {total_sub} distinct sub-topics. {auto_touched} sub-topics have automated "
        f"evidence from this run; the remainder are manual/checklist and must be worked from the "
        f"playbook. Absence of a finding is not proof of safety.",
        f"{out/'objective_coverage_map.csv'}; {out/'objective_coverage_map.json'}",
        remediation="Work the manual sub-topics through the Section-4 loop and record each status "
                    "(Tested/Simulated/Not Authorized/Not Applicable/Blocked/Needs High-Risk Approval).",
    )
    ctx.log("OK", "coverage_map",
            f"objective coverage map written ({len(PLAYBOOK_TAXONOMY)} branches / {total_sub} "
            f"sub-topics; {auto_touched} auto-touched) -> {out}")
