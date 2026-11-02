"""
Phase: code_intel   (v3.1)

The v3 source-code testing brain. Where the older `code_scan` phase greps a tree
for secrets/endpoints/sinks, `code_intel` does the full reviewer workflow:

    1. Repo intake        (dirs + git repos, optional private-repo token)
    2. Code intelligence  (framework, routes, auth, roles, models, handlers)
    3. Endpoint -> live   (map code routes onto the real domains, reachability)
    4. Source -> vuln     (file -> input -> sink -> missing control -> hypothesis)
    5. Branch modules     (15 focused source branches, each its own output)
    6. Reports            (per-branch JSON, remediation plan, native findings)

Design promise (unchanged from the v2.24/v3.0 safety model):
    Source analysis is READ-ONLY. Live mapping is REACHABILITY-ONLY (a single
    safe request per endpoint, no payloads). Actual exploit confirmation is
    delegated to the existing consented active phases (add_sqli, injections,
    business_logic, access_control) — this phase only produces the hypothesis
    and the safe test plan. It never dumps data, mutates state, or exploits.

Runs whenever any code input is supplied (--code-dir / --code-repos /
--code-repos-file). Silent skip otherwise, exactly like code_scan. This phase is
additive: `code_scan` still runs and behaves identically.
"""
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path

from core import code_intel as CI
from core import fp_filters as FP
from core.evidence_redaction import redact_value
from core.git_intake import repository_name, clone_repository
from core.evidence_redaction import redact_text


# ── all branches this phase can emit ─────────────────────────────────────────
ALL_BRANCHES = [
    "code_secrets", "code_dependencies", "code_routes", "code_auth",
    "code_access_control", "code_business_logic", "code_injection",
    "code_uploads", "code_payments", "code_webhooks", "code_admin",
    "code_cloud", "code_mobile_api", "code_ai_api", "code_ci_cd",
]

# --include-* flag -> branch (lets the user's exact command switch branches on)
_INCLUDE_MAP = {
    "include_secrets": "code_secrets",
    "include_dependencies": "code_dependencies",
    "include_api_routes": "code_routes",
    "include_admin_routes": "code_admin",
    "include_auth_flows": "code_auth",
    "include_access_control": "code_access_control",
    "include_business_logic": "code_business_logic",
    "include_payment_flows": "code_payments",
    "include_upload_flows": "code_uploads",
    "include_webhook_flows": "code_webhooks",
    "include_cloud_config": "code_cloud",
    "include_mobile_api": "code_mobile_api",
    "include_ci_cd": "code_ci_cd",
}


# ── intake helpers ───────────────────────────────────────────────────────────
def _gather_repos(ctx):
    repos = []
    raw = getattr(ctx.args, "code_repos", None)
    if raw:
        repos += [r.strip() for r in raw.split(",") if r.strip()]
    rfile = getattr(ctx.args, "code_repos_file", None)
    if rfile and Path(rfile).is_file():
        repos += [l.strip() for l in Path(rfile).read_text().splitlines()
                  if l.strip() and not l.startswith("#")]
    return list(dict.fromkeys(repos))


def _clone(ctx, repos, dest: Path):
    dest.mkdir(parents=True, exist_ok=True)
    token = ""
    env_name = getattr(ctx.args, "github_token_env", None)
    if env_name:
        token = os.environ.get(env_name, "")
    cloned = []
    for url in repos:
        if getattr(ctx.args, 'offline', False):
            ctx.log('WARN', 'code_intake', 'offline mode: repository cloning blocked; use --code-dir')
            continue
        try:
            name = repository_name(url)
        except ValueError as exc:
            ctx.log('WARN', 'code_intel', redact_text(f'repository rejected: {exc}'))
            continue
        target = dest / name
        if target.exists():
            cloned.append(target)
            continue
        ctx.log("INFO", "code_intel", f"cloning {name} (shallow)…")
        try:
            clone_repository(url, target, token)
            if target.exists():
                cloned.append(target)
        except Exception as e:
            ctx.log("WARN", "code_intel", redact_text(f"clone failed {url}: {e}"))
    return cloned


def _selected_branches(ctx):
    raw = (getattr(ctx.args, "code_branches", None) or "").strip().lower()
    if raw in ("", "all"):
        selected = set(ALL_BRANCHES)
    else:
        selected = {b.strip() for b in raw.split(",") if b.strip()}
    # any --include-* flag additively switches its branch on
    for flag, branch in _INCLUDE_MAP.items():
        if getattr(ctx.args, flag, False):
            selected.add(branch)
    # v3.4: --no-include-<branch> removes noisy branches
    _no_map = {
        "no_include_dependencies": "code_dependencies",
        "no_include_ci_cd": "code_ci_cd",
        "no_include_secrets": "code_secrets",
        "no_include_business_logic": "code_business_logic",
        "no_include_access_control": "code_access_control",
        "no_include_admin_routes": "code_admin",
        "no_include_api_routes": "code_routes",
        "no_include_payment_flows": "code_payments",
        "no_include_upload_flows": "code_uploads",
        "no_include_webhook_flows": "code_webhooks",
        "no_include_auth_flows": "code_auth",
        "no_include_cloud_config": "code_cloud",
        "no_include_mobile_api": "code_mobile_api",
    }
    for flag, branch in _no_map.items():
        if getattr(ctx.args, flag, False):
            selected.discard(branch)
    # keep canonical order
    return [b for b in ALL_BRANCHES if b in selected]


# ── live reachability (safe, no payloads) ────────────────────────────────────
def _probe_live(ctx, plan, out_dir):
    """Send one safe request per mapped endpoint. Records status + auth signal."""
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
    except Exception:
        ctx.log("WARN", "code_intel", "requests not available — skipping live mapping")
        return []

    import secrets as _secrets
    # v3.4: same-server control — a random nonexistent path per host. If a "live"
    # endpoint returns the SAME status and near-identical length as this control,
    # the host answers 200-on-everything (wildcard/SPA/WAF) and the match is a FP.
    control = {}
    for item in plan[:int(getattr(ctx.args, "code_live_budget", 200) or 200)]:
        base = item["live_base"]
        if base in control:
            continue
        rand = f"{base}/tbhm-control-{_secrets.token_hex(6)}"
        try:
            rr = requests.get(rand, timeout=10, verify=False, allow_redirects=False)
            control[base] = (rr.status_code, len(rr.content))
        except Exception:
            control[base] = (None, None)

    results = []
    generic = 0
    budget = int(getattr(ctx.args, "code_live_budget", 200) or 200)
    for item in plan[:budget]:
        ctx.runner.throttle("code_intel_live")
        url = item["url"]
        status, length, note = None, None, ""
        for method in ("HEAD", "GET"):
            try:
                r = requests.request(method, url, timeout=10, verify=False,
                                     allow_redirects=False)
                status = r.status_code
                length = len(r.content) if method == "GET" else \
                    int(r.headers.get("content-length", 0) or 0)
                if status == 405 and method == "HEAD":
                    continue  # retry with GET
                break
            except Exception as e:
                note = str(e)[:120]
                continue
        reachable = status is not None and status < 500 and status != 404
        auth_required = status in (401, 403)
        # same-server control comparison
        cstat, clen = control.get(item["live_base"], (None, None))
        generic_response = False
        if reachable and cstat is not None and status == cstat and length is not None \
                and clen is not None:
            denom = max(length, clen, 1)
            if abs(length - clen) / denom < 0.10:   # <10% size delta vs control
                generic_response = True
                reachable = False                    # not a real distinct endpoint
                generic += 1
        row = dict(item)
        row.update({
            "status": status,
            "length": length,
            "reachable": reachable,
            "auth_required_observed": auth_required,
            "generic_response": generic_response,
            "control_status": cstat,
            "note": note,
        })
        results.append(row)
    if generic:
        ctx.log("INFO", "code_intel",
                f"live map: {generic} endpoint(s) matched the same-server control "
                f"(200-on-everything) — flagged generic, not reported")
    (out_dir / "endpoint_to_live_map.json").write_text(
        json.dumps(results, indent=2))
    # split views the user asked for
    orphan_admin = [r for r in results if "/admin" in r["normalised"].lower()
                    and r.get("reachable") and not r.get("auth_required_observed")]
    hidden_api = [r for r in results if r["file"] == "(extracted)"
                  and r.get("reachable")]
    (out_dir / "orphaned_admin_routes.json").write_text(json.dumps(orphan_admin, indent=2))
    (out_dir / "hidden_api_routes.json").write_text(json.dumps(hidden_api, indent=2))
    return results


# ── branch emitters ──────────────────────────────────────────────────────────
def _emit_secrets(ctx, cmap, code_dir):
    findings = 0
    all_secrets = cmap.get("secrets", [])
    # v3.4: prod secrets go to report; test/docs/LICENSE secrets go to audit only.
    # (the save_finding gate additionally drops dummy/low-entropy values.)
    prod = [s for s in all_secrets if s.get("context", "prod") == "prod"]
    suppressed = [s for s in all_secrets if s.get("context", "prod") != "prod"]
    (code_dir / "secrets_findings.json").write_text(json.dumps(redact_value(prod), indent=2))
    if suppressed:
        _append_suppressed(ctx, code_dir, "code_secrets", suppressed)
    for s in prod:
        sev = s["severity"]
        ctx.save_finding({
            "phase": "code_intel", "severity": sev,
            "confidence": "MEDIUM" if "Generic" in s["type"] else "HIGH",
            "title": f"[code_secrets] Hardcoded secret: {s['type']}",
            "target": s.get("path", ""), "url": "",
            "description": f"{s['type']} in {s.get('path')}:{s.get('line')}. "
                           f"Committed credentials are visible to anyone with repo access.",
            "evidence": f"{s.get('path')}:{s.get('line')}  {s.get('match')}",
            "impact": "Credential exposure; verify if live and rotate.",
            "remediation": "Remove from source, rotate, load from a secret manager.",
            "cwe": "CWE-798",
            "mrs_score": {"HIGH": 80, "MEDIUM": 55, "LOW": 35}.get(sev, 40),
        })
        findings += 1
    return {"count": len(prod), "suppressed": len(suppressed), "items": prod}, findings


def _append_suppressed(ctx, code_dir, branch, items):
    """v3.4: archive non-prod (test/docs/LICENSE) hits to suppressed_findings.jsonl
    and the dropped register so they appear in false_positives.md — never lost."""
    path = code_dir / "suppressed_findings.jsonl"
    with open(path, "a") as fh:
        for h in items:
            rec = {"branch": branch, "context": h.get("context"),
                   "file": h.get("file") or h.get("path"),
                   "line": h.get("line"), "match": h.get("match") or h.get("type"),
                   "reason": f"{h.get('context')} path (non-production)"}
            fh.write(json.dumps(redact_value(rec)) + "\n")
            try:
                ctx.storage._record_drop(
                    {"phase": "code_intel", "severity": "INFO",
                     "title": f"[{branch}] {rec['file']}:{rec['line']}",
                     "target": rec["file"], "evidence": str(rec["match"])[:80]},
                    rec["reason"], "code_context_filter")
            except Exception:
                pass


def _emit_routes(ctx, cmap, code_dir):
    routes = cmap.get("routes", [])
    (code_dir / "route_map.json").write_text(json.dumps(routes, indent=2))
    return {"count": len(routes), "items": routes}, 0


def _emit_auth(ctx, cmap, code_dir):
    auth = cmap.get("auth", {})
    (code_dir / "auth_logic_map.json").write_text(json.dumps(auth, indent=2))
    findings = 0
    # routes with no auth middleware in-file that look sensitive
    authed_files = {m["file"] for m in auth.get("middleware", [])}
    for r in cmap.get("routes", []):
        p = r["path"].lower()
        sensitive = any(k in p for k in ("admin", "user", "account", "payment",
                                         "order", "delete", "internal", "settings"))
        if sensitive and r["file"] not in authed_files and r["method"] in (
            "POST", "PUT", "PATCH", "DELETE", "ANY"
        ):
            ctx.save_finding({
                "phase": "code_intel", "severity": "MEDIUM", "confidence": "LOW",
                "title": f"[code_auth] Sensitive route without visible auth guard: {r['method']} {r['path']}",
                "target": r["file"], "url": "",
                "description": f"{r['method']} {r['path']} ({r['file']}:{r['line']}) is a state-changing/"
                               f"sensitive route, but no auth middleware was detected in its file. "
                               f"Confirm the guard exists at a higher layer before relying on it.",
                "evidence": f"{r['file']}:{r['line']}  handler={r.get('handler') or '?'}",
                "impact": "Possible broken authentication / missing authorization if truly unguarded.",
                "remediation": "Attach an explicit auth+authorization check to this route; add a regression test.",
                "cwe": "CWE-306",
                "mrs_score": 50,
            })
            findings += 1
    return {"mechanisms": auth.get("mechanisms", []),
            "middleware": auth.get("middleware", [])}, findings


def _emit_access_control(ctx, cmap, code_dir):
    roles = cmap.get("roles", [])
    (code_dir / "role_permission_matrix.json").write_text(json.dumps(roles, indent=2))
    return {"count": len(roles), "items": roles}, 0


def _dev_dependency_names(roots):
    """v3.4: collect names declared under devDependencies (npm) to drop from SCA."""
    import json as _json
    from pathlib import Path
    dev = set()
    for root in roots:
        for pj in Path(root).rglob("package.json"):
            if FP.path_context(str(pj)) != "prod":
                continue
            try:
                data = _json.loads(pj.read_text(errors="ignore"))
            except Exception:
                continue
            for name in (data.get("devDependencies") or {}):
                dev.add(name.lower())
    return dev


def _emit_dependencies(ctx, cmap, code_dir, roots):
    from core import sbom
    comps = []
    for root in roots:
        try:
            comps += sbom.parse_dependencies(root)
        except Exception:
            pass
    uniq = {(c["name"], c["version"], c["ecosystem"]): c for c in comps}
    comps = list(uniq.values())
    # v3.4: --sca-prod-only drops devDependency CVEs (never ship to prod)
    dropped_dev = 0
    if getattr(ctx.args, "sca_prod_only", True):
        dev = _dev_dependency_names(roots)
        if dev:
            before = len(comps)
            comps = [c for c in comps if c["name"].lower() not in dev]
            dropped_dev = before - len(comps)
    findings = 0
    vuln = []
    if comps:
        try:
            (code_dir / "sbom.cyclonedx.json").write_text(
                json.dumps(sbom.cyclonedx(comps), indent=2))
            if getattr(ctx.args, 'allow_external_enrichment', False) and not getattr(ctx.args, 'offline', False):
                comps = sbom.query_osv(comps)
            else:
                ctx.log('INFO', 'sbom', 'OSV lookup disabled; local SBOM generated without publishing dependency metadata')
            vuln = [c for c in comps if c.get("vulns")]
            for c in vuln:
                ids = ", ".join(v["id"] for v in c["vulns"][:6])
                ctx.save_finding({
                    "phase": "code_intel", "severity": "HIGH", "confidence": "MEDIUM",
                    "title": f"[code_dependencies] Vulnerable dependency: {c['name']} {c['version']}",
                    "target": c.get("file", ""), "url": "",
                    "description": f"{c['name']}@{c['version']} ({c['ecosystem']}) has advisories: {ids}. "
                                   f"Reachability not verified.",
                    "evidence": "; ".join(f"{v['id']}: {v['summary']}" for v in c["vulns"][:3])[:400],
                    "impact": "Depends on the CVE and whether the vulnerable path is reachable.",
                    "remediation": "Upgrade to a fixed release per the advisory.",
                    "references": [f"https://osv.dev/vulnerability/{v['id']}" for v in c["vulns"][:5]],
                    "cwe": "CWE-1104", "mrs_score": 70,
                })
                findings += 1
        except Exception as e:
            ctx.log("WARN", "code_intel", f"dependency step failed: {e}")
    out = {"components": len(comps), "vulnerable": len(vuln),
           "dev_dependencies_dropped": dropped_dev}
    (code_dir / "dependency_findings.json").write_text(json.dumps(out, indent=2))
    if dropped_dev:
        ctx.log("INFO", "code_intel",
                f"SCA: dropped {dropped_dev} devDependency component(s) (--sca-prod-only)")
    return out, findings


def _emit_handler_branch(ctx, cmap, code_dir, key, branch, sev, title_kind, cwe,
                         impact, out_name=None):
    all_items = cmap.get("handlers", {}).get(key, [])
    # v3.4: split prod (report) vs test/docs/LICENSE (suppressed audit)
    items = [h for h in all_items if h.get("context", "prod") == "prod"]
    suppressed = [h for h in all_items if h.get("context", "prod") != "prod"]
    # branch JSON now holds only prod hits (what the operator reads)
    (code_dir / (out_name or f"{branch}_findings.json")).write_text(
        json.dumps(items, indent=2))
    if suppressed:
        _append_suppressed(ctx, code_dir, branch, suppressed)
    # A handler/feature keyword is an inventory observation. Its existence
    # does not establish an authorization, injection, or business-logic defect.
    for h in items[:40]:
        if hasattr(ctx.storage, "save_observation"):
            ctx.storage.save_observation(
                phase="code_intel", observation_type="source_feature",
                target=h["file"], summary=f"{title_kind} requires contextual review",
                evidence={"branch": branch, "line": h["line"], "match": h["match"],
                          "security_invariant_tested": False})
    return {"count": len(items), "items": items, "classification": "inventory"}, 0


def _emit_business_logic(ctx, cmap, code_dir, traces):
    bl = [t for t in traces if t["possible_vuln"] in (
        "SQL injection",) or "price" in t.get("input", "").lower()]
    # dedicated price/amount surface from payment handlers already covered;
    # business logic here highlights traces that touch money/quantity fields
    money = [t for t in traces if any(k in (t["input"] + t["sink_match"]).lower()
             for k in ("price", "amount", "qty", "quantity", "total", "discount", "coupon"))]
    out = {"money_flow_traces": money, "count": len(money)}
    (code_dir / "business_logic_findings.json").write_text(json.dumps(out, indent=2))
    findings = 0
    for t in money[:25]:
        ctx.save_finding({
            "phase": "code_intel", "severity": "MEDIUM", "confidence": "LOW",
            "title": f"[code_business_logic] Client-influenced value reaches sink: {t['file']}:{t['line']}",
            "target": t["file"], "url": "",
            'file': t['file'], 'line': t['line'], 'function': t['function'],
            "description": f"A monetary/quantity field appears near a sink in {t['function'] or 'handler'} "
                           f"without a clear server-side validation. Classic price/quantity manipulation shape.",
            "evidence": f"{t['file']}:{t['line']}  input={t['input']}  sink={t['sink']}",
            "impact": "Possible price/quantity manipulation or business-logic abuse.",
            "remediation": "Recompute prices/totals server-side from trusted catalog data; never trust client amounts.",
            "cwe": "CWE-840", "mrs_score": 55,
        })
        findings += 1
    return out, findings


def _emit_injection(ctx, cmap, code_dir, traces):
    inj = [t for t in traces if t["possible_vuln"] in (
        "SQL injection", "OS command injection", "code injection",
        "DOM XSS", "insecure deserialization", "YAML deserialization",
        "code injection", "MITM / weak transport")]
    (code_dir / "injection_findings.json").write_text(json.dumps(inj, indent=2))
    findings = 0
    from datetime import datetime as _dt
    for t in inj[:50]:
        mitigated = t.get("taint_class") == "mitigated"
        static_flow = t.get("taint_class") in {
            "unsanitized_static_lead", "supported_static_reachable"
        }
        reachable = bool(t.get("reachability_corroborated"))
        if mitigated:
            sev = "INFO"
            title_tag = "mitigated"
        elif static_flow:
            sev = t["severity"] if t["severity"] in ("HIGH", "MEDIUM") else "HIGH"
            title_tag = "supported static lead" + (" (route reachable)" if reachable else "")
            if bool(getattr(ctx.args, "reachable_only", False)) and not reachable:
                # Do not hide deterministic source evidence.  The option is a
                # reporting/noise control, so uncorroborated flows remain leads
                # but are visibly downgraded instead of being discarded.
                sev = "LOW"
                title_tag = "static lead (not present in live reachable map)"
        else:
            sev = t["severity"] if t["severity"] in ("HIGH", "MEDIUM") else "MEDIUM"
            title_tag = "candidate"
        f = {
            "phase": "code_intel", "severity": sev,
            "confidence": t["confidence"],
            "title": f"[code_injection] {t['possible_vuln']} {title_tag}: {t['file']}:{t['line']}",
            "target": t["file"], "url": "",
            "description": f"Function {t['function'] or '?'} — input {t['input']} reaches sink "
                           f"'{t['sink']}'. Missing control: {t['missing_control']}.",
            "evidence": f"{t['file']}:{t['line']}  {t['sink_match']}  |  {t['input']}",
            "impact": f"{t['possible_vuln']} — a static source-to-sink path was identified, "
                      "but exploitability is not proven without independent runtime/manual verification.",
            "remediation": f"Add: {t['missing_control']}.",
            "cwe": t["cwe"],
            "mrs_score": 70 if static_flow else (55 if sev in ("HIGH", "MEDIUM") else 20),
            "how_to_test_live": t["how_to_test_live"],
        }
        if static_flow:
            # Static dataflow is strong deterministic support, not proof.  It
            # must remain visible at HIGH confidence without entering the
            # confirmed report until an independent verifier reproduces impact.
            f["verified"] = False
            f["verification_method"] = (
                "static-taint-plus-route-reachability" if reachable
                else "static-taint-dataflow"
            )
            f["finding_class"] = (
                "lead" if bool(getattr(ctx.args, "reachable_only", False)) and not reachable
                else "supported"
            )
            f["validation_required"] = (
                "Reproduce the source-to-sink behavior in an authorized test "
                "environment with a benign marker and a negative control."
            )
        ctx.save_finding(f)
        findings += 1
    return {"count": len(inj), "items": inj}, findings


def _emit_ci_cd(ctx, cmap, code_dir, roots):
    hits = []
    ci_markers = (".github/workflows", ".gitlab-ci", "jenkinsfile", "circleci",
                  "azure-pipelines", "bitbucket-pipelines", ".travis.yml", "cloudbuild")
    for root in roots:
        for f in Path(root).rglob("*"):
            if not f.is_file():
                continue
            low = str(f).lower()
            if any(m in low for m in ci_markers):
                try:
                    text = f.read_text(errors="ignore")
                except Exception:
                    continue
                risky = []
                for pat, why in [
                    (r"(?i)pull_request_target", "pull_request_target (untrusted checkout risk)"),
                    (r"(?i)\$\{\{\s*github\.event\.[^}]*\}\}", "unsanitised github.event interpolation"),
                    (r"(?i)(secrets\.[A-Z_]+)", "secret usage — check for leak to fork PRs"),
                    (r"(?i)curl\s+[^|]+\|\s*(bash|sh)", "curl | sh remote code execution"),
                    (r"(?i)actions/checkout@(v1|v2)\b", "outdated checkout action"),
                ]:
                    import re as _re
                    if _re.search(pat, text):
                        risky.append(why)
                if risky:
                    hits.append({"file": str(f.relative_to(Path(root).parent)),
                                 "issues": risky})
    (code_dir / "ci_cd_findings.json").write_text(json.dumps(hits, indent=2))
    findings = 0
    for h in hits:
        ctx.save_finding({
            "phase": "code_intel", "severity": "MEDIUM", "confidence": "LOW",
            "title": f"[code_ci_cd] CI/CD risk in {h['file']}",
            "target": h["file"], "url": "",
            "description": "Pipeline configuration contains patterns associated with supply-chain / "
                           "secret-exfil risk: " + "; ".join(h["issues"]),
            "evidence": h["file"] + " :: " + "; ".join(h["issues"]),
            "impact": "CI compromise can lead to secret theft or malicious build artefacts.",
            "remediation": "Pin actions by SHA, avoid pull_request_target with checkout, scope secrets.",
            "cwe": "CWE-506", "mrs_score": 50,
        })
        findings += 1
    return {"count": len(hits), "items": hits}, findings


# ── main ─────────────────────────────────────────────────────────────────────
def run(ctx):
    code_dir_arg = getattr(ctx.args, "code_dir", None)
    repos = _gather_repos(ctx)
    if not code_dir_arg and not repos:
        return  # silent skip — no source input

    # Apply the parser-level --exclude-tests/--include-tests policy before
    # any stack, route, secret or taint walker touches the tree.
    CI.configure_scan_policy(bool(getattr(ctx.args, "exclude_tests", True)))

    base = ctx.output / "source_code_full"
    src = base / "source_code"
    ev = base / "evidence"
    (ev / "code_snippets").mkdir(parents=True, exist_ok=True)
    (ev / "live_requests").mkdir(parents=True, exist_ok=True)
    (ev / "screenshots").mkdir(parents=True, exist_ok=True)
    logs = base / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    src.mkdir(parents=True, exist_ok=True)
    (logs / "source_scan.log").write_text(
        f"code_intel start {datetime.utcnow().isoformat()}Z\n")
    (logs / "skipped_checks.log").write_text("")
    (logs / "errors.log").write_text("")

    ctx.log("INFO", "code_intel", "━━━ v3 source-code intelligence ━━━")

    roots = []
    if code_dir_arg and Path(code_dir_arg).is_dir():
        roots.append(Path(code_dir_arg))
    if repos:
        roots += _clone(ctx, repos, base / "_repos")
    if not roots:
        ctx.log("WARN", "code_intel", "no source available to analyse")
        return

    # 1+2. intake + intelligence map (per-root, merged)
    inventory = []
    merged = {"stack": {"languages": [], "frameworks": [], "package_managers": [],
                        "manifests": []},
              "routes": [], "auth": {"mechanisms": [], "middleware": []},
              "roles": [], "models": [], "secrets": [], "sinks": [],
              "endpoints": {"urls": [], "paths": [], "hosts": []},
              "handlers": {k: [] for k in ("upload", "payment", "admin",
                                           "webhook", "cloud", "mobile", "ai")}}
    for root in roots:
        cmap = CI.build_map(root)
        inventory.append({"repo": root.name, "stack": cmap["stack"],
                          "counts": cmap["counts"]})
        merged["routes"] += cmap["routes"]
        merged["auth"]["mechanisms"] += cmap["auth"]["mechanisms"]
        merged["auth"]["middleware"] += cmap["auth"]["middleware"]
        merged["roles"] += cmap["roles"]
        merged["models"] += cmap["models"]
        merged["secrets"] += cmap["secrets"]
        merged["sinks"] += cmap["sinks"]
        for k in merged["handlers"]:
            merged["handlers"][k] += cmap["handlers"].get(k, [])
        for k in ("urls", "paths", "hosts"):
            merged["endpoints"][k] += cmap["endpoints"][k]
        for fld in ("languages", "frameworks", "package_managers", "manifests"):
            merged["stack"][fld] += cmap["stack"].get(fld, [])
        # keep the last stack summary fields
        merged["stack"]["primary_language"] = cmap["stack"].get("primary_language")

    for k in ("urls", "paths", "hosts"):
        merged["endpoints"][k] = sorted(set(merged["endpoints"][k]))
    for fld in ("frameworks", "package_managers", "manifests"):
        merged["stack"][fld] = sorted(set(merged["stack"][fld]))

    (src / "repo_inventory.json").write_text(json.dumps(inventory, indent=2))
    (src / "framework_detection.json").write_text(
        json.dumps(merged["stack"], indent=2))

    ctx.log("OK", "code_intel",
            f"map: {len(merged['routes'])} routes | "
            f"{len(merged['auth']['middleware'])} auth guards | "
            f"{len(merged['roles'])} role refs | {len(merged['models'])} models | "
            f"{len(merged['secrets'])} secrets | frameworks={','.join(merged['stack']['frameworks']) or '?'}")

    # persist extracted endpoints so recon/api_fuzz can consume them too
    if merged["endpoints"]["paths"]:
        (src / "discovered_endpoints.json").write_text(
            json.dumps(merged["endpoints"], indent=2))
        # also feed the legacy consumer path used by api_fuzz
        code_legacy = ctx.output / "code"
        code_legacy.mkdir(exist_ok=True)
        (code_legacy / "endpoints.txt").write_text(
            "\n".join(merged["endpoints"]["paths"]))

    # 3. endpoint -> live mapping (reachability only, gated).  Source-to-sink
    # traces are generated *after* this block so route reachability can annotate
    # the actual route records consumed by the taint engine.
    do_live = bool(getattr(ctx.args, "map_code_to_live", False)) or \
        bool(ctx.profile.get("active_probes", False))
    live_results = []
    if do_live:
        domains = _read_file_list(getattr(ctx.args, "domains_file", None))
        urls = _read_file_list(getattr(ctx.args, "urls_file", None))
        # fall back to the scan's own targets
        if not domains and not urls:
            domains = [t for t in ctx.targets if not t.startswith("http")]
            urls = [t for t in ctx.targets if t.startswith("http")]
        bases = CI.live_bases_from_targets(domains, urls)
        if bases:
            plan = CI.build_live_match_plan(merged, bases)
            ctx.log("INFO", "code_intel",
                    f"live map: {len(plan)} endpoint×host pairs against {len(bases)} host(s) (reachability only)")
            live_results = _probe_live(ctx, plan, src)
            reach = sum(1 for r in live_results if r.get("reachable"))
            orphans = sum(1 for r in live_results
                          if "/admin" in r["normalised"].lower()
                          and r.get("reachable") and not r.get("auth_required_observed"))
            ctx.log("OK", "code_intel",
                    f"live map: {reach}/{len(live_results)} reachable | {orphans} unauth admin route(s)")
            for r in live_results:
                if "/admin" in r["normalised"].lower() and r.get("reachable") \
                        and not r.get("auth_required_observed"):
                    ctx.save_finding({
                        "phase": "code_intel", "severity": "HIGH", "confidence": "MEDIUM",
                        "title": f"[code_admin] Admin route reachable without auth: {r['url']}",
                        "target": r["live_base"], "url": r["url"],
                        "method": r["method"],
                        "description": f"Source route {r['code_path']} ({r['file']}) maps to a live admin "
                                       f"endpoint returning HTTP {r['status']} without an auth challenge.",
                        "evidence": f"{r['method']} {r['url']} → {r['status']} (len={r['length']})",
                        "impact": "Unauthenticated access to administrative functionality.",
                        "remediation": "Enforce authentication+authorization on all /admin routes; verify at the edge.",
                        "cwe": "CWE-284", "cvss": "8.6", "mrs_score": 88,
                    })
        else:
            ctx.log("INFO", "code_intel", "live map skipped — no in-scope hosts resolved")
    else:
        ctx.log("INFO", "code_intel",
                "live map disabled — pass --map-code-to-live or use an active profile")


    # 4. source -> vuln traces (across all roots).  Copy safe live-status
    # corroboration back into the canonical route records before tracing.  A
    # reachable route strengthens a static lead but never proves exploitation.
    if live_results:
        route_index = {}
        for route in merged.get("routes", []):
            key = (str(route.get("file") or ""), CI.normalise_path(str(route.get("path") or "/")))
            route_index.setdefault(key, []).append(route)
        for result in live_results:
            if not result.get("reachable"):
                continue
            key = (str(result.get("file") or ""), str(result.get("normalised") or ""))
            for route in route_index.get(key, []):
                route["live_status"] = result.get("status")
                route["live_url"] = result.get("url")
                route["live_reachability_only"] = True

    traces = []
    for root in roots:
        traces += CI.trace_vulns(root, merged)
    (src / "source_to_vuln_traces.json").write_text(json.dumps(traces, indent=2))
    coverage = merged.pop('_taint_coverage', [])
    (src/'analysis_coverage.json').write_text(json.dumps({'schema': 'tbhm.source-analysis-coverage/1',
        'files': coverage, 'meaning': 'Analysis modes only; lexical/pattern modes and parse failures are not clean security verdicts.'}, indent=2)+'\n')
    if any(row['mode'] in {'parse_error', 'analysis_error'} for row in coverage) and getattr(ctx, 'execution_ledger', None):
        ctx.execution_ledger.record(kind='artifact', status='partial', artifact='source_code_full/source_code/analysis_coverage.json', reason='source parsing/dataflow analysis incomplete')
    ctx.log("OK", "code_intel", f"traces: {len(traces)} source→vuln hypotheses")

    # 5. branch modules
    branches = _selected_branches(ctx)
    ctx.log("INFO", "code_intel", f"branches: {', '.join(branches)}")
    branch_summary = {}
    total_findings = 0

    def _record(name, result_findings):
        nonlocal total_findings
        result, n = result_findings
        branch_summary[name] = result.get("count", result.get("components", "-")) \
            if isinstance(result, dict) else "-"
        total_findings += n

    if "code_secrets" in branches:
        _record("code_secrets", _emit_secrets(ctx, merged, src))
    if "code_dependencies" in branches:
        _record("code_dependencies", _emit_dependencies(ctx, merged, src, roots))
    if "code_routes" in branches:
        _record("code_routes", _emit_routes(ctx, merged, src))
    if "code_auth" in branches:
        _record("code_auth", _emit_auth(ctx, merged, src))
    if "code_access_control" in branches:
        _record("code_access_control", _emit_access_control(ctx, merged, src))
    if "code_business_logic" in branches:
        _record("code_business_logic", _emit_business_logic(ctx, merged, src, traces))
    if "code_injection" in branches:
        _record("code_injection", _emit_injection(ctx, merged, src, traces))
    if "code_uploads" in branches:
        _record("code_uploads", _emit_handler_branch(
            ctx, merged, src, "upload", "code_uploads", "MEDIUM",
            "File upload handler", "CWE-434",
            "Unrestricted upload could allow webshell/overwrite if type/path unchecked.",
            out_name="upload_findings.json"))
    if "code_payments" in branches:
        _record("code_payments", _emit_handler_branch(
            ctx, merged, src, "payment", "code_payments", "MEDIUM",
            "Payment/pricing logic", "CWE-840",
            "Payment tampering or price manipulation if amounts trusted from client.",
            out_name="payment_findings.json"))
    if "code_webhooks" in branches:
        _record("code_webhooks", _emit_handler_branch(
            ctx, merged, src, "webhook", "code_webhooks", "MEDIUM",
            "Webhook receiver", "CWE-345",
            "Forged webhook events if signatures are not verified.",
            out_name="webhook_findings.json"))
    if "code_admin" in branches:
        _record("code_admin", _emit_handler_branch(
            ctx, merged, src, "admin", "code_admin", "MEDIUM",
            "Admin surface", "CWE-284",
            "Privilege escalation if admin routes lack authorization.",
            out_name="admin_route_findings.json"))
    if "code_cloud" in branches:
        _record("code_cloud", _emit_handler_branch(
            ctx, merged, src, "cloud", "code_cloud", "LOW",
            "Cloud/IAM usage", "CWE-732",
            "Over-broad cloud permissions or unsigned URLs could expose data."))
    if "code_mobile_api" in branches:
        _record("code_mobile_api", _emit_handler_branch(
            ctx, merged, src, "mobile", "code_mobile_api", "LOW",
            "Mobile API surface", "CWE-926",
            "Exported components/deeplinks/WebView bridges may widen attack surface."))
    if "code_ai_api" in branches:
        _record("code_ai_api", _emit_handler_branch(
            ctx, merged, src, "ai", "code_ai_api", "LOW",
            "AI/LLM integration", "CWE-1427",
            "Prompt injection / unsafe tool use if user text reaches the model unchecked."))
    if "code_ci_cd" in branches:
        _record("code_ci_cd", _emit_ci_cd(ctx, merged, src, roots))

    # persist a few maps the user asked for by name
    (src / "endpoint_to_live_map.json").exists() or \
        (src / "endpoint_to_live_map.json").write_text(json.dumps(live_results, indent=2))

    # 6. remediation plan + top-level report + branch summary
    _write_remediation_plan(src, merged, traces, live_results, branch_summary)
    _write_report_html(base, inventory, merged, traces, live_results,
                       branch_summary, total_findings)

    ctx.log("OK", "code_intel",
            f"code_intel complete: {total_findings} findings across {len(branches)} branches → "
            f"{base}/REPORT.html")


# ── small utilities ──────────────────────────────────────────────────────────
def _read_file_list(path):
    if not path or not Path(path).is_file():
        return []
    return [l.strip() for l in Path(path).read_text().splitlines()
            if l.strip() and not l.startswith("#")]


def _write_remediation_plan(src, merged, traces, live_results, branch_summary):
    lines = ["# Remediation plan (v3 source-code intelligence)", "",
             f"_Generated {datetime.utcnow().isoformat()}Z_", "",
             "## Priority order", ""]
    hi = [t for t in traces if t["severity"] == "HIGH"]
    if hi:
        lines.append("### 1. High-severity source→sink traces")
        for t in hi[:20]:
            lines.append(f"- **{t['possible_vuln']}** — `{t['file']}:{t['line']}` "
                         f"({t['function'] or 'handler'}). Fix: {t['missing_control']}. "
                         f"Test: {t['how_to_test_live']}.")
        lines.append("")
    orphans = [r for r in live_results if "/admin" in r["normalised"].lower()
               and r.get("reachable") and not r.get("auth_required_observed")]
    if orphans:
        lines.append("### 2. Live admin routes without an auth challenge")
        for r in orphans[:20]:
            lines.append(f"- `{r['method']} {r['url']}` → HTTP {r['status']}. "
                         f"Enforce auth+authorization at the edge and in the handler.")
        lines.append("")
    if merged.get("secrets"):
        lines.append("### 3. Hardcoded secrets")
        lines.append(f"- {len(merged['secrets'])} secret(s) in source — rotate each and "
                     f"move to a secret manager. See `secrets_findings.json`.")
        lines.append("")
    lines += ["## Branch coverage", ""]
    for b, c in branch_summary.items():
        lines.append(f"- `{b}`: {c}")
    (src / "remediation_plan.md").write_text("\n".join(lines))


def _write_report_html(base, inventory, merged, traces, live_results,
                       branch_summary, total_findings):
    fw = ", ".join(merged["stack"].get("frameworks", [])) or "unknown"
    rows_tr = "".join(
        f"<tr><td>{t['severity']}</td><td>{t['possible_vuln']}</td>"
        f"<td>{_esc(t['file'])}:{t['line']}</td><td>{_esc(t['sink'])}</td>"
        f"<td>{_esc(t['missing_control'])}</td></tr>"
        for t in traces[:200])
    rows_live = "".join(
        f"<tr><td>{r.get('status')}</td><td>{r['method']}</td>"
        f"<td>{_esc(r['url'])}</td><td>{'yes' if r.get('auth_required_observed') else 'no'}</td>"
        f"<td>{_esc(r['file'])}</td></tr>"
        for r in live_results[:200])
    rows_br = "".join(f"<tr><td>{b}</td><td>{c}</td></tr>"
                      for b, c in branch_summary.items())
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>TBHM v3 — Source-Code Intelligence Report</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#111;background:#fafafa}}
 h1{{margin:0 0 .3rem}} .sub{{color:#666;margin-bottom:1.5rem}}
 .cards{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem}}
 .card{{background:#fff;border:1px solid #e2e2e2;border-radius:8px;padding:1rem 1.3rem;min-width:120px}}
 .card b{{font-size:1.6rem;display:block}}
 table{{border-collapse:collapse;width:100%;background:#fff;margin:.5rem 0 2rem}}
 th,td{{border:1px solid #e2e2e2;padding:.45rem .6rem;text-align:left;vertical-align:top;font-size:13px}}
 th{{background:#f0f0f0}} code{{background:#f0f0f0;padding:0 .3rem;border-radius:3px}}
</style></head><body>
<h1>TBHM v3 — Source-Code Intelligence</h1>
<div class="sub">Read-only static map + reachability-only live mapping. Generated {datetime.utcnow().isoformat()}Z</div>
<div class="cards">
 <div class="card"><b>{len(merged['routes'])}</b>routes</div>
 <div class="card"><b>{len(traces)}</b>source→vuln traces</div>
 <div class="card"><b>{len(merged['secrets'])}</b>secrets</div>
 <div class="card"><b>{sum(1 for r in live_results if r.get('reachable'))}</b>live reachable</div>
 <div class="card"><b>{total_findings}</b>findings</div>
</div>
<p><b>Frameworks:</b> {_esc(fw)} &nbsp; <b>Primary language:</b> {_esc(merged['stack'].get('primary_language','?'))}
 &nbsp; <b>Package managers:</b> {_esc(', '.join(merged['stack'].get('package_managers', [])) or '?')}</p>

<h2>Branch coverage</h2>
<table><tr><th>Branch</th><th>Items</th></tr>{rows_br}</table>

<h2>Source → vulnerability traces</h2>
<table><tr><th>Sev</th><th>Possible vuln</th><th>Location</th><th>Sink</th><th>Missing control</th></tr>{rows_tr}</table>

<h2>Endpoint → live map (reachability only)</h2>
<table><tr><th>Status</th><th>Method</th><th>URL</th><th>Auth challenge</th><th>Source</th></tr>{rows_live}</table>

<p class="sub">Exploit confirmation is intentionally delegated to the consented active phases
(add_sqli, injections, business_logic, access_control). This report provides hypotheses and a safe test plan only.</p>
</body></html>"""
    (base / "REPORT.html").write_text(html)


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))
