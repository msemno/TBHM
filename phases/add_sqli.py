"""TBHM v3 phase: focused SQL injection verification add-on.

This wraps the v2.24 add-on SQLi engine into the native TBHM phase/reporting
model. It remains detection-only: no database dumps or extraction actions.
"""
from __future__ import annotations

from urllib.parse import urlparse, parse_qs

from tbhm_addons.mod_sqli import SqliModule
from .addons_common import evidence_dir, save_json, write_md, make_logger, confidence


def _candidate_urls(ctx):
    explicit = getattr(ctx.args, "addon_sqli_target", None)
    if explicit:
        return [explicit]

    urls_file = ctx.output / "recon" / "urls.txt"
    urls = ctx.runner.read_lines(urls_file) if urls_file.exists() else []
    cands = []
    for u in urls:
        try:
            if parse_qs(urlparse(u).query):
                cands.append(u)
        except Exception:
            continue
    max_urls = max(1, int(getattr(ctx.args, "addon_sqli_max_urls", 30) or 30))
    return cands[:max_urls]


def run(ctx):
    phase_name = "add_sqli"
    if not ctx.profile.get("send_payloads", False):
        ctx.log("INFO", phase_name, "profile disallows payloads - skipping focused SQLi add-on")
        return

    targets = _candidate_urls(ctx)
    out = evidence_dir(ctx, "01_add_sqli")
    if not targets:
        write_md(out / "ADD_SQLI_NOT_RUN.md", "ADD-SQLI Not Run", [
            ("Reason", "No URL with query-string parameters was available. Run recon/discovery first or pass --addon-sqli-target 'https://host/path?id=1'."),
            ("Safety", "This phase is detection-only and does not dump database contents."),
        ])
        ctx.save_finding({
            "phase": phase_name, "severity": "INFO", "confidence": "MEDIUM",
            "title": "Focused SQLi add-on not tested", "target": ctx.targets[0],
            "description": "No parameterized URL was supplied or discovered for the v3 ADD-SQLI phase.",
            "evidence": str(out / "ADD_SQLI_NOT_RUN.md"),
            "impact": "SQLi coverage is incomplete for this run.",
            "remediation": "Supply a representative parameterized URL with --addon-sqli-target or run discovery before ADD-SQLI.",
        })
        return

    delay = float(getattr(ctx.args, "addon_sqli_delay", 1.0) or 1.0)
    time_delay = int(getattr(ctx.args, "addon_sqli_time_delay", 5) or 5)
    verify_tls = not bool(getattr(ctx.args, "addon_sqli_no_tls_verify", False))
    sqlmap_fallback = bool(getattr(ctx.args, "addon_sqli_sqlmap", False))
    mod = SqliModule(delay_between_requests=delay, time_delay_s=time_delay, verify_tls=verify_tls)

    all_results = []
    total_findings = 0
    logger = make_logger(ctx, "ADD-SQLI", target=targets[0])
    for idx, url in enumerate(targets, start=1):
        ctx.log("INFO", phase_name, f"ADD-SQLI testing {idx}/{len(targets)}: {url[:120]}")
        with logger.phase("ADD-SQLI", "Focused SQL injection detection", silent=getattr(ctx.args, "silent", False)) as ph:
            res = mod.run(url, phase=ph, run_sqlmap_on_hit=sqlmap_fallback)
        d = res.to_dict()
        all_results.append(d)
        for f in d.get("findings", []):
            total_findings += 1
            technique = f.get("technique", "unknown")
            param = f.get("parameter", "")
            ctx.save_finding({
                "phase": phase_name,
                "severity": "HIGH",
                "confidence": confidence(f.get("confidence", "firm")),
                "title": f"Focused SQL injection candidate ({technique})",
                "target": ctx.targets[0] if ctx.targets else url,
                "url": f.get("url", url),
                "method": f.get("method", "GET"),
                "parameter": param,
                "payload": f.get("payload", ""),
                "description": "The v3 ADD-SQLI verifier observed SQL parser/error, boolean differential, or timing behavior consistent with SQL injection. The module is detection-only and does not dump database data.",
                "evidence": f.get("evidence", ""),
                "impact": "A confirmed SQL injection can allow unauthorized data access, authentication bypass, data modification, or database-specific command execution depending on privileges and DBMS exposure.",
                "remediation": "Use parameterized queries/prepared statements, remove string-concatenated SQL, apply strict input validation, least-privilege DB accounts, and add regression tests for this parameter.",
                "cwe": "CWE-89",
                "cvss": "8.8",
                "mrs_score": 90,
                "request_raw": f"GET {f.get('url', url)}\nParameter: {param}\nPayload: {f.get('payload', '')}",
            })

    save_json(out / "add_sqli_results.json", all_results)
    write_md(out / "ADD_SQLI_SUMMARY.md", "ADD-SQLI Focused SQL Injection Summary", [
        ("Targets tested", "\n".join(f"- {u}" for u in targets)),
        ("Findings", str(total_findings)),
        ("Safety boundary", "Detection only. No database dumping, credential extraction, destructive writes, or privilege escalation are performed."),
        ("Evidence", str(out / "add_sqli_results.json")),
    ])
    ctx.log("OK", phase_name, f"ADD-SQLI complete: {total_findings} finding(s)")
