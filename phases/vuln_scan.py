"""Phase: vuln_scan -- nuclei + subdomain takeover."""
from __future__ import annotations
import json
from pathlib import Path

from core import bootstrap, nuclei_runtime


def run(ctx):
    alive_file = ctx.output / "recon" / "alive.txt"
    if not alive_file.exists() or not ctx.runner.read_lines(alive_file):
        ctx.log("WARN", "vuln_scan", "no alive hosts - skipping")
        return
    if not ctx.profile.get("active_probes", True):
        ctx.log("INFO", "vuln_scan", "passive profile - skipping nuclei")
        return
    _nuclei(ctx, alive_file)
    _takeover(ctx, alive_file)


def _nuclei(ctx, alive_file):
    if not ctx.runner.has("nuclei"):
        ctx.log("WARN", "vuln_scan", "nuclei not installed - skipping")
        return
    from core.targets import target_scope_allows
    allowed = [u for u in ctx.runner.read_lines(alive_file) if target_scope_allows(ctx, u)]
    if not allowed:
        ctx.log('WARN', 'vuln_scan', 'no authorized nuclei input targets')
        return
    scoped_file = ctx.output/'scans/nuclei_targets.txt'
    scoped_file.parent.mkdir(parents=True, exist_ok=True)
    ctx.runner.write_lines(scoped_file, allowed)
    alive_file = scoped_file
    # Make the normal nuclei phase self-healing too; otherwise it can silently
    # run against an empty/default-misconfigured template store.
    nuclei_runtime.installed_templates(bootstrap)
    template_root = bootstrap.nuclei_templates_root()

    cfg = ctx.profile.get("nuclei", {})
    sevs = cfg.get("severity", ["critical", "high"])
    tags = cfg.get("tags", ["cve", "exposure", "misconfig"])

    # v2.11: CLI overrides. --nuclei-severity wins outright; --include-info just
    # appends low/info so the user can keep the profile floor but still see them.
    sev_override = getattr(ctx.args, "nuclei_severity", None)
    if sev_override:
        sevs = [s.strip() for s in sev_override.split(",") if s.strip()]
    elif getattr(ctx.args, "include_info", False):
        sevs = list(dict.fromkeys(list(sevs) + ["low", "info"]))
    extra_tags = getattr(ctx.args, "nuclei_tags", None)
    if extra_tags:
        tags = list(dict.fromkeys(list(tags) + [t.strip() for t in extra_tags.split(",") if t.strip()]))

    if not sevs:
        return
    out_jsonl = ctx.output / "scans" / "nuclei.jsonl"
    out_jsonl.parent.mkdir(exist_ok=True)
    cmd = ["nuclei", "-l", str(alive_file), "-jsonl", "-silent", "-no-color",
           "-disable-update-check",            # v2.11: don't stall on update check
           "-severity", ",".join(sevs)]
    if tags:
        cmd += ["-tags", ",".join(tags)]
    # Explicitly point nuclei at the discovered official template root when we
    # have one. This fixes environments where nuclei is installed but its config
    # does not know where templates live.
    if template_root:
        cmd += ["-t", str(template_root)]
    # v2.11: also run any user-supplied extra template directory.
    extra_dir = getattr(ctx.args, "custom_templates", None)
    if extra_dir and Path(extra_dir).is_dir():
        cmd += ["-t", str(extra_dir)]
    proxy = getattr(ctx.args, "proxy", None)
    if proxy:
        cmd += ["-proxy", proxy]
    rl = ctx.profile.get("rate_limit", {})
    cmd += ["-rl", str(rl.get("global_rps", 10))]
    cmd += ["-c", "25", "-bs", "25", "-o", str(out_jsonl)]
    ctx.log("INFO", "vuln_scan", f"running nuclei (sev={','.join(sevs)})...")
    out_jsonl.unlink(missing_ok=True)
    rc, out, err = ctx.runner.run(cmd, timeout=3600, log_name="nuclei")
    execution = nuclei_runtime.interpret_execution(rc, err, out,
                       out_jsonl.exists() and out_jsonl.stat().st_size > 0)
    if execution in ('tool-error', 'tool-incompatible', 'missing-templates', 'timeout', 'killed', 'cancelled'):
        ctx.log('WARN', 'vuln_scan', f'nuclei execution failed: {execution} (rc={rc})')
        if not out_jsonl.exists():
            return
    if not out_jsonl.exists():
        detail = " ".join((err or out or "").split())[:240]
        ctx.log("WARN", "vuln_scan",
                "nuclei produced no output file — run './tbhm.py --setup' to refresh templates "
                f"or check logs/nuclei.log{': ' + detail if detail else ''}")
        return
    n = 0
    for r in nuclei_runtime.records(ctx, out_jsonl):
        info = r.get("info", {})
        sev = (info.get("severity") or "info").upper()
        ctx.save_finding({
            **nuclei_runtime.evidence_fields(r),
            "request_raw": str(r.get('request') or '')[:8000],
            "response_raw": str(r.get('response') or '')[:8000],
            "phase": "vuln_scan",
            "template_id": r.get("template-id") or r.get("templateID", ""),
            "severity": sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "INFO",
            "confidence": "HIGH",
            "title": info.get("name") or r.get("template-id", "nuclei finding"),
            "target": r.get("host", ""),
            "url": r.get("matched-at", r.get("host", "")),
            "method": (r.get("type") or "").upper(),
            "description": info.get("description", ""),
            "evidence": str(r.get("matcher-name", ""))[:200] + " | " +
                        str(r.get("extracted-results", ""))[:300],
            "impact": info.get("impact") or "",
            "remediation": info.get("remediation") or "",
            "cwe": _cwe(info),
            "cvss": str(info.get("classification", {}).get("cvss-score", "")),
            "references": info.get("reference") or [],
            "mrs_score": 90,
        })
        n += 1
    ctx.log('OK' if rc == 0 else 'WARN', 'vuln_scan', f'nuclei: {n} observations; execution={execution}')


def _takeover(ctx, alive_file):
    if not ctx.runner.has("subzy"):
        return
    ctx.log("INFO", "vuln_scan", "running subzy for takeover...")
    rc, out, _ = ctx.runner.run(
        ["subzy", "run", "--targets", str(alive_file), "--hide_fails", "--vuln"],
        timeout=600, log_name="subzy"
    )
    for line in out.splitlines():
        if "VULNERABLE" in line.upper():
            ctx.save_finding({
                "phase": "vuln_scan",
                "severity": "HIGH",
                "confidence": "HIGH",
                "title": "Possible Subdomain Takeover",
                "target": ctx.targets[0],
                "evidence": line[:400],
                "description": "subzy flagged this host as vulnerable to takeover. "
                               "Verify by attempting to claim the upstream resource.",
                "impact": "Attacker can host arbitrary content on a target subdomain.",
                "remediation": "Remove the dangling DNS record or claim the resource.",
                "cwe": "CWE-350",
                "mrs_score": 70,
            })


def _cwe(info: dict) -> str:
    cwe = (info.get("classification", {}) or {}).get("cwe-id", []) or []
    if isinstance(cwe, str):
        return cwe
    return ",".join(map(str, cwe))
