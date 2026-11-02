"""
Phase: custom_nuclei   (v2.11)

Runs the bundled TBHM custom nuclei template set (nuclei-templates/tbhm/).

These are curated for the LOW / INFO band the user explicitly wants surfaced:
missing security headers, weak cookie flags, version/tech disclosure, permissive
CORS, exposed dotfiles/backups, directory listing, dangerous HTTP methods, and
verbose error pages.

Unlike vuln_scan (which honours the profile's severity floor and usually drops
info/low to cut noise), this phase captures EVERY severity the custom templates
emit — that is the whole point: "even if it's low, I still want it."

If nuclei is installed but its official template store is empty, bootstrap is
invoked first so the run isn't silently empty.
"""
from __future__ import annotations
from core import ratelimit
import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from core import noise_filter, bootstrap, nuclei_runtime
from core.targets import get_root_domains


def run(ctx):
    if not ctx.profile.get('active_probes', True):
        return
    if not shutil.which("nuclei"):
        ctx.log("WARN", "custom_nuclei", "nuclei not in PATH — skipping (run install.sh)")
        return

    # Resolve the bundled template directory.
    info = bootstrap.ensure_custom_templates(log=ctx.log)
    tdir = Path(info["path"])
    if not info["present"]:
        ctx.log("WARN", "custom_nuclei", f"custom template dir not found: {tdir}")
        return

    # Make sure nuclei has *some* official templates too (DSL helpers etc. work
    # regardless, but this also self-heals the empty-store case).
    # No hidden network download/setup during a scan.
    nuclei_runtime.installed_templates(bootstrap)

    # Build target list (alive hosts + crawled URLs).
    targets = []
    for fname in ("alive.txt", "crawl_urls.txt", "all_urls.txt"):
        f = ctx.output / "recon" / fname
        if f.exists():
            targets.extend(ctx.runner.read_lines(f))
    if not targets:
        # Fall back to the raw targets so a bare `-d host` run still scans.
        targets = [t if t.startswith("http") else f"https://{t}" for t in ctx.targets]

    in_scope = set(get_root_domains(ctx))
    from core.targets import target_scope_allows
    targets = [t for t in targets
               if target_scope_allows(ctx, t) and not noise_filter.is_noise(t, in_scope_hosts=in_scope)[0]]
    targets = list(dict.fromkeys(targets))
    if not targets:
        ctx.log("WARN", "custom_nuclei", "no targets — skipping")
        return

    ndir = ctx.output / "nuclei"
    ndir.mkdir(exist_ok=True)
    tfile = ndir / "custom_targets.txt"
    tfile.write_text("\n".join(targets[:1000]))
    out_file = ndir / "tbhm_custom.jsonl"

    intensity = getattr(ctx, "intensity", "standard")
    rate_limit = ratelimit.cap(ctx.profile, {"quick": 40, "standard": 80, "deep": 150, "insane": 300}.get(intensity, 80))
    timeout_min = {"quick": 6, "standard": 12, "deep": 25, "insane": 40}.get(intensity, 12)

    # Allow the user to widen/narrow severities; default = everything.
    sev = getattr(ctx.args, "nuclei_severity", None) or "info,low,medium,high,critical"

    cmd = [
        "nuclei",
        "-l", str(tfile),
        "-t", str(tdir),
        "-severity", sev,
        "-jsonl", "-o", str(out_file),
        "-rl", str(rate_limit),
        "-timeout", "12",
        "-retries", "1",
        "-silent", "-no-color",
        "-disable-update-check",
    ]
    extra_dir = getattr(ctx.args, "custom_templates", None)
    if extra_dir and Path(extra_dir).is_dir():
        cmd += ["-t", str(extra_dir)]
    proxy = getattr(ctx.args, "proxy", None)
    if proxy:
        cmd += ["-proxy", proxy]

    ctx.log("INFO", "custom_nuclei",
            f"━━━ TBHM custom sweep: {sum(1 for _ in tdir.rglob('*.yaml'))} templates × "
            f"{len(targets[:1000])} targets (sev={sev}) ━━━")
    out_file.unlink(missing_ok=True)
    rc, stdout, stderr = ctx.runner.run(cmd, timeout=timeout_min * 60, log_name="custom_nuclei")
    if rc not in (0, 1):
        err = " ".join((stderr or stdout or "").split())[:240]
        ctx.log("WARN", "custom_nuclei", f"sweep exited rc={rc}: {err or 'no stderr/stdout'}")

    if not out_file.exists():
        err = " ".join((stderr or stdout or "").split())[:240]
        ctx.log("WARN", "custom_nuclei", f"no output produced{': ' + err if err else ''}")
        return

    n = 0
    for obj in nuclei_runtime.records(ctx, out_file):
        finding = _to_finding(obj)
        if not finding:
            continue
        if noise_filter.is_noise(finding.get("url", ""), in_scope_hosts=in_scope)[0]:
            continue
        ctx.save_finding(finding)
        n += 1
    ctx.log("OK", "custom_nuclei", f"custom_nuclei: {n} findings (low/info included)")


def _to_finding(obj: dict) -> dict | None:
    info = obj.get("info") or {}
    template_id = obj.get("template-id") or obj.get("templateID", "")
    matched_at = obj.get("matched-at") or obj.get("matchedAt", "")
    if not matched_at or not template_id:
        return None
    sev_map = {"INFO": "INFO", "LOW": "LOW", "MEDIUM": "MEDIUM",
               "HIGH": "HIGH", "CRITICAL": "CRITICAL", "UNKNOWN": "LOW"}
    severity = sev_map.get((info.get("severity") or "info").upper(), "LOW")
    extracted = obj.get("extracted-results") or []
    evidence = (" | ".join(extracted) if extracted
                else obj.get("matcher-name", "")
                or f"Matched by TBHM template {template_id}")
    mrs = {"CRITICAL": 90, "HIGH": 80, "MEDIUM": 55, "LOW": 35, "INFO": 20}.get(severity, 30)
    finding = {
        "phase":       "custom_nuclei",
        "template_id": template_id,
        "severity":    severity,
        "confidence":  "HIGH",
        "title":       f"[tbhm] {info.get('name', template_id)}",
        "target":      urlparse(matched_at).hostname or matched_at,
        "url":         matched_at,
        "method":      (obj.get("request") or "").split(" ", 1)[0] or "GET",
        "description": info.get("description", "") or f"TBHM template: {template_id}",
        "evidence":    evidence,
        "impact":      f"Severity: {severity}. Tags: {', '.join(info.get('tags', []))}",
        "remediation": info.get("remediation", "") or "See template metadata.",
        "cwe":         (info.get("classification", {}) or {}).get("cwe-id", "") or "",
        "references":  info.get("reference") or [],
        "reproducer_curl": f"curl -i -sk '{matched_at}'",
        "request_raw": (obj.get("request") or "")[:4000],
        "response_raw":(obj.get("response") or "")[:4000],
        "mrs_score":   mrs,
    }
    finding.update(nuclei_runtime.evidence_fields(obj))
    return finding
