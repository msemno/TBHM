"""
Phase: nuclei_extended

Runs multiple targeted nuclei sweeps. v2.16-fixed improves the automation by:
  - bootstrapping/locating official templates before scanning;
  - using absolute workflow paths instead of fragile relative `workflows/`;
  - falling back from workflow mode to tag mode if workflows are unavailable;
  - logging useful stderr snippets instead of silently swallowing failed sweeps;
  - keeping JSONL parsing/reporting compatible with previous versions.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse

from core import bootstrap, noise_filter, ratelimit
from core import nuclei_runtime
from core.targets import get_root_domains


# Each entry: (sweep_id, nuclei_args, severity_floor, mrs_base)
# severity_floor is informational metadata kept for compatibility/reporting.
SWEEPS = [
    ("cves",          ["-tags", "cve", "-severity", "medium,high,critical"], "MEDIUM", 80),
    ("owasp",         ["-tags", "owasp,owasp-top10"],                         "MEDIUM", 75),
    ("exposures",     ["-tags", "exposure,config,files,backup,dotfile"],      "LOW",    65),
    ("misconfig",     ["-tags", "misconfig,security-headers,cors"],           "LOW",    55),
    ("takeover",      ["-tags", "takeover,dns"],                              "HIGH",   85),
    ("default-login", ["-tags", "default-login,panel"],                       "HIGH",   80),
    ("injections",    ["-tags", "xss,sqli,ssrf,lfi,rce,xxe,ssti"],            "MEDIUM", 75),
    ("graphql",       ["-tags", "graphql,introspection"],                     "LOW",    65),
    ("api-fuzz",      ["-tags", "fuzz,api"],                                  "MEDIUM", 70),
    # special: resolved at runtime to absolute workflow path; falls back to tags.
    ("tech-stack",    ["__TECH_STACK_WORKFLOWS__"],                           "LOW",    60),
]


def run(ctx):
    if not shutil.which("nuclei"):
        ctx.log("WARN", "nuclei_extended", "nuclei not in PATH — skipping")
        return

    ctx.log("INFO", "nuclei_extended", "checking nuclei templates...")
    tpl_info = nuclei_runtime.installed_templates(bootstrap)
    template_root = bootstrap.nuclei_templates_root()
    if not template_root:
        ctx.log("WARN", "nuclei_extended", "official nuclei template root not found; sweeps may rely on nuclei defaults")
    elif tpl_info.get("count", 0) < 100:
        ctx.log("WARN", "nuclei_extended", f"low nuclei template count ({tpl_info.get('count')}); coverage will be degraded")

    targets = _collect_targets(ctx)
    in_scope = set(get_root_domains(ctx))
    targets = [t for t in targets if not noise_filter.is_noise(t, in_scope_hosts=in_scope)[0]]
    targets = list(dict.fromkeys(targets))

    if not targets:
        ctx.log("WARN", "nuclei_extended", "no targets — skipping")
        return

    nuclei_dir = ctx.output / "nuclei"
    nuclei_dir.mkdir(exist_ok=True)
    targets_file = nuclei_dir / "extended_targets.txt"
    targets_file.write_text("\n".join(targets[:500]) + "\n")

    intensity = getattr(ctx, "intensity", "standard")
    rate_limit = ratelimit.cap(ctx.profile, {"quick": 30, "standard": 75, "deep": 150, "insane": 300}.get(intensity, 75))
    timeout_min = {"quick": 5, "standard": 10, "deep": 25, "insane": 40}.get(intensity, 10)

    ctx.log("INFO", "nuclei_extended", f"━━━ Extended nuclei sweep: {len(SWEEPS)} combos × {len(targets[:500])} targets ━━━")

    total_findings = 0
    for sweep_id, extra_args, sev_floor, mrs_base in SWEEPS:
        resolved_args = _resolve_sweep_args(extra_args, template_root)
        if not resolved_args:
            ctx.log("WARN", "nuclei_extended", f"  sweep '{sweep_id}': no usable templates/workflows")
            continue

        out_file = nuclei_dir / f"{sweep_id}.jsonl"
        if out_file.exists():
            out_file.unlink()

        cmd = [
            "nuclei",
            "-l", str(targets_file),
            "-jsonl", "-o", str(out_file),
            "-rl", str(rate_limit),
            "-timeout", "12",
            "-retries", "1",
            "-silent", "-no-color",
            "-stats", "-si", "10",
            "-disable-update-check",
        ] + resolved_args

        # If we know the official root and the sweep is tag-based, pass it
        # explicitly. This avoids the common "no templates found" issue when
        # nuclei's default config path is wrong.
        if template_root and "-t" not in cmd and "-w" not in cmd:
            cmd += ["-t", str(template_root)]

        ctx.log("INFO", "nuclei_extended", f"  → sweep '{sweep_id}'…")
        out_file.unlink(missing_ok=True)
        rc, stdout, stderr = ctx.runner.run(cmd, timeout=timeout_min * 60, log_name=f"nuclei_extended_{sweep_id}")
        state = nuclei_runtime.interpret_execution(rc, stderr, stdout, out_file.exists() and out_file.stat().st_size > 0)
        if state in ('timeout', 'tool-error', 'tool-incompatible', 'missing-templates', 'killed', 'cancelled'):
            ctx.log('WARN', 'nuclei_extended', f"  sweep '{sweep_id}' {state} rc={rc}: {_short(stderr or stdout)}")
            if not out_file.exists():
                continue
        elif _looks_like_no_templates(stderr + stdout):
            ctx.log("WARN", "nuclei_extended", f"  sweep '{sweep_id}': no matching templates available")
            continue

        if not out_file.exists():
            ctx.log("INFO", "nuclei_extended", f"  sweep '{sweep_id}': no matches (no output file)")
            continue

        n_sweep = 0
        for obj in nuclei_runtime.records(ctx, out_file):
            finding = _to_finding(obj, sweep_id, mrs_base)
            if not finding:
                continue
            if noise_filter.is_noise(finding.get("url", ""), in_scope_hosts=in_scope)[0]:
                continue
            ctx.save_finding(finding)
            n_sweep += 1
        ctx.log("OK", "nuclei_extended", f"  sweep '{sweep_id}': {n_sweep} findings")
        total_findings += n_sweep

    ctx.log("OK", "nuclei_extended", f"nuclei_extended: {total_findings} total findings")


def _collect_targets(ctx) -> list[str]:
    targets: list[str] = []
    for rel in (("recon", "alive.txt"), ("recon", "crawl_urls.txt"), ("recon", "all_urls.txt")):
        f = ctx.output.joinpath(*rel)
        if f.exists():
            targets.extend(ctx.runner.read_lines(f))
    if not targets:
        targets = [t if str(t).startswith("http") else f"https://{t}" for t in ctx.targets]
    from core.targets import target_scope_allows
    return [u for u in targets if target_scope_allows(ctx, u)]


def _resolve_sweep_args(extra_args: list[str], template_root: Path | None) -> list[str]:
    if extra_args == ["__TECH_STACK_WORKFLOWS__"]:
        if template_root:
            workflows = template_root / "workflows"
            if workflows.is_dir() and any(workflows.rglob("*.yaml")):
                return ["-w", str(workflows), "-tags", "wordpress,jira,jenkins,gitlab,confluence,atlassian"]
        # Fallback when workflows are not installed: still run relevant tags.
        return ["-tags", "wordpress,jira,jenkins,gitlab,confluence,atlassian"]
    return list(extra_args)


def _looks_like_no_templates(text: str) -> bool:
    t = (text or "").lower()
    needles = [
        "no templates provided",
        "no templates found",
        "could not find template",
        "no templates were found",
        "no matching templates",
    ]
    return any(n in t for n in needles)


def _short(text: str, n: int = 240) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[:n] if text else "no stderr/stdout"


# ──────────────────────────────────────────────────────────────────────────────
# Map nuclei JSON output → TBHM finding
# ──────────────────────────────────────────────────────────────────────────────

def _to_finding(obj: dict, sweep_id: str, mrs_base: int) -> dict | None:
    info = obj.get("info") or {}
    template_id = obj.get("template-id") or obj.get("templateID", "")
    matched_at = obj.get("matched-at") or obj.get("matchedAt", "") or obj.get("host", "")
    severity = (info.get("severity") or "info").upper()

    if not matched_at or not template_id:
        return None

    sev_map = {"INFO": "INFO", "LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL", "UNKNOWN": "LOW"}
    severity = sev_map.get(severity, "LOW")

    # ---- Subdomain-takeover false-positive control -------------------------
    # subzy/takeover templates self-report HIGH on a fingerprint BANNER
    # ("There isn't a GitHub Pages site here", "NoSuchBucket", ...). A banner only
    # proves the target is UNCLAIMED, not that the attacker controls it, so it is a
    # LEAD, not a confirmed takeover. Downgrade it regardless of the template's
    # self-reported severity — BUT never downgrade a genuine CVE that merely carries
    # a takeover tag. Only takeover findings are touched; all other nuclei findings
    # are returned exactly as before (no extra fields added).
    _tags_raw = info.get("tags") or ""
    _tags_l = (_tags_raw if isinstance(_tags_raw, str) else ",".join(map(str, _tags_raw))).lower()
    _tid_l = (template_id or "").lower()
    _is_cve = ("cve" in _tags_l) or _tid_l.startswith("cve-")
    _is_takeover = (not _is_cve) and (
        ("takeover" in _tags_l) or ("takeover" in _tid_l) or ("subzy" in _tid_l)
    )
    _takeover_lead = False
    if _is_takeover:
        # Banner-only match = no proof of control. Treat as a low-confidence lead
        # at LOW severity so it never lands in the confirmed/high buckets.
        severity = "LOW"
        _takeover_lead = True
    curl_cmd = _build_curl_from_nuclei(obj, matched_at)

    references = info.get("reference") or []
    if isinstance(references, str):
        references = [references]
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]

    finding = {
        "phase":       "nuclei_extended",
        "template_id": template_id,
        "severity":    severity,
        "confidence":  "HIGH",
        "title":       f"[{sweep_id}] {info.get('name', template_id)}",
        "target":      urlparse(matched_at).hostname or matched_at,
        "url":         matched_at,
        "method":      (obj.get("request") or "").split(" ", 1)[0] or "GET",
        "payload":     "",
        "description": info.get("description", "") or f"nuclei template: {template_id}",
        "evidence":    (obj.get("extracted-results") and " | ".join(map(str, obj["extracted-results"])) or obj.get("matcher-name", "") or f"Matched by nuclei template {template_id}"),
        "impact":      f"Severity per nuclei: {severity}. Tags: {', '.join(tags)}",
        "remediation": info.get("remediation", "") or "See nuclei template metadata.",
        "cwe":         (info.get("classification", {}) or {}).get("cwe-id", "") or "",
        "cvss":        str((info.get("classification", {}) or {}).get("cvss-score", "")) or "",
        "references":  references,
        "request_raw": (obj.get("request") or "")[:8000],
        "response_raw": (obj.get("response") or "")[:8000],
        "reproducer_curl": curl_cmd,
        "mrs_score":   _adj_mrs(mrs_base, severity),
    }
    # Only takeover LEADS get lead metadata — normal findings stay untouched so the
    # strict classifier's own defaults (incl. its validation-guidance text) apply.
    if _takeover_lead:
        finding["confidence"] = "LOW"
        finding["finding_class"] = "LEAD"
        finding["title"] = "[LEAD] " + finding["title"]
        finding["validation_required"] = (
            "Unconfirmed subdomain takeover: nuclei matched only a fingerprint banner "
            "on the target, which proves the backing resource is unclaimed but NOT that "
            "you control it. Verify the dangling DNS record (CNAME/NS) still points to a "
            "claimable provider, then demonstrate authorized claim of that resource before "
            "reporting. Do not submit on the banner alone."
        )
        finding["impact"] = (
            "POTENTIAL subdomain takeover (unverified). " + finding.get("impact", "")
        ).strip()
    finding.update(nuclei_runtime.evidence_fields(obj))
    if _takeover_lead:
        finding['finding_class'] = 'lead'
    return finding


def _adj_mrs(base: int, severity: str) -> int:
    bumps = {"CRITICAL": +10, "HIGH": +5, "MEDIUM": 0, "LOW": -10, "INFO": -20}
    return max(20, min(99, base + bumps.get(severity, 0)))


def _build_curl_from_nuclei(obj: dict, url: str) -> str:
    """Extract or synthesize a curl command from nuclei output."""
    req = obj.get("request") or ""
    if not req:
        return f"curl -i -sk '{url}'"

    first_line = req.split("\n", 1)[0]
    parts = first_line.split(" ")
    method = parts[0] if parts else "GET"
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
        method = "GET"

    headers = []
    body_lines = []
    in_body = False
    for line in req.split("\n")[1:]:
        if not in_body:
            if line.strip() == "":
                in_body = True
                continue
            if ":" in line:
                k, _, v = line.partition(":")
                k, v = k.strip(), v.strip()
                if k.lower() in ("host", "content-length"):
                    continue
                if v:
                    headers.append(f"-H {repr(f'{k}: {v}')}")
        else:
            body_lines.append(line)
    body = "\n".join(body_lines).strip()

    cmd = [f"curl -i -sk -X {method}"]
    cmd += headers
    if body:
        body_escaped = body.replace("'", "'\\''")
        cmd.append(f"--data '{body_escaped}'")
    cmd.append(f"'{url}'")
    return " \\\n     ".join(cmd)
