"""
Phase: curl_verify

Third verification layer (after audit's shadow replay + verify phase).
Uses real `curl` subprocess to:

  1. Re-run every HIGH / CRITICAL finding's reproducer_curl and confirm it
     still works. Sets `curl_verified = true/false` on the finding.
  2. Probe every alive target with curl_probes (TRACE / WebDAV / Host header
     injection / method override / admin bypass / Range DoS / server-status).

Why a third layer? Because curl is what triagers run. If `curl` reproduces
the bug, the report is bullet-proof. If `curl` doesn't reproduce, you don't
embarrass yourself.
"""
from __future__ import annotations
import json
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from core import curl_probes, noise_filter
from core.targets import get_root_domains


def run(ctx):
    if not shutil.which("curl"):
        ctx.log("WARN", "curl_verify", "curl not in PATH — skipping")
        return

    in_scope = set(get_root_domains(ctx))

    # Part 1: liveness observation only.  A generic GET cannot verify the
    # original method, identity, payload, invariant or negative control.
    rows = ctx.storage.conn.execute(
        "SELECT id,url,severity,title,phase,request_raw FROM findings "
        "WHERE severity IN ('HIGH','CRITICAL') AND url != ''"
    ).fetchall()
    observed = 0
    for row in rows[:200]:
        if ctx.runner._cancel_event.is_set():
            return
        url = row["url"]
        if noise_filter.is_noise(url, in_scope_hosts=in_scope)[0]:
            continue
        rc, stdout, stderr = curl_probes.run_captured_curl(ctx,
            ["curl", "-sk", "-i", "--max-time", "10", "-A", "Mozilla/5.0", url],
            timeout=15)
        tx = ctx._last_curl_capture['test_execution_id']
        status = next((line.strip() for line in stdout.splitlines() if line.startswith("HTTP/")), "")
        obs_id = ctx.storage.save_observation(
            phase="curl_verify", observation_type="endpoint_liveness", target=url,
            summary=f"curl returned {status or 'no HTTP status'}",
            evidence={"returncode": rc, "status_line": status, "body_length_tail": len(stdout),
                      "stderr": stderr[:1000], "finding_id": row["id"]},
            test_execution_id=tx,
        )
        ctx.storage.complete_test_execution(
            tx, status="inconclusive",
            result_summary="Endpoint liveness observed; original vulnerability was not replayed and is not confirmed.",
            extra={"observation_id": obs_id})
        observed += 1

    # Part 2: bounded curl probes.  Probe signals are supported candidates until
    # a probe-specific assertion, negative control and repeatability proof exist.
    alive_file = ctx.output / "recon" / "alive.txt"
    if not alive_file.exists():
        ctx.log("OK", "curl_verify", f"liveness observations={observed}; no alive.txt for probe stage")
        return
    alive = ctx.runner.read_lines(alive_file)
    if not alive:
        return
    from core import ratelimit
    _rps = ratelimit.cap(ctx.profile, ctx.profile.get("rate_limit", {}).get("global_rps", 10))
    curl_probes.set_rate(_rps)
    probe_findings = 0
    for target in alive[:30]:
        if noise_filter.is_noise(target, in_scope_hosts=in_scope)[0]:
            continue
        host = urlparse(target).hostname or target
        try:
            probe_results = curl_probes.run_all(target, ctx=ctx)
        except Exception as exc:
            ctx.log("WARN", "curl_verify", f"probe error on {target}: {exc}")
            continue
        for result in probe_results:
            tx = result['test_execution_id']
            fid = ctx.save_finding({
                "phase": "curl_verify", "severity": result["severity"], "confidence": "MEDIUM",
                "title": result["title"], "target": host, "url": target,
                "evidence": result["evidence"],
                "description": f"A bounded curl probe produced a security-relevant signal for {result['probe']}. "
                               "The record remains supported until a probe-specific negative control and repeatability proof pass.",
                "impact": "Potential control weakness; verify the actual security boundary before reporting.",
                "remediation": _remediation_for(result["probe"]), "cwe": _cwe_for(result["probe"]),
                "mrs_score": _mrs_for(result["severity"]), "reproducer_curl": result["reproducer_curl"],
                "response_raw": result.get('response_raw', ''),
                "http_exchange_refs": result.get('http_exchange_refs', []),
                "evidence_capture_status": result.get('evidence_capture_status', 'missing-http-exchange'),
                "finding_class": "supported", "verified": False,
                "verification_method": "bounded curl probe signal; strict proof pending",
                "test_execution_id": tx,
            })
            ctx.storage.complete_test_execution(
                tx, status="manual-review-required",
                result_summary=f"Probe signal saved as supported candidate finding_id={fid}.")
            probe_findings += 1
    ctx.log("OK", "curl_verify", f"liveness observations={observed}; supported probe candidates={probe_findings}")


# ──────────────────────────────────────────────────────────────────────────────
# Lookups
# ──────────────────────────────────────────────────────────────────────────────
def _remediation_for(probe_id: str) -> str:
    d = {
        "trace_method": "Disable TRACE method in web server config (TraceEnable off in Apache, modules-disabled in nginx).",
        "options_method": "Disable dangerous HTTP methods (PUT, DELETE, CONNECT, PATCH) in web server config if not required.",
        "webdav":       "Disable WebDAV unless explicitly required; restrict by IP.",
        "host_header":  "Use a strict allowlist of expected Host header values; do not echo the Host into Location or canonical links.",
        "method_override": "Reject X-HTTP-Method-Override headers unless explicitly needed by your API.",
        "admin_bypass": "Do not trust X-Original-URL / X-Rewrite-URL from clients. Strip these headers at the edge.",
        "range_dos":    "Patch Apache to a non-vulnerable version, or limit Range header complexity at the WAF.",
        "server_status": "Restrict /server-status and /server-info to local IPs only.",
        "cors_check": "Implement a strict CORS policy. Avoid reflecting arbitrary origins and only allow trusted domains.",
        "sensitive_files": "Remove sensitive files from the web root and restrict access to configuration directories.",
        "admin_paths": "Restrict access to admin and debug interfaces to internal IP addresses or via VPN.",
        "open_redirect": "Validate redirect targets against an allowlist and avoid using user-supplied URLs for redirects.",
        "reflection": "Ensure all user-supplied input is properly encoded before being reflected in the response.",
        "sql_errors": "Disable verbose error messages in production and use parameterized queries to prevent SQL injection.",
        "path_traversal": "Validate and sanitize file paths; avoid using user-supplied input directly in file operations.",
        "api_roots": "Ensure all API endpoints are properly authenticated and authorized.",
    }
    return d.get(probe_id, "See evidence and research the vulnerability type.")


def _cwe_for(probe_id: str) -> str:
    d = {
        "trace_method":     "CWE-200",
        "options_method":   "CWE-16",
        "webdav":           "CWE-285",
        "host_header":      "CWE-644",
        "method_override":  "CWE-650",
        "admin_bypass":     "CWE-287",
        "range_dos":        "CWE-400",
        "server_status":    "CWE-200",
        "cors_check":       "CWE-942",
        "sensitive_files":  "CWE-552",
        "admin_paths":      "CWE-200",
        "open_redirect":    "CWE-601",
        "reflection":       "CWE-79",
        "sql_errors":       "CWE-209",
        "path_traversal":   "CWE-22",
        "api_roots":        "CWE-200",
    }
    return d.get(probe_id, "CWE-200")


def _mrs_for(sev: str) -> int:
    return {"CRITICAL": 95, "HIGH": 80, "MEDIUM": 60, "LOW": 40}.get(sev, 30)
