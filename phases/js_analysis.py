"""Complete JavaScript intelligence over every discovered in-scope candidate.

Consumes Katana, ParamSpider, ZAP and crawler evidence, fetches every unique JS
candidate by default, analyzes each body (including vendor/noise files), attempts source-map recovery, classifies usefulness, and feeds endpoints
and parameters back into TBHM. Read-only GET requests only.
"""
from __future__ import annotations
from core.evidence_redaction import redact_text
import base64
import csv
import hashlib
import json
from pathlib import Path
from urllib.parse import unquote_to_bytes, urljoin, urlparse

from core import anti_block, fp_filters as FP, noise_filter
from core.api_baseline import RateLimiter
from core.js_intelligence import analyze_text, discover_candidates, canonical_url, find_raw_secrets
from core import secret_vault
from core.sourcemaps import extract_from_map, _write_recovered
from core.targets import get_root_domains, target_scope_allows
from core.scoped_http import network_discovery_enabled, effective_rps, safe_get

# Backward-compatibility constants for pre-v4 plugins that imported these from
# phases.js_analysis. v4 analyzes every in-scope candidate by default and uses
# operator --js-* caps instead; these are retained only so imports do not break.
_MAX_FETCH = 120
_MAX_DEEP = 40
_TIMEOUT = 15

try:
    import requests
except ImportError:
    requests = None




def _name_score(url: str) -> tuple[int, list[str]]:
    """Compatibility helper retained from v3.9.3; current scoring is content-driven."""
    name = Path(urlparse(url).path).name.lower()
    score, reasons = 0, []
    if any(token in name for token in ("main", "app", "bundle", "config", "auth", "api", "admin", "graphql")):
        score += 4; reasons.append("high-value filename")
    if any(token in name for token in ("jquery", "bootstrap", "polyfill", "analytics", "vendor")):
        score -= 3; reasons.append("library/vendor filename")
    return score, reasons

def _safe_name(url: str, index: int) -> str:
    name = Path(urlparse(url).path).name or f"script_{index}.js"
    stem = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:100]
    return f"{index:05d}_{hashlib.sha256(url.encode()).hexdigest()[:12]}_{stem}.json"


def _merge_lines(path: Path, values) -> int:
    existing = set(path.read_text(errors="ignore").splitlines()) if path.is_file() else set()
    clean = {str(x).strip() for x in values if str(x).strip()}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(sorted(existing | clean)) + ("\n" if existing or clean else ""), encoding="utf-8")
    return len(clean - existing)


def _fetch(ctx, url: str, limiter, timeout: int):
    host = urlparse(url).hostname or ""
    headers = anti_block.headers_for(host)
    response, final_url, chain = safe_get(ctx, requests, url, headers=headers, timeout=timeout,
                                          verify=False, rate_limiter=limiter, max_redirects=5)
    anti_block.observe(urlparse(final_url).hostname or host, response.status_code, len(response.content))
    return response, final_url, chain




def _decode_inline_source_map(reference: str, max_bytes: int) -> tuple[str | None, str | None]:
    """Decode a sourceMappingURL data URI without network access.

    Returns ``(text, error)`` and enforces the same response-size policy as
    remotely fetched maps.
    """
    if not reference.lower().startswith("data:"):
        return None, "not_inline"
    try:
        header, payload = reference.split(",", 1)
        raw = base64.b64decode(payload, validate=True) if ";base64" in header.lower() else unquote_to_bytes(payload)
        if len(raw) > max_bytes:
            return None, f"inline source map exceeds js_max_bytes={max_bytes}"
        return raw.decode("utf-8", errors="replace"), None
    except Exception as exc:
        return None, f"invalid inline source map: {exc}"

def _emit_findings(ctx, analysis: dict, final_url: str):
    count = 0
    for secret in analysis.get("secrets", []):
        pseudo = {"phase": "js_analysis", "title": f"Hardcoded secret in JS: {secret.get('type','candidate')}",
                  "target": final_url, "confidence": "MEDIUM", "evidence": "[value redacted]"}
        action, _reason, _tier = FP.assess(pseudo)
        if action == "drop":
            continue
        ctx.save_finding({
            "phase": "js_analysis", "severity": "MEDIUM" if action == "keep" else "LOW",
            "confidence": "MEDIUM" if action == "keep" else "LOW",
            "title": f"Hardcoded secret candidate in JavaScript: {secret.get('type','unknown')}",
            "target": final_url, "url": final_url,
            "description": "A client-side credential-like value passed TBHM's secret-pattern and false-positive filters. The value is redacted in aggregate evidence.",
            "evidence": json.dumps(secret, ensure_ascii=False)[:3000],
            "impact": "A live client-side credential may expose backend, cloud or third-party services.",
            "remediation": "Validate ownership and scope without destructive use, remove the value from client bundles, rotate it if live, and move privileged operations server-side.",
            "cwe": "CWE-798", "mrs_score": 55, "finding_class": "lead",
        }); count += 1
    for flow in analysis.get("taint_flows", [])[:200]:
        ctx.save_finding({
            "phase": "js_analysis", "severity": "MEDIUM", "confidence": "LOW",
            "title": "[STATIC JS PATH] Browser-controlled source reaches dangerous sink",
            "target": final_url, "url": final_url,
            "description": "Static JavaScript analysis correlated a browser-controlled source with a DOM/code/navigation sink. Bundling and control-flow uncertainty require manual confirmation.",
            "evidence": json.dumps(flow, ensure_ascii=False)[:5000],
            "impact": "Depending on context and encoding, this may contribute to DOM XSS, open redirect, unsafe dynamic code execution, or client-side request manipulation.",
            "remediation": "Trace the exact value, apply context-appropriate encoding or allowlisting, avoid dynamic code/HTML sinks, and verify with a benign browser test.",
            "cwe": flow.get('sink_cwe') or 'CWE-79', "mrs_score": 58, "finding_class": "lead",
            "validation_required": "Lexical source/sink co-occurrence only; verify runtime reachability, context and negative controls.",
        }); count += 1
    if analysis.get("source_maps"):
        ctx.save_finding({
            "phase": "js_analysis", "severity": "LOW", "confidence": "MEDIUM",
            "title": "JavaScript source map referenced",
            "target": final_url, "url": final_url,
            "description": "The JavaScript bundle references source-map material. Reachable maps can expose original TypeScript/JSX, comments and internal paths.",
            "evidence": json.dumps(analysis.get("source_maps"), ensure_ascii=False)[:3000],
            "impact": "Source disclosure can reduce reverse-engineering effort and reveal undocumented application behavior.",
            "remediation": "Do not publish production source maps unless intentionally required; remove sourcesContent or restrict access.",
            "cwe": "CWE-540", "mrs_score": 30, "finding_class": "lead",
        }); count += 1
    return count


def run(ctx):
    if not requests:
        ctx.log("WARN", "js_analysis", "requests not available — skipping")
        return
    if not network_discovery_enabled(ctx):
        ctx.log("INFO", "js_analysis", "passive/zero-touch profile — skipping JS fetches")
        return
    extra = getattr(ctx.args, "js_candidate_results", None) or []
    if isinstance(extra, str): extra = [extra]
    candidates = discover_candidates(ctx.output, extra_paths=extra,
                                     max_scan_files=int(getattr(ctx.args, "js_candidate_scan_files", 10000)))
    if not candidates:
        ctx.log("WARN", "js_analysis", "no JavaScript candidates found in Katana/ParamSpider/ZAP/crawler evidence")
        return
    requested_max = int(getattr(ctx.args, "js_max_files", 0) or 0)
    hard_max = len(candidates) if requested_max <= 0 else max(1, min(requested_max, 1_000_000))
    max_bytes = max(1024, min(int(getattr(ctx.args, "js_max_bytes", 15 * 1024 * 1024)), 100 * 1024 * 1024))
    timeout = max(1, min(int(getattr(ctx.args, "js_timeout", 20)), 120))
    max_source_maps = max(1, min(int(getattr(ctx.args, "js_max_source_maps", 250)), 5000))
    max_recovered_sources = max(1, min(int(getattr(ctx.args, "js_max_recovered_sources", 10000)), 100000))
    rps = effective_rps(ctx)
    if rps <= 0:
        return
    limiter = RateLimiter(rps)
    roots = set(get_root_domains(ctx))
    out = ctx.output / "js_analysis"
    details = out / "files"; maps_dir = out / "source_maps"; recovered_dir = out / "recovered_sources"
    for directory in (out, details, maps_dir, recovered_dir): directory.mkdir(parents=True, exist_ok=True)

    records, endpoints, parameters = [], set(), set()
    findings = recovered_count = 0
    sealed_secrets = []
    for index, candidate in enumerate(candidates):
        url = canonical_url(candidate.get("url", ""))
        record = {"url": url, "discovery_sources": candidate.get("sources", []), "index": index}
        if index >= hard_max:
            record.update({"status": "skipped", "classification": "skipped_operator_limit", "reason": f"js_max_files={hard_max}"})
            records.append(record); continue
        if not url or not target_scope_allows(ctx, url):
            record.update({"status": "skipped", "classification": "skipped_out_of_scope"}); records.append(record); continue
        noise, noise_reason = noise_filter.is_noise(url, in_scope_hosts=roots)
        record["noise_hint"] = bool(noise); record["noise_reason"] = noise_reason
        try:
            response, final_url, chain = _fetch(ctx, url, limiter, timeout)
            record.update({"status_code": response.status_code, "final_url": final_url, "redirect_chain": chain,
                           "content_type": response.headers.get("Content-Type", "")})
        except Exception as exc:
            record.update({"status": "inaccessible", "classification": "inaccessible", "error": str(exc)[:1000]})
            records.append(record); continue
        if response.status_code != 200:
            record.update({"status": "inaccessible", "classification": "inaccessible_http"}); records.append(record); continue
        body_bytes = response.content
        if len(body_bytes) > max_bytes:
            record.update({"status": "skipped", "classification": "skipped_oversize", "bytes": len(body_bytes), "max_bytes": max_bytes})
            records.append(record); continue
        body = body_bytes.decode(response.encoding or "utf-8", errors="replace")
        analysis = analyze_text(body, final_url)
        record.update({"status": "analyzed", "analysis": analysis})
        for _sec in find_raw_secrets(body, final_url):
            sealed_secrets.append({"type": _sec.get("type", "unknown"), "match": _sec.get("match"), "url": final_url})
        endpoints.update(analysis.get("endpoints", {}).get("paths", []))
        endpoints.update(x for x in analysis.get("endpoints", {}).get("urls", []) if target_scope_allows(ctx, x))
        parameters.update(analysis.get("parameters", []))
        findings += _emit_findings(ctx, analysis, final_url)

        # Fetch and reconstruct every referenced source map up to an explicit
        # safety bound. Every excess/out-of-scope/inaccessible reference is
        # represented in evidence instead of being silently discarded.
        recovered = []
        map_refs = list(dict.fromkeys(analysis.get("source_maps", [])))
        for map_index, map_ref in enumerate(map_refs):
            if map_index >= max_source_maps:
                recovered.append({"reference": map_ref, "status": "skipped",
                                  "classification": "skipped_source_map_limit",
                                  "reason": f"js_max_source_maps={max_source_maps}"})
                continue
            map_text = None
            map_chain = []
            map_final = map_ref
            if str(map_ref).lower().startswith("data:"):
                map_text, inline_error = _decode_inline_source_map(str(map_ref), max_bytes)
                if inline_error:
                    recovered.append({"reference": "data:[redacted]", "status": "skipped",
                                      "classification": "invalid_or_oversize_inline_source_map",
                                      "error": inline_error})
                    continue
                map_final = f"{final_url}::inline-source-map-{map_index}"
            else:
                map_url = canonical_url(urljoin(final_url, map_ref))
                if not map_url or not target_scope_allows(ctx, map_url):
                    recovered.append({"reference": map_ref, "url": map_url, "status": "skipped",
                                      "classification": "skipped_out_of_scope_source_map"})
                    continue
                try:
                    map_response, map_final, map_chain = _fetch(ctx, map_url, limiter, timeout)
                except Exception as exc:
                    recovered.append({"url": map_url, "status": "inaccessible", "error": str(exc)[:500]})
                    continue
                if map_response.status_code != 200:
                    recovered.append({"url": map_final, "status": "inaccessible_http",
                                      "status_code": map_response.status_code, "bytes": len(map_response.content)})
                    continue
                if len(map_response.content) > max_bytes:
                    recovered.append({"url": map_final, "status": "skipped",
                                      "classification": "skipped_oversize_source_map",
                                      "bytes": len(map_response.content), "max_bytes": max_bytes})
                    continue
                map_text = map_response.content.decode(map_response.encoding or "utf-8", errors="replace")
            map_hash = hashlib.sha256((map_text or "").encode(errors="ignore")).hexdigest()
            map_path = maps_dir / f"{map_hash}.map"
            map_path.write_text(redact_text(map_text or ""), encoding="utf-8")
            sources = extract_from_map(map_text or "")
            map_record = {"url": map_final, "redirect_chain": map_chain, "sha256": map_hash,
                          "status": "analyzed", "source_count": len(sources), "sources": []}
            for source_index, (source_name, source_text) in enumerate(sources.items()):
                if source_index >= max_recovered_sources:
                    map_record["sources"].append({"name": source_name, "status": "skipped",
                                                  "classification": "skipped_recovered_source_limit",
                                                  "reason": f"js_max_recovered_sources={max_recovered_sources}"})
                    continue
                safe_parts = [part for part in Path(source_name).parts if part not in {"", ".", ".."}]
                relative = Path(*safe_parts) if safe_parts else Path(f"source_{recovered_count}.js")
                destination = recovered_dir / map_hash / relative
                recovery_root = recovered_dir / map_hash
                try:
                    recovery_root.mkdir(parents=True, exist_ok=True)
                    _write_recovered(recovery_root, relative.parts, source_text)
                except OSError as exc:
                    map_record["sources"].append({"name": source_name, "status": "skipped",
                                                  "classification": "recovery_write_blocked",
                                                  "error": str(exc)[:500]})
                    continue
                source_analysis = analyze_text(source_text, f"{map_final}::{source_name}")
                for _sec in find_raw_secrets(source_text, map_final):
                    sealed_secrets.append({"type": _sec.get("type", "unknown"), "match": _sec.get("match"), "url": map_final})
                sidecar = destination.with_suffix(destination.suffix + ".analysis.json")
                try:
                    _write_recovered(recovery_root, sidecar.relative_to(recovery_root).parts,
                                     json.dumps(source_analysis, indent=2, ensure_ascii=False))
                except OSError as exc:
                    map_record["sources"].append({"name": source_name, "status": "skipped",
                                                  "classification": "recovery_write_blocked",
                                                  "error": str(exc)[:500]})
                    continue
                endpoints.update(source_analysis.get("endpoints", {}).get("paths", []))
                endpoints.update(x for x in source_analysis.get("endpoints", {}).get("urls", []) if target_scope_allows(ctx, x))
                parameters.update(source_analysis.get("parameters", []))
                findings += _emit_findings(ctx, source_analysis, map_final)
                map_record["sources"].append({"name": source_name, "path": str(destination), "status": "analyzed",
                                              "classification": source_analysis.get("classification"),
                                              "usefulness_score": source_analysis.get("usefulness_score")})
                recovered_count += 1
            recovered.append(map_record)
        record["source_map_recovery"] = recovered
        detail = details / _safe_name(url, index)
        detail.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
        record["detail_file"] = str(detail)
        records.append(record)

    _merge_lines(ctx.output / "recon" / "javascript.txt", [r.get("url") for r in records if r.get("url")])
    new_eps = _merge_lines(ctx.output / "recon" / "js_endpoints.txt", endpoints)
    new_params = _merge_lines(ctx.output / "recon" / "params.txt", parameters)
    counts = {}
    for row in records:
        cls = row.get("analysis", {}).get("classification") or row.get("classification") or "unknown"
        counts[cls] = counts.get(cls, 0) + 1
    index_payload = {"schema": "tbhm.js-intelligence/1.1", "candidates": len(candidates), "hard_max": hard_max,
                     "max_source_maps_per_file": max_source_maps,
                     "max_recovered_sources_per_map": max_recovered_sources,
                     "records": records, "counts": counts, "endpoints": sorted(endpoints), "parameters": sorted(parameters),
                     "recovered_sources": recovered_count, "findings": findings}
    (out / "JS_USEFULNESS_INDEX.json").write_text(json.dumps(index_payload, indent=2, ensure_ascii=False), encoding="utf-8")
    # Run-scoped sealed handoff of live secret candidates to api_key_pivot;
    # encrypted, never plaintext on disk. Findings remain redacted.
    if sealed_secrets:
        vault = secret_vault.seal(ctx, sealed_secrets)
        if vault:
            ctx.log("OK", "js_analysis", f"sealed {len(sealed_secrets)} secret candidate(s) for authorized in-run validation")
    # Backward-compatible ranked.json (url + value score + reasons) for older
    # plugins/dashboards/scripts that consumed js_analysis/ranked.json.
    ranked = []
    for row in records:
        analysis = row.get("analysis", {})
        reasons = list(analysis.get("reasons", []) or [])
        classification = analysis.get("classification", row.get("classification"))
        if classification:
            reasons.append(f"classification:{classification}")
        ranked.append({
            "url": row.get("url"),
            "final_url": row.get("final_url", row.get("url")),
            "score": analysis.get("usefulness_score", row.get("score", 0)),
            "reasons": reasons,
            "status": row.get("status"),
            "bytes": analysis.get("bytes", row.get("bytes", 0)),
            "classification": classification,
        })
    ranked.sort(key=lambda c: (c.get("score") or 0), reverse=True)
    (out / "ranked.json").write_text(json.dumps(ranked, indent=2, ensure_ascii=False), encoding="utf-8")
    with (out / "JS_USEFULNESS_INDEX.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle); writer.writerow(["url", "status", "classification", "score", "bytes", "sources"])
        for row in records:
            analysis = row.get("analysis", {})
            writer.writerow([row.get("url"), row.get("status"), analysis.get("classification", row.get("classification")),
                             analysis.get("usefulness_score", ""), analysis.get("bytes", row.get("bytes", "")),
                             ";".join(row.get("discovery_sources", []))])
    summary = ["# JavaScript Intelligence Summary", "", f"- Candidates: {len(candidates)}", f"- Records: {len(records)}",
               f"- Classifications: `{json.dumps(counts, sort_keys=True)}`", f"- New endpoints: {new_eps}",
               f"- New parameters: {new_params}", f"- Recovered source files: {recovered_count}", f"- Findings: {findings}",
               "", "Every unique in-scope candidate is analyzed by default; scope, size, access failures and any operator-selected count cap are recorded explicitly."]
    (out / "JS_ANALYSIS_SUMMARY.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    ctx.log("OK", "js_analysis", f"processed {len(records)} JS candidate(s); {counts}; recovered {recovered_count} source file(s)")
