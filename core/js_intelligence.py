"""Complete JavaScript candidate aggregation and usefulness analysis.

Consumes Katana, ParamSpider, ZAP, crawler and historical URL outputs; analyzes
every unique in-scope JavaScript candidate up to an explicit hard safety bound;
classifies each file as useful, review, library/noise, inaccessible or skipped;
and feeds endpoints/parameters back into TBHM.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse
from typing import Iterable, Any

from core import code_patterns as CP
from core import sourcemaps as SM
from core.taint_engine import analyze_js

URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.I)
JS_URL_RE = re.compile(r"https?://[^\s\"'<>\\]+?\.m?js(?:\?[^\s\"'<>\\]*)?", re.I)
REL_JS_RE = re.compile(r"(?:src|href|url|endpoint|sourceMappingURL)\s*[:=]?\s*[\"']([^\"']+\.m?js(?:\?[^\"']*)?)[\"']", re.I)
SOURCE_MAP_RE = re.compile(r"(?m)(?:\/\/[#@]|\/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)")
PARAM_RE = re.compile(r"(?i)(?:URLSearchParams\s*\([^)]*\)|searchParams|location\.search|queryString)[\s\S]{0,100}?\.(?:get|has|append|set)\s*\(\s*[\"']([^\"']+)")
PARAM_OBJECT_RE = re.compile(r"(?i)(?:params|query|data)\s*:\s*\{([^}]{1,2000})\}")
OBJECT_KEY_RE = re.compile(r"(?:^|[,\s])([A-Za-z_$][\w$-]{1,80})\s*:")
GRAPHQL_RE = re.compile(r"(?is)\b(query|mutation|subscription)\s+([A-Za-z_$][\w$]*)?\s*(?:\([^)]*\))?\s*\{")
DOM_SOURCE_RE = re.compile(r"(?i)(location\.(?:href|search|hash)|document\.(?:URL|referrer|cookie)|window\.name|event\.data|localStorage|sessionStorage|postMessage)")
DOM_SINK_RE = re.compile(r"(?i)(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\s*\(|new\s+Function|setTimeout\s*\(\s*[\"']|setInterval\s*\(\s*[\"']|location\.(?:href|assign|replace)|\.html\s*\()");
AUTH_RE = re.compile(r"(?i)(authorization|bearer|access[_-]?token|refresh[_-]?token|jwt|oauth|oidc|pkce|client[_-]?secret|api[_-]?key)")
CLOUD_RE = re.compile(r"(?i)(firebaseConfig|aws[_-]?(?:access|secret)|cognito|amplify|s3[.-]|azure|gcp|serviceAccount|supabase|sentryDsn|dsn\s*:)")
WS_RE = re.compile(r"(?i)(new\s+WebSocket|wss?://|socket\.io|sockjs|stomp)")
FEATURE_RE = re.compile(r"(?i)(feature[_-]?flag|launchdarkly|split\.io|isAdmin|is_admin|debug\s*[:=]\s*true|__DEV__|environment\s*[:=])")
FRAMEWORKS = {
    "react": re.compile(r"(?i)(React\.createElement|__REACT_DEVTOOLS|react-dom|jsx-runtime)"),
    "angular": re.compile(r"(?i)(@angular|ng-version|zone\.js|ɵɵdefineComponent)"),
    "vue": re.compile(r"(?i)(createApp\(|__VUE__|vue-router|Vue\.component)"),
    "nextjs": re.compile(r"(?i)(__NEXT_DATA__|_next/static|next/router)"),
    "nuxt": re.compile(r"(?i)(__NUXT__|_nuxt/)"),
    "webpack": re.compile(r"(?i)(__webpack_require__|webpackChunk)"),
    "vite": re.compile(r"(?i)(import\.meta\.env|/@vite/|__vite__)"),
    "jquery": re.compile(r"(?i)(jQuery|\$\.ajax|jquery[-.]\d)"),
}
LIBRARY_NAME = re.compile(r"(?i)(jquery|bootstrap|polyfill|analytics|gtag|gtm|recaptcha|hotjar|intercom|segment|amplitude|sentry|vendor(?:\.|-)|runtime(?:\.|-))")


def canonical_url(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", parsed.query, ""))


def _extract_urls(value: Any, base: str = "") -> set[str]:
    out = set()
    if isinstance(value, dict):
        for child in value.values():
            out.update(_extract_urls(child, base))
    elif isinstance(value, list):
        for child in value:
            out.update(_extract_urls(child, base))
    elif isinstance(value, str):
        for match in JS_URL_RE.finditer(value):
            out.add(match.group(0).rstrip(".,);]"))
        if value.endswith((".js", ".mjs")) and base:
            out.add(urljoin(base, value))
    return out


def discover_candidates(output: str | Path, extra_paths: Iterable[str | Path] = (), max_scan_files: int = 5000) -> list[dict]:
    output = Path(output)
    sources = {}
    known = [
        output / "recon/javascript.txt", output / "recon/urls.txt", output / "recon/katana_urls.txt",
        output / "recon/katana.jsonl", output / "recon/paramspider_urls.txt", output / "recon/zap_urls.txt",
        output / "recon/js_endpoints.txt", output / "logs/katana.log",
    ]
    known.extend(Path(p) for p in extra_paths if p)
    for root_name in ("recon", "scans", "evidence/22_web_scanner_tooling"):
        root = output / root_name
        if root.is_dir():
            known.extend([p for p in root.rglob("*") if p.is_file()][:max_scan_files])
    seen_files = set()
    for path in known:
        try:
            resolved = path.resolve()
        except Exception:
            continue
        if resolved in seen_files or not path.is_file() or path.stat().st_size > 100_000_000:
            continue
        seen_files.add(resolved)
        suffix = path.suffix.lower()
        urls = set()
        try:
            if suffix in {".json", ".sarif"}:
                urls.update(_extract_urls(json.loads(path.read_text(errors="ignore"))))
            elif suffix == ".jsonl":
                for line in path.read_text(errors="ignore").splitlines()[:100000]:
                    try: urls.update(_extract_urls(json.loads(line)))
                    except Exception: urls.update(m.group(0) for m in JS_URL_RE.finditer(line))
            else:
                text = path.read_text(errors="ignore")
                urls.update(m.group(0).rstrip(".,);]") for m in JS_URL_RE.finditer(text))
                urls.update(line.strip() for line in text.splitlines() if ".js" in line and line.strip().startswith(("http://", "https://")))
        except Exception:
            continue
        for raw in urls:
            url = canonical_url(raw)
            if url and (urlparse(url).path.lower().endswith((".js", ".mjs")) or ".js?" in url.lower() or ".mjs?" in url.lower()):
                sources.setdefault(url, set()).add(str(path))
    return [{"url": url, "sources": sorted(srcs)} for url, srcs in sorted(sources.items())]


def entropy(text: str) -> float:
    if not text:
        return 0.0
    sample = text[:100000]
    counts = {char: sample.count(char) for char in set(sample)}
    return -sum((count / len(sample)) * math.log2(count / len(sample)) for count in counts.values())


def find_raw_secrets(text: str, source: str = "") -> list[dict]:
    """Unredacted secret-candidate rows for the run-scoped sealed vault only.

    ``analyze_text`` redacts the ``match`` value before it can reach findings
    or on-disk detail files. This returns the raw rows so the sealed vault can
    hand live candidates to the authorized in-run validator without ever
    writing plaintext.
    """
    return CP.find_secrets(text or "", source or "")


def analyze_text(text: str, source: str) -> dict:
    endpoints = CP.find_endpoints(text)
    secrets = CP.find_secrets(text, source)
    params = set(PARAM_RE.findall(text))
    for obj in PARAM_OBJECT_RE.findall(text):
        params.update(OBJECT_KEY_RE.findall(obj))
    frameworks = sorted(name for name, rx in FRAMEWORKS.items() if rx.search(text))
    graphql = [{"operation": m.group(1).lower(), "name": m.group(2) or ""} for m in GRAPHQL_RE.finditer(text)]
    dom_sources = sorted({m.group(1) for m in DOM_SOURCE_RE.finditer(text)})
    dom_sinks = sorted({m.group(1) for m in DOM_SINK_RE.finditer(text)})
    taint = [flow.__dict__ for flow in analyze_js(text, source)]
    auth = sorted({m.group(1).lower() for m in AUTH_RE.finditer(text)})
    cloud = sorted({m.group(1) for m in CLOUD_RE.finditer(text)})
    websockets = sorted({m.group(1) for m in WS_RE.finditer(text)})
    features = sorted({m.group(1) for m in FEATURE_RE.finditer(text)})
    source_maps = [m.group(1).strip().strip("'\"") for m in SOURCE_MAP_RE.finditer(text)]
    score, reasons = 0, []
    signals = [
        (len(secrets) * 8, "secret candidates"),
        ((len(endpoints.get("paths", [])) + len(endpoints.get("urls", []))) * 2, "API/endpoints"),
        (len(params), "parameters"), (len(graphql) * 3, "GraphQL operations"),
        (len(taint) * 5, "source-to-sink flows"), (len(auth) * 2, "authentication logic"),
        (len(cloud) * 3, "cloud/service configuration"), (len(websockets) * 2, "WebSocket logic"),
        (len(features), "feature/debug flags"), (len(source_maps) * 3, "source maps"),
    ]
    for points, reason in signals:
        if points:
            score += min(points, 30)
            reasons.append(f"{reason}: {points if reason != 'API/endpoints' else len(endpoints.get('paths', [])) + len(endpoints.get('urls', []))}")
    if LIBRARY_NAME.search(Path(urlparse(source).path).name):
        score -= 4; reasons.append("library/vendor filename")
    if frameworks:
        score += 1; reasons.append("framework: " + ", ".join(frameworks))
    classification = "useful" if score >= 5 else "review" if score >= 1 else "library_or_no_actionable_signal"
    return {
        "source": source, "sha256": hashlib.sha256(text.encode(errors="ignore")).hexdigest(), "bytes": len(text.encode(errors="ignore")),
        "lines": text.count("\n") + 1, "entropy": round(entropy(text), 3), "classification": classification,
        "usefulness_score": score, "usefulness_reasons": reasons, "frameworks": frameworks,
        "endpoints": {key: sorted(value) for key, value in endpoints.items()}, "parameters": sorted(params),
        "secrets": [{k: ("[REDACTED]" if k == "match" else v) for k, v in row.items()} for row in secrets],
        "graphql": graphql, "dom_sources": dom_sources, "dom_sinks": dom_sinks, "taint_flows": taint,
        "auth_indicators": auth, "cloud_indicators": cloud, "websocket_indicators": websockets,
        "feature_debug_indicators": features, "source_maps": source_maps,
    }
