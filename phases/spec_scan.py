"""
Phase: spec_scan   (v2.19)

API interface discovery. Two jobs:

1. OpenAPI/Swagger — probe common spec locations, parse any spec found (JSON or
   YAML), and extract EVERY documented path+method+params. A published spec is the
   whole API surface for free — deterministic, better than fuzzing. Extracted paths
   are written to <output>/spec/endpoints.txt so api_fuzz consumes them.

2. Other interfaces — probe for SOAP/WSDL, OData, JSON-RPC, XML-RPC endpoints and
   flag their presence as manual-test leads.

Optional: if `schemathesis` is installed AND --spec-fuzz is set AND a spec URL
resolves, run bounded schema-conformance fuzzing (staging/authorized only).

Rate-limited via the global cap. Detection only.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except Exception:
    requests = None

try:
    import yaml
except Exception:
    yaml = None

from core import ratelimit

SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/v3/api-docs", "/v2/api-docs", "/api-docs", "/api/openapi.json",
    "/docs/openapi.json", "/swagger/v1/swagger.json", "/api-docs/v1",
    "/api/swagger.json", "/openapi", "/swagger-ui/index.html",
    "/.well-known/openapi.json",
]

INTERFACE_PROBES = {
    "SOAP/WSDL":  ["/?wsdl", "/service?wsdl", "/api?wsdl", "/soap?wsdl", "/services"],
    "XML-RPC":    ["/xmlrpc.php", "/RPC2", "/rpc"],
    "OData":      ["/odata", "/api/odata", "/odata/$metadata"],
    "JSON-RPC":   ["/jsonrpc", "/api/rpc", "/api/jsonrpc"],
    "GraphQL-alt":["/graphql/console", "/playground", "/altair"],
}


def _get(session, url, rl, timeout=10):
    rl.wait()
    try:
        return session.get(url, timeout=timeout, verify=False, allow_redirects=False)
    except Exception:
        return None


def _bases(ctx):
    bases = []
    f = ctx.output / "recon" / "alive.txt"
    if f.exists():
        bases = ctx.runner.read_lines(f)
    if not bases:
        bases = [t if t.startswith("http") else f"https://{t}" for t in ctx.targets]
    return list(dict.fromkeys(b.rstrip("/") for b in bases))[:25]


def _parse_spec(text, ctype):
    """Parse an OpenAPI/Swagger doc (JSON or YAML). Return dict or None."""
    text = text.strip()
    if text[:1] in ("{", "["):
        try:
            return json.loads(text)
        except Exception:
            pass
    if yaml and ("swagger" in text[:2000] or "openapi" in text[:2000] or "paths:" in text):
        try:
            return yaml.safe_load(text)
        except Exception:
            pass
    return None


def _extract_paths(spec):
    """From a parsed spec, return [(method, path, [params])]."""
    out = []
    paths = (spec or {}).get("paths") or {}
    if not isinstance(paths, dict):
        return out
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "options", "head"):
                continue
            params = []
            if isinstance(op, dict):
                for p in op.get("parameters", []) or []:
                    if isinstance(p, dict) and p.get("name"):
                        params.append(p["name"])
            out.append((method.upper(), path, params))
    return out


def run(ctx):
    out_dir = ctx.output / 'spec'
    out_dir.mkdir(exist_ok=True)
    from core.api_contracts import review_files
    review_files(ctx, out_dir)
    from core.scoped_http import network_discovery_enabled
    if (getattr(ctx.args, 'offline', False) or not network_discovery_enabled(ctx)
            or getattr(ctx, 'targets', []) == ['local-analysis.invalid']):
        return
    if requests is None:
        ctx.log("WARN", "spec_scan", "requests unavailable — skipping")
        return
    requests.packages.urllib3.disable_warnings()
    bases = _bases(ctx)
    if not bases:
        return

    rps = ratelimit.cap(ctx.profile, ctx.profile.get("rate_limit", {}).get("global_rps", 5))
    rl = ratelimit.RateLimiter(rps) if hasattr(ratelimit, "RateLimiter") else _FallbackRL(rps)
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (TBHM spec_scan)",
                            "Accept": "application/json, application/yaml, */*"})
    proxy = getattr(ctx.args, "proxy", None)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    out_dir = ctx.output / "spec"
    out_dir.mkdir(exist_ok=True)
    all_paths = set()
    spec_urls = []

    ctx.log("INFO", "spec_scan", f"━━━ API spec + interface discovery on {len(bases)} host(s) ━━━")

    for base in bases:
        # 1) OpenAPI/Swagger
        for p in SPEC_PATHS:
            r = _get(session, base + p, rl)
            if r is None or r.status_code != 200:
                continue
            spec = _parse_spec(r.text, r.headers.get("Content-Type", ""))
            if not spec or "paths" not in spec:
                # Swagger UI HTML (no paths) is still worth flagging.
                if "swagger-ui" in r.text.lower() or "redoc" in r.text.lower():
                    ctx.save_finding({
                        "phase": "spec_scan", "severity": "INFO", "confidence": "HIGH",
                        "title": f"API documentation UI exposed: {p}",
                        "target": urlparse(base).hostname, "url": base + p, "method": "GET",
                        "evidence": r.text[:200],
                        "description": "Interactive API docs are public — enumerates the API surface for an attacker.",
                        "impact": "Full API surface disclosure.",
                        "remediation": "Restrict API docs to authenticated/internal access in production.",
                        "cwe": "CWE-200", "mrs_score": 25,
                    })
                continue
            extracted = _extract_paths(spec)
            spec_urls.append(base + p)
            (out_dir / f"spec_{urlparse(base).hostname}{p.replace('/','_')}").write_text(r.text[:1_000_000])
            for method, path, params in extracted:
                all_paths.add(path)
            ctx.save_finding({
                "phase": "spec_scan", "severity": "INFO", "confidence": "HIGH", "finding_class": "lead",
                "title": f"OpenAPI/Swagger spec exposed: {p} ({len(extracted)} operations)",
                "target": urlparse(base).hostname, "url": base + p, "method": "GET",
                "evidence": f"{len(extracted)} operations; sample: " +
                            ", ".join(f"{m} {pt}" for m, pt, _ in extracted[:6]),
                "description": "A machine-readable API contract was observed. Public documentation may be intentional; this is a surface inventory observation.",
                "impact": "No unauthorized access or sensitive disclosure demonstrated.",
                "remediation": "Compare documentation visibility with the intended API publication policy.",
                "mrs_score": 10,
            })

        # 2) Other interfaces
        for kind, paths in INTERFACE_PROBES.items():
            for p in paths:
                r = _get(session, base + p, rl)
                if r is None or r.status_code not in (200, 401, 403, 405):
                    continue
                body = (r.text or "")[:400]
                sig = _interface_signature(kind, r.status_code, body, r.headers.get("Content-Type", ""))
                if not sig:
                    continue
                ctx.save_finding({
                    "phase": "spec_scan", "severity": "INFO", "confidence": "MEDIUM",
                    "title": f"{kind} interface detected: {p}",
                    "target": urlparse(base).hostname, "url": base + p, "method": "GET",
                    "evidence": f"HTTP {r.status_code}; {sig}",
                    "description": f"A {kind} interface is reachable. Test it for authentication, "
                                   f"function-level authorization, and parser safety (XXE for SOAP/XML-RPC).",
                    "impact": "Additional attack surface; often weaker auth than the main REST API.",
                    "remediation": "Authenticate the interface; disable if unused; harden the XML parser.",
                    "cwe": "CWE-284", "mrs_score": 25,
                })

    if all_paths:
        (out_dir / "endpoints.txt").write_text("\n".join(sorted(all_paths)))
        ctx.log("OK", "spec_scan",
                f"spec_scan: {len(all_paths)} documented paths → {out_dir/'endpoints.txt'} "
                f"(feed: --api-wordlist {out_dir/'endpoints.txt'})")

    # 3) Optional schemathesis (opt-in, staging only)
    if spec_urls and getattr(ctx.args, "spec_fuzz", False) and ctx.runner.has("schemathesis"):
        for surl in spec_urls[:2]:
            base = surl.rsplit("/", 1)[0]
            rep = out_dir / f"schemathesis_{urlparse(surl).hostname}.txt"
            ctx.log("INFO", "spec_scan", f"schemathesis (bounded) on {surl}")
            try:
                ctx.runner.run(["schemathesis", "run", surl, "--checks", "all",
                                "--max-examples", "10", "--request-timeout", "10",
                                "--report", str(rep)], timeout=900, log_name="schemathesis", capture_mode="tail")
            except Exception:
                pass

    if not all_paths and not spec_urls:
        ctx.log("OK", "spec_scan", "spec_scan: no OpenAPI/interface specs found")


def _interface_signature(kind, status, body, ctype):
    low = body.lower()
    if kind == "SOAP/WSDL" and ("wsdl" in low or "soap:envelope" in low or "definitions" in low):
        return "WSDL/SOAP markers present"
    if kind == "XML-RPC" and ("xml-rpc" in low or "methodresponse" in low or "faultcode" in low or status == 405):
        return "XML-RPC markers/method-not-allowed"
    if kind == "OData" and ("odata" in low or "$metadata" in low or "edmx" in low):
        return "OData metadata markers"
    if kind == "JSON-RPC" and ("jsonrpc" in low or "-32601" in body or "-32600" in body):
        return "JSON-RPC error/version markers"
    if kind == "GraphQL-alt" and ("graphql" in low or "playground" in low or "altair" in low):
        return "GraphQL IDE markers"
    return ""


class _FallbackRL:
    def __init__(self, rps):
        import time
        self._t = time
        self._iv = 1.0 / max(0.5, rps)
        self._last = 0.0

    def wait(self):
        now = self._t.monotonic()
        d = now - self._last
        if d < self._iv:
            self._t.sleep(self._iv - d)
        self._last = self._t.monotonic()
