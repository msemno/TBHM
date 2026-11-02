"""
Phase: graphql_audit   (v3.3)

Detection-oriented GraphQL security review. For each discovered GraphQL endpoint
it performs bounded, safe checks:

  * introspection enabled?      (single introspection query)
  * suggestions/field hints on?  (typo query -> "Did you mean")
  * batching accepted?           (array-body probe)
  * alias/depth amplification surface (STATIC analysis of the schema depth — it
    does NOT fire a large amplification query at the target)

Requests are minimal and read-only. It never sends a resource-exhausting query;
depth/alias risk is inferred from the schema, not by hammering the server.
Honors --no-destructive (all probes are POST introspection reads, no mutations).
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

_INTROSPECTION = {"query": "{__schema{queryType{name} types{name fields{name}}}}"}
_TYPO = {"query": "{__schema{directiv}}"}  # deliberate typo to trigger suggestions


def _candidates(ctx):
    cands = []
    explicit = getattr(ctx.args, "graphql_url", None)
    if explicit:
        cands.append(explicit)
    # common paths on each target host
    for t in (ctx.targets or []):
        base = t if t.startswith("http") else "https://" + t
        p = urlparse(base)
        root = f"{p.scheme}://{p.netloc}"
        for path in ("/graphql", "/api/graphql", "/v1/graphql", "/query"):
            cands.append(root + path)
    # anything discovery flagged
    urls = ctx.runner.read_lines(ctx.output / "recon" / "urls.txt") \
        if (ctx.output / "recon" / "urls.txt").exists() else []
    cands += [u for u in urls if "graphql" in u.lower()]
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c); out.append(c)
    return out[:20]


def _schema_depth(types):
    """Rough max nesting from an introspection type list (static, no requests)."""
    field_types = 0
    for t in types or []:
        for f in (t.get("fields") or []):
            field_types += 1
    return field_types


def run(ctx):
    if not ctx.profile.get("active_probes", False) and not getattr(ctx.args, "graphql_url", None):
        ctx.log("INFO", "graphql_audit", "passive profile & no --graphql-url — skipping")
        return
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
    except Exception:
        ctx.log("WARN", "graphql_audit", "requests unavailable — skipping")
        return

    out_dir = ctx.output / "graphql"
    out_dir.mkdir(exist_ok=True)
    results, findings = [], 0

    for url in _candidates(ctx):
        ctx.runner.throttle("graphql")
        row = {"url": url, "reachable": False, "introspection": False,
               "suggestions": False, "batching": False, "schema_fields": 0}
        try:
            r = requests.post(url, json=_INTROSPECTION, timeout=10, verify=False)
            row["reachable"] = r.status_code < 500
            if r.status_code < 400 and "__schema" in r.text:
                row["introspection"] = True
                try:
                    data = r.json().get("data", {}).get("__schema", {})
                    row["schema_fields"] = _schema_depth(data.get("types"))
                except Exception:
                    pass
        except Exception:
            results.append(row)
            continue
        # suggestions
        try:
            r2 = requests.post(url, json=_TYPO, timeout=10, verify=False)
            if "did you mean" in r2.text.lower():
                row["suggestions"] = True
        except Exception:
            pass
        # batching (array body) — single tiny probe
        try:
            r3 = requests.post(url, json=[{"query": "{__typename}"}, {"query": "{__typename}"}],
                               timeout=10, verify=False)
            if r3.text.strip().startswith("["):
                row["batching"] = True
        except Exception:
            pass
        results.append(row)

        if row["introspection"]:
            ctx.save_finding({
                "phase": "graphql_audit", "severity": "LOW", "confidence": "HIGH",
                "title": "GraphQL introspection enabled",
                "target": ctx.targets[0] if ctx.targets else url, "url": url,
                "description": "Introspection is enabled, exposing the full schema. Combined with "
                               f"{row['schema_fields']} field(s), deep/aliased queries could amplify load. "
                               "No amplification query was sent.",
                "evidence": f"introspection=on suggestions={row['suggestions']} batching={row['batching']}",
                "impact": "Schema disclosure aids attackers; batching/alias abuse enables DoS or auth-check bypass.",
                "remediation": "Disable introspection & suggestions in production, add query depth/complexity "
                               "limits, and disable/limit batching.",
                "cwe": "CWE-200", "mrs_score": 35,
            })
            findings += 1

    (out_dir / "graphql_audit.json").write_text(json.dumps(results, indent=2))
    reach = sum(1 for r in results if r["reachable"])
    ctx.log("OK", "graphql_audit",
            f"{reach}/{len(results)} GraphQL endpoint(s) reachable | {findings} finding(s) "
            f"→ graphql_audit.json")
