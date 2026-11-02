"""Native authorized OSINT API collectors."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlparse

from core import redteam_utils as RT
from core.osint_collectors import collect, provider_status
from core.targets import target_scope_allows


def _queries(ctx) -> list[str]:
    values=[]
    raw=getattr(ctx.args,"osint_api_query",None)
    if raw: values.extend(x.strip() for x in str(raw).split(",") if x.strip())
    qf=getattr(ctx.args,"osint_api_queries_file",None)
    if qf and Path(qf).is_file(): values.extend(x.strip() for x in Path(qf).read_text(encoding="utf-8",errors="ignore").splitlines() if x.strip() and not x.strip().startswith("#"))
    if not values:
        for target in getattr(ctx,"targets",[]) or []:
            host=urlparse(target).hostname if str(target).startswith(("http://","https://")) else str(target).split("/")[0].split(":")[0]
            if host and host!="local-analysis.invalid": values.append(host)
    return list(dict.fromkeys(values))[:max(1,min(int(getattr(ctx.args,"osint_api_max_queries",50) or 50),500))]


def run(ctx):
    provider=str(getattr(ctx.args,"osint_api_provider","") or "").strip().lower()
    if not provider:
        return
    out=RT.evidence_dir(ctx,"12_osint_api_collectors")
    status=provider_status(provider)
    if not status.get("available"):
        payload={"provider_status":status,"results":[],"summary":{"ok":0,"errors":0}}
        (out/"osint_api_results.json").write_text(json.dumps(payload,indent=2),encoding="utf-8")
        ctx.log("WARN","osint_api_collectors",status.get("reason") or "provider unavailable")
        return
    results=[]
    for query in _queries(ctx):
        # Domain/IP registry lookup is intelligence collection only. It cannot
        # expand active scope; out-of-scope values are still allowed as passive
        # intelligence only when explicitly supplied by the operator.
        try:
            ipaddress.ip_address(query)
            qtype = "ip"
        except ValueError:
            qtype = "domain"
        result=collect(provider,query,query_type=qtype,timeout=int(getattr(ctx.args,"osint_api_timeout",20) or 20),retries=int(getattr(ctx.args,"osint_api_retries",2) or 2),redact_pii=not bool(getattr(ctx.args,"osint_api_include_pii",False)))
        result["active_scope_allowed"] = bool(target_scope_allows(ctx, query))
        result["active_scope_note"] = "OSINT result does not modify scope."
        results.append(result)
    payload={"provider_status":status,"results":results,"summary":{"ok":sum(1 for x in results if x.get("status")=="ok"),"errors":sum(1 for x in results if x.get("status")!="ok")},"cache_policy":"No cross-engagement cache is created by default."}
    (out/"osint_api_results.json").write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")
    RT.write_md(out/"OSINT_API_COLLECTORS.md","Native OSINT API Collectors",[("Provider",json.dumps(status,indent=2)),("Summary",json.dumps(payload["summary"],indent=2)),("Privacy","Person-level fields are redacted by default. Provider output is intelligence evidence and never expands active scope automatically.")])
    ctx.phase_state["osint_api_collectors"]=payload["summary"]
    ctx.log("OK","osint_api_collectors",f"{payload['summary']['ok']} successful {provider} lookup(s)")
