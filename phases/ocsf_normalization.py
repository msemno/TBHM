"""Emit class-aware, deterministic OCSF-oriented evidence streams."""
from __future__ import annotations

import json
from pathlib import Path
from core import redteam_utils as RT
from core.ocsf import finding_event, write_jsonl
from core.ocsf_export import event
from core.version import VERSION


def _load_optional(path: Path):
    if not path.is_file(): return []
    try:
        data=json.loads(path.read_text(encoding="utf-8",errors="replace"))
        if isinstance(data,list): return data
        for key in ("records","observations","paths","controls","results"):
            if isinstance(data,dict) and isinstance(data.get(key),list): return data[key]
    except Exception: pass
    return []


def run(ctx):
    if getattr(ctx.args,"no_ocsf",False): return
    out=RT.evidence_dir(ctx,"108_ocsf_normalization")
    try: findings=ctx.storage.all_findings()
    except Exception: findings=[]
    version=VERSION; profile=str((ctx.profile or {}).get("name",""))
    events=[finding_event(row,tool_version=version,profile=profile) for row in findings]
    # Include new non-finding evidence classes when their artifacts exist.
    roots=[
        (ctx.output/"redteam/107_session_beacon_import/session_beacon_inventory.json","session"),
        (ctx.output/"redteam/28_passive_wireless_inventory/passive_wireless_inventory.json","wireless"),
        (ctx.output/"redteam/79_cloud_identity_path_analysis/cloud_identity_paths.json","cloud_iam"),
        (ctx.output/"redteam/12_osint_api_collectors/osint_api_results.json","osint"),
    ]
    class_counts={"finding":len(events)}
    for path,hint in roots:
        rows=_load_optional(path); class_counts[hint]=len(rows)
        for row in rows: events.append(event(row,tool_version=version,profile=profile,class_hint=hint))
    count=write_jsonl(out/"ocsf_findings.jsonl",events)
    summary={"events":count,"classes":class_counts,"compatibility":"OCSF 1.1-oriented class-aware events","native_schema_preserved":True,"stable_fingerprints":True}
    (out/"ocsf_summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    RT.write_md(out/"OCSF_NORMALIZATION.md","Class-Aware OCSF-Oriented Export",[("Result",json.dumps(summary,indent=2)),("Determinism","Stable fingerprints exclude volatile timestamps and runtime fields, so the same logical event receives the same fingerprint across exports."),("Design","TBHM native evidence remains the source of truth. Unknown fields and provenance remain under unmapped.")])
    ctx.log("OK","ocsf_normalization",f"{count} event(s) normalized across {len([x for x in class_counts.values() if x])} class group(s)")
