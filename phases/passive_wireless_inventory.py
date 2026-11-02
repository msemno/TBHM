"""Passive/import-only wireless observation inventory."""
from __future__ import annotations

import json
from core import redteam_utils as RT
from core.wireless_inventory import import_observations


def run(ctx):
    path=getattr(ctx.args,"wireless_observations",None)
    if not path:
        return
    out=RT.evidence_dir(ctx,"28_passive_wireless_inventory")
    result=import_observations(path,location_label=str(getattr(ctx.args,"wireless_location_label","") or ""),max_records=max(1,min(int(getattr(ctx.args,"wireless_max_records",50000) or 50000),200000)))
    (out/"passive_wireless_inventory.json").write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")
    RT.write_csv(out/"passive_wireless_inventory.csv",result["observations"])
    RT.write_md(out/"PASSIVE_WIRELESS_INVENTORY.md","Passive Wireless Inventory",[("Result",json.dumps(result["summary"],indent=2)),("Boundary",result["boundary"]),("Risk notes","Observations are inventory evidence. Encryption/vendor heuristics require analyst validation and do not prove unauthorized access.")])
    ctx.phase_state["passive_wireless_inventory"]=result["summary"]
    ctx.log("OK","passive_wireless_inventory",f"{result['summary']['observations']} observation(s)")
