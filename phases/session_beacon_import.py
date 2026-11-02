"""Import-only authorized session and beacon evidence."""
from __future__ import annotations

import json
from core import redteam_utils as RT
from core.session_importer import import_evidence


def run(ctx):
    path = getattr(ctx.args, "session_evidence", None)
    if not path:
        return
    out = RT.evidence_dir(ctx, "107_session_beacon_import")
    result = import_evidence(path, redact_usernames=bool(getattr(ctx.args, "session_redact_usernames", False)), max_records=max(1, min(int(getattr(ctx.args, "session_max_records", 10000) or 10000), 100000)))
    (out / "session_beacon_inventory.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    RT.write_csv(out / "session_beacon_inventory.csv", result["records"])
    RT.write_md(out / "SESSION_BEACON_IMPORT.md", "Session and Beacon Evidence Import", [
        ("Result", json.dumps(result["summary"], indent=2)),
        ("Boundary", result["boundary"]),
        ("Interpretation", "Imported session state is evidence from an external authorized source. It does not prove how access was obtained and does not confirm a vulnerability by itself."),
    ])
    ctx.phase_state["session_beacon_import"] = result["summary"]
    ctx.log("OK", "session_beacon_import", f"{result['summary']['normalized']} normalized session record(s)")
