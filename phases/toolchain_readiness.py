"""Corporate tool-catalog readiness and integration-mode audit (v3.9.5)."""
from __future__ import annotations
import json
from pathlib import Path
from core import redteam_utils as RT
from core import tool_catalog


def run(ctx):
    _profile_name=str((getattr(ctx, "profile", {}) or {}).get("name", ""))
    _corporate_profile=_profile_name in {"authorized_redteam", "authorized_assumed_breach"}
    if not (_corporate_profile or getattr(ctx.args, "tool_readiness", False) or getattr(ctx.args, "redteam", False)
            or getattr(ctx.args, "corporate_osint", False) or getattr(ctx.args, "data_analysis", False)):
        return
    catalog = tool_catalog.load(getattr(ctx.args, "tool_catalog", None))
    cats = [x.strip() for x in str(getattr(ctx.args, "tool_categories", "") or "").split(",") if x.strip()]
    report = tool_catalog.readiness(catalog, categories=cats or None)
    out = RT.evidence_dir(ctx, "01_toolchain_readiness")
    (out / "toolchain_readiness.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    missing = [r for r in report["rows"] if r.get("executable") and not r.get("installed")]
    lines = ["# Corporate Toolchain Readiness", "",
             f"Registered catalog entries: **{report['registered']}**", "",
             f"Executable integrations: **{report['executable_entries']}**", "",
             f"Installed executable integrations: **{report['installed_executables']}**", "",
             f"Missing executable integrations: **{report['missing_executables']}**", "",
             "## Safety model", "",
             "Safe/static/read-only tools may be installed and invoked by their phases. "
             "Credential operations, coercion, exploit frameworks, C2, phishing, wireless disruption, "
             "OT writes and dynamic malware execution remain approval-gated or import-only.", "",
             "## Missing executable integrations", ""]
    for row in missing[:250]:
        lines.append(f"- **{row['name']}** ({row['category']}, {row['integration_mode']}): {row.get('install_hint') or 'manual/operator-managed'}")
    (out / "TOOLCHAIN_READINESS.md").write_text("\n".join(lines)+"\n", encoding="utf-8")
    ctx.phase_state["toolchain_readiness"] = {
        "registered": report["registered"], "installed": report["installed_executables"],
        "missing": report["missing_executables"], "catalog": str(tool_catalog.DEFAULT_CATALOG)}
    ctx.log("OK", "toolchain_readiness", f"{report['installed_executables']}/{report['executable_entries']} executable integrations installed; {report['registered']} catalogued")
