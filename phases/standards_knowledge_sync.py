"""Versioned standards/feed readiness phase (offline-first, explicit updates)."""
from __future__ import annotations
import json
from pathlib import Path
from core import redteam_utils as RT


def run(ctx):
    _profile_name=str((getattr(ctx, "profile", {}) or {}).get("name", ""))
    _corporate_profile=_profile_name in {"authorized_redteam", "authorized_assumed_breach"}
    if not (_corporate_profile or getattr(ctx.args, "intel_enrichment", False) or getattr(ctx.args, "redteam", False)
            or getattr(ctx.args, "standards_sync", False) or getattr(ctx.args, "intel_online", False)):
        return
    out = RT.evidence_dir(ctx, "04_standards_knowledge")
    root = Path(__file__).resolve().parents[1]
    manifest_path = root / "knowledge" / "standards_manifest_v396.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        manifest = {"manifest_version": "3.9.6", "frameworks": [], "feeds": []}
    feed_dir = Path(getattr(ctx.args, "intel_dir", None) or (ctx.output / "intelligence_feeds"))
    feed_dir.mkdir(parents=True, exist_ok=True)
    update = {"requested": bool(getattr(ctx.args, "intel_online", False)), "executed": False}
    if update["requested"]:
        helper = root / "scripts" / "update_intel_feeds.py"
        rc, stdout, stderr = ctx.runner.run(
            ["python3", str(helper), "--output", str(feed_dir), "--kev", "--epss"],
            timeout=900, log_name="standards_intel_update")
        update.update({"executed": True, "return_code": rc,
                       "stdout": stdout[-2000:], "stderr": stderr[-2000:]})
    expected = {
        "epss": list(feed_dir.glob("*epss*.csv*")),
        "kev": list(feed_dir.glob("*known*exploited*.json")) + list(feed_dir.glob("*kev*.json")),
        "osv": list(feed_dir.glob("osv/*.json")),
        "attack": list(feed_dir.glob("**/*attack*.json")),
        "capec": list(feed_dir.glob("**/*capec*")),
        "d3fend": list(feed_dir.glob("**/*d3fend*")),
    }
    frameworks = []
    for item in manifest.get("frameworks", []):
        expected_file = item.get("expected_file")
        frameworks.append({**item, "local_dataset_present": bool(expected_file and (feed_dir / expected_file).exists())})
    report = {
        "manifest_version": manifest.get("manifest_version"),
        "frameworks": frameworks,
        "feeds": manifest.get("feeds", []),
        "feed_directory": str(feed_dir),
        "local_feed_counts": {k: len(v) for k, v in expected.items()},
        "update": update,
        "note": "TBHM stores mappings/metadata and operator-provided datasets; it does not redistribute standards text. Online feed retrieval is explicit and provenance is written by the updater.",
    }
    (out / "standards_knowledge.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    RT.write_csv(out / "standards_readiness.csv", frameworks)
    RT.write_md(out / "STANDARDS_KNOWLEDGE.md", "Standards and Intelligence Knowledge", [
        ("Manifest", f"Version {report['manifest_version']}; {len(frameworks)} framework families registered."),
        ("Local feed readiness", "\n".join(f"- {k}: {len(v)} file(s)" for k, v in expected.items())),
        ("Update", json.dumps(update, indent=2)),
        ("Integrity", report["note"]),
    ])
    ctx.phase_state["intel_feed_dir"] = str(feed_dir)
    ctx.phase_state["standards_manifest"] = report
    level = "OK" if not update.get("executed") or update.get("return_code") == 0 else "WARN"
    ctx.log(level, "standards_knowledge_sync", f"{len(frameworks)} frameworks registered; feeds at {feed_dir}")
