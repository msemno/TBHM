"""Campaign-scale content-addressed artifact deduplication and reuse index."""
from __future__ import annotations
from pathlib import Path
from core import redteam_utils as RT
from core.artifact_store import ArtifactStore
from core.reverse_phase_utils import write_json


def run(ctx):
    store_root = getattr(ctx.args, "reverse_campaign_store", None)
    source = getattr(ctx.args, "reverse_campaign_artifacts", None) or getattr(ctx.args, "binary_path", None)
    if not (store_root and source):
        return
    out = RT.evidence_dir(ctx, "25k_reverse_campaign_index")
    p = Path(source).expanduser()
    files = [p] if p.is_file() else [x for x in p.rglob("*") if x.is_file() and not x.is_symlink()] if p.is_dir() else []
    max_files = int(getattr(ctx.args, "reverse_campaign_max_files", 100000))
    store = ArtifactStore(store_root)
    records = []
    try:
        for file in files[:max_files]:
            records.append(store.add(file, campaign=str(getattr(ctx.args, "reverse_campaign", "default")),
                                     project=str(getattr(ctx.args, "reverse_project", "default")),
                                     product=str(getattr(ctx.args, "reverse_product", "unknown")),
                                     version=str(getattr(ctx.args, "reverse_product_version", "unknown")),
                                     copy=bool(getattr(ctx.args, "reverse_campaign_copy", False))))
        stats = store.stats()
    finally:
        store.close()
    write_json(out / "CAMPAIGN_ARTIFACT_INDEX.json", {"schema": "tbhm.campaign-store/1.0", "records": records, "stats": stats})
    RT.write_md(out / "CAMPAIGN_INDEX_SUMMARY.md", "Campaign Artifact Index", [
        ("Observed files", str(len(records))), ("Unique artifacts", str(stats.get("unique_artifacts", 0))),
        ("Reused artifacts", str(stats.get("reused_artifacts", 0))), ("Store", str(stats.get("root", ""))),
    ])
    ctx.log("OK", "reverse_campaign_index", f"indexed {len(records)} artifact observation(s)")
