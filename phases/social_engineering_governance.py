"""Governed social-engineering, physical and wireless exercise register.

The phase validates plans and imports metrics. It never sends messages, hosts a
credential page, intercepts MFA, clones badges, performs lock bypass, transmits
wireless disruption frames, or collects real passwords.
"""
from __future__ import annotations
import csv
import hashlib
import json
from pathlib import Path
from core import redteam_utils as RT
from core.approval_gate import approved, load_manifest, summary as approval_summary
try:
    import yaml
except Exception:
    yaml = None


def _load(path):
    if not path:
        return {}
    p = Path(path)
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="ignore")) if p.suffix.lower() == ".json" else (yaml.safe_load(p.read_text(encoding="utf-8", errors="ignore")) if yaml else {})
    except Exception:
        return {}


def _hash(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


def run(ctx):
    if not (getattr(ctx.args, "social_engineering", False) or getattr(ctx.args, "social_engineering_plan", None) or getattr(ctx.args, "social_engineering_results", None)):
        return
    out = RT.evidence_dir(ctx, "27_social_engineering_governance")
    try:
        manifest = load_manifest(getattr(ctx.args, "approval_manifest", None))
    except Exception as exc:
        manifest = {}; ctx.log("WARN", "social_engineering_governance", str(exc))
    plan = _load(getattr(ctx.args, "social_engineering_plan", None))
    exercises = []
    for item in (plan.get("exercises", []) if isinstance(plan, dict) else []):
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "simulation").lower()
        target_group = str(item.get("target_group") or "")
        action = f"social_engineering:{kind}"
        ok, detail = approved(manifest, action, str(item.get("scope_target") or ""))
        controls = {
            "synthetic_credentials_only": bool(item.get("synthetic_credentials_only")),
            "real_password_collection_disabled": bool(item.get("real_password_collection_disabled")),
            "notification_plan": bool(item.get("notification_plan")),
            "takedown_plan": bool(item.get("takedown_plan")),
            "max_recipients": int(item.get("max_recipients") or 0),
        }
        safe = all([controls["synthetic_credentials_only"], controls["real_password_collection_disabled"],
                    controls["notification_plan"], controls["takedown_plan"],
                    0 < controls["max_recipients"] <= 5000])
        exercises.append({
            "id": item.get("id"), "type": kind, "target_group_hash": _hash(target_group) if target_group else "",
            "approval_verified": ok, "approval_detail": detail, "safety_controls_pass": safe,
            "status": "APPROVED_EXTERNAL_SIMULATION" if ok and safe else "BLOCKED",
            "metrics_expected": item.get("metrics_expected", ["delivered", "opened", "reported", "synthetic_submission"]),
            "prohibited": ["real password collection", "MFA interception", "unapproved impersonation", "third-party targeting", "physical coercion"],
        })
    results = []
    rp = getattr(ctx.args, "social_engineering_results", None)
    if rp:
        root = Path(rp)
        files = [root] if root.is_file() else [p for p in root.rglob("*.json") if p.is_file()] if root.is_dir() else []
        for p in files[:500]:
            try:
                data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
                rows = data if isinstance(data, list) else data.get("results", [data]) if isinstance(data, dict) else []
                for row in rows:
                    if isinstance(row, dict):
                        results.append({k: row.get(k) for k in ("campaign_id", "type", "sent", "delivered", "opened", "reported", "synthetic_submission", "cleanup_status")})
            except Exception:
                continue
    RT.write_csv(out / "exercise_register.csv", exercises)
    (out / "exercise_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    payload = {"approval": approval_summary(manifest), "planned": len(exercises), "imported_results": len(results), "boundary": "Plan/import only. No delivery, credential capture, MFA interception, physical bypass, or wireless attack execution."}
    (out / "social_engineering_summary.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    RT.write_md(out / "SOCIAL_ENGINEERING_GOVERNANCE.md", "Social Engineering, Physical and Wireless Governance", [
        ("Summary", json.dumps(payload, indent=2)),
        ("Required controls", "Approved target group, synthetic credentials, disabled real-password collection, deconfliction, notification, takedown, data minimization, cleanup and human approval."),
    ])
    ctx.log("OK", "social_engineering_governance", f"{len(exercises)} plan(s), {len(results)} result(s)")
