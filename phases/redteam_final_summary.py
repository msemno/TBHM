"""Final red-team lifecycle summary."""
from __future__ import annotations
from core import redteam_utils as RT


def run(ctx):
    out = RT.evidence_dir(ctx, "99_final_summary")
    rt_root = RT.rt_dir(ctx)
    files = sorted(str(p.relative_to(ctx.output)) for p in rt_root.rglob("*") if p.is_file())
    (out / "redteam_file_index.txt").write_text("\n".join(files) + ("\n" if files else ""))
    try:
        conn = ctx.storage.conn
        campaigns = conn.execute("SELECT COUNT(*) c FROM redteam_campaigns").fetchone()["c"]
        operations = conn.execute("SELECT COUNT(*) c FROM redteam_operations").fetchone()["c"]
        op_status = {r["status"]: r["c"] for r in conn.execute(
            "SELECT status,COUNT(*) c FROM redteam_operations GROUP BY status").fetchall()}
        detections = conn.execute("SELECT COUNT(*) c FROM detection_outcomes").fetchone()["c"]
        cleanups = conn.execute("SELECT COUNT(*) c FROM cleanup_actions").fetchone()["c"]
    except Exception:
        campaigns = operations = detections = cleanups = 0; op_status = {}
    RT.write_md(out / "REDTEAM_FINAL_SUMMARY.md", "TBHM Red-Team Lifecycle Summary", [
        ("Lifecycle coverage", "The campaign model represents reconnaissance, resource development, initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, command-and-control, exfiltration, impact, exploit validation, social/physical, wireless, cloud, identity, mobile, firmware, IoT/OT and AI security objectives."),
        ("Campaign register", f"campaigns={campaigns}; operations={operations}; operation_statuses={op_status}"),
        ("Detection and cleanup", f"detection_outcomes={detections}; cleanup_actions={cleanups}"),
        ("Evidence index", f"{len(files)} red-team evidence/control files indexed in redteam_file_index.txt."),
        ("Honesty rule", "A branch without an approved operation and evidence is Not Executed or Not Tested, never Safe."),
        ("Exploit and high-impact boundary", "TBHM can register and validate approved exploit/control evidence, but does not autonomously generate or launch weaponized exploits, steal credentials, deploy persistence, evade EDR, establish C2, move laterally, phish users, alter OT, or exfiltrate real data. Those operations remain separately approved, operator-executed, hash-bound, imported, and cleanup-verified."),
    ])
    ctx.log("OK", "redteam_summary", f"red-team lifecycle summary written to {out}")
