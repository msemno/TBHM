"""
Phase: backup_restore_simulation   (v3.3)

Tabletop + safe-validation register for backup/restore and ransomware-recovery
resilience. It does NOT delete, encrypt, or restore anything. It generates a
structured checklist an engagement lead walks through with the client, plus
detection of backup-exposure signals already seen this run (exposed backup
files, open backup service ports).

Requires --backup-sim (it's an interview/tabletop aid, off by default).
"""
from __future__ import annotations

import json
import re

TABLETOP = [
    ("Backup coverage", "Are all Tier-0/critical systems backed up? Frequency/RPO?"),
    ("Offline/immutable copies", "Is there an air-gapped or immutable (WORM) copy ransomware can't reach?"),
    ("Restore tested", "When was a full restore last tested end-to-end? RTO measured?"),
    ("Backup credentials", "Are backup service accounts separate, least-privilege, MFA-protected?"),
    ("Backup network isolation", "Is the backup fabric segmented from production/AD?"),
    ("Encryption of backups", "Are backups encrypted at rest and keys escrowed separately?"),
    ("Monitoring", "Are mass-deletion / mass-encryption events on backups alerted?"),
    ("3-2-1 rule", "3 copies, 2 media, 1 offsite — verified?"),
    ("Runbook", "Is there a tested ransomware recovery runbook with owners and comms?"),
]
_BACKUP_FILE_RE = re.compile(r"(?i)\.(bak|bkp|backup|dump|sql|tar\.gz|zip|old|swp)(\b|$)")
_BACKUP_PORTS = {"nfs": 2049, "smb": 445, "rsync": 873, "bacula": 9101, "veeam": 9392}


def run(ctx):
    if not getattr(ctx.args, "backup_sim", False):
        return

    out_dir = ctx.output / "backup_restore"
    out_dir.mkdir(exist_ok=True)

    md = ["# Backup / restore resilience tabletop (safe)", "",
          "Walk through with the client. No data was modified, deleted, or restored.", ""]
    for topic, q in TABLETOP:
        md += [f"## {topic}", f"- {q}", "- Status: ☐ pass ☐ gap ☐ n/a", "- Evidence:", ""]
    (out_dir / "backup_restore_tabletop.md").write_text("\n".join(md))
    (out_dir / "backup_restore_tabletop.json").write_text(json.dumps(
        [{"topic": t, "question": q} for t, q in TABLETOP], indent=2))

    # detection: exposed backup artefacts already found this run
    exposed = []
    try:
        for f in ctx.storage.all_findings():
            blob = f.get("url", "") + " " + f.get("evidence", "") + " " + f.get("title", "")
            if _BACKUP_FILE_RE.search(blob):
                exposed.append(f.get("title", "")[:80])
    except Exception:
        pass
    if exposed:
        ctx.save_finding({
            "phase": "backup_restore_simulation", "severity": "MEDIUM", "confidence": "LOW",
            "title": f"Potential exposed backup artefact(s): {len(exposed)}",
            "target": ctx.targets[0] if ctx.targets else "",
            "description": "Findings this run referenced backup-like artefacts: "
                           + "; ".join(exposed[:6]),
            "evidence": "; ".join(exposed[:10]),
            "impact": "Exposed backups can leak data wholesale and undermine recovery integrity.",
            "remediation": "Remove public backup files; isolate and encrypt backup storage.",
            "cwe": "CWE-530", "mrs_score": 50,
        })

    ctx.save_finding({
        "phase": "backup_restore_simulation", "severity": "INFO", "confidence": "HIGH",
        "title": f"Backup/restore resilience tabletop ({len(TABLETOP)} items)",
        "target": ctx.targets[0] if ctx.targets else "",
        "description": "Tabletop register generated for backup/ransomware-recovery review.",
        "evidence": str(out_dir / "backup_restore_tabletop.md"),
        "impact": "Coverage aid for recovery resilience.",
        "remediation": "Complete the tabletop and validate a real restore in a lab.",
        "mrs_score": 15,
    })
    ctx.log("OK", "backup_restore_simulation",
            f"tabletop ({len(TABLETOP)} items) | {len(exposed)} exposed-backup signal(s)")
