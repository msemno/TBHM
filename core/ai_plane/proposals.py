"""Propose-and-approve gate + tamper-evident audit.

The advisor may *propose* source changes. It never writes to the TBHM tree.
A proposal is recorded in the store and materialized under
$TBHM_AI_HOME/proposals/pending/<uid>/ with:
    proposal.json   structured description + evidence + risks
    change.patch    a unified diff (advisory; NOT applied)

Approval only moves the proposal to accepted/ and logs operator intent. Applying
it remains a deliberate human git action (branch -> tests -> review -> merge),
per the Propose-and-Approve architecture. Nothing here shells out to `git apply`
against the working tree.

Every proposal/decision is appended to a hash-chained audit log so the evidence
trail cannot be silently rewritten.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from pathlib import Path


def _hash(prev: str, payload: dict) -> str:
    h = hashlib.sha256()
    h.update(prev.encode("utf-8"))
    h.update(json.dumps(payload, sort_keys=True, default=str).encode("utf-8"))
    return h.hexdigest()


class Audit:
    """Append-only, hash-chained audit written both to SQLite and JSONL."""

    def __init__(self, store, home):
        self.store = store
        self.home = home

    def record(self, action: str, subject: str | None = None, detail: dict | None = None) -> str:
        prev = self.store.last_audit_hash()
        at = time.time()   # one timestamp, used for both the hash and the stored row
        payload = {"action": action, "subject": subject, "detail": detail or {}, "at": at}
        this = _hash(prev, payload)
        self.store.audit(action, subject, detail, prev, this, created_at=at)
        line = json.dumps({**payload, "prev_hash": prev, "this_hash": this}, default=str)
        with open(self.home.hash_chain, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return this

    def verify_chain(self) -> tuple[bool, str]:
        rows = self.store.query("SELECT action, subject, detail_json, prev_hash, this_hash, "
                                "created_at FROM audit_log ORDER BY id ASC")
        prev = ""
        for r in rows:
            payload = {"action": r["action"], "subject": r["subject"],
                       "detail": json.loads(r["detail_json"] or "{}"), "at": r["created_at"]}
            expect = _hash(prev, payload)
            if r["prev_hash"] != prev or r["this_hash"] != expect:
                return False, f"audit chain broken at action={r['action']}"
            prev = r["this_hash"]
        return True, f"audit chain intact ({len(rows)} entries)"


class ProposalGate:
    def __init__(self, store, home, audit: Audit):
        self.store = store
        self.home = home
        self.audit = audit

    def create(self, *, problem: str, evidence: list, affected_files: list,
               patch_text: str = "", expected_benefit: str = "", risks: list | None = None) -> dict:
        uid = "AI-PROP-" + uuid.uuid4().hex[:8].upper()
        pdir = self.home.proposals_pending / uid
        pdir.mkdir(parents=True, exist_ok=True)
        patch_path = pdir / "change.patch"
        if patch_text:
            patch_path.write_text(patch_text, encoding="utf-8")
        record = {
            "proposal_id": uid,
            "problem": problem,
            "evidence": evidence,
            "affected_files": affected_files,
            "patch_path": str(patch_path) if patch_text else "",
            "expected_benefit": expected_benefit,
            "risks": risks or [],
            "status": "pending",
            "created_at": time.time(),
        }
        (pdir / "proposal.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
        self.store.add_proposal(
            proposal_uid=uid, problem=problem[:4000],
            evidence_json=json.dumps(evidence, default=str),
            affected_files=json.dumps(affected_files), patch_path=record["patch_path"],
            expected_benefit=expected_benefit[:2000],
            risks=json.dumps(risks or []), status="pending")
        self.audit.record("proposal.create", uid, {"files": affected_files})
        return record

    def list_pending(self) -> list[dict]:
        out = []
        for d in sorted(self.home.proposals_pending.glob("AI-PROP-*")):
            pj = d / "proposal.json"
            if pj.exists():
                out.append(json.loads(pj.read_text()))
        return out

    def decide(self, uid: str, accept: bool, note: str = "") -> dict:
        if not isinstance(uid, str) or not re.fullmatch(r'AI-PROP-[A-F0-9]{8}', uid):
            return {'ok': False, 'detail': 'invalid proposal identity'}
        src = self.home.proposals_pending / uid
        if src.is_symlink() or src.resolve().parent != self.home.proposals_pending.resolve():
            return {'ok': False, 'detail': 'unsafe proposal directory'}
        if not src.exists():
            return {"ok": False, "detail": f"no pending proposal {uid}"}
        dst_base = self.home.proposals_accepted if accept else self.home.proposals_rejected
        dst = dst_base / uid
        dst.parent.mkdir(parents=True, exist_ok=True)
        src.rename(dst)
        self.store.set_proposal_status(uid, "accepted" if accept else "rejected")
        self.audit.record("proposal.decide", uid,
                          {"decision": "accepted" if accept else "rejected", "note": note})
        return {"ok": True, "uid": uid, "status": "accepted" if accept else "rejected",
                "applied": False,
                "detail": ("Approved and archived. Apply deliberately via git "
                           "(branch -> tests -> review -> merge). Not auto-applied.")
                          if accept else "Rejected and archived."}
