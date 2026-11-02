"""Function-level binary patch comparison over normalized IR documents."""
from __future__ import annotations

import difflib
import hashlib
import json
import re
from pathlib import Path

from core.reverse_ir import add_fingerprints, function_fingerprint

SECURITY_CALLS = re.compile(r"(?i)(system|exec|popen|strcpy|memcpy|sprintf|snprintf|validate|sanit|check|verify|signature|auth|privilege)")


def _feature(fn: dict) -> str:
    parts = [str(fn.get("name") or ""), str(fn.get("size") or 0)]
    parts.extend(str(op.get("mnemonic") or op.get("opcode") or "") for op in fn.get("pcode", []) if isinstance(op, dict))
    parts.extend(str(x.get("name") or x.get("address") or x) if isinstance(x, dict) else str(x) for x in fn.get("calls", []))
    parts.extend(str(x.get("value") or x) if isinstance(x, dict) else str(x) for x in fn.get("strings", []))
    return "|".join(parts)


def _security_tokens(fn: dict) -> set[str]:
    text = _feature(fn) + "|" + str(fn.get("decompiled_c") or "")
    return {m.group(0).lower() for m in SECURITY_CALLS.finditer(text)}


def compare(old_ir: dict, new_ir: dict, similarity_threshold: float = 0.72) -> dict:
    old = [x for x in old_ir.get("functions", []) if isinstance(x, dict)]
    new = [x for x in new_ir.get("functions", []) if isinstance(x, dict)]
    for fn in old + new:
        fn.setdefault("fingerprint", function_fingerprint(fn))
    old_by_fp = {fn["fingerprint"]: fn for fn in old}
    new_by_fp = {fn["fingerprint"]: fn for fn in new}
    exact = []
    matched_old, matched_new = set(), set()
    for fp, old_fn in old_by_fp.items():
        if fp in new_by_fp:
            new_fn = new_by_fp[fp]
            exact.append({"old": old_fn.get("name"), "new": new_fn.get("name"), "fingerprint": fp})
            matched_old.add(id(old_fn)); matched_new.add(id(new_fn))
    old_names = {str(fn.get("name")): fn for fn in old if id(fn) not in matched_old}
    new_names = {str(fn.get("name")): fn for fn in new if id(fn) not in matched_new}
    changed = []
    for name in sorted(set(old_names) & set(new_names)):
        a, b = old_names[name], new_names[name]
        ratio = difflib.SequenceMatcher(None, _feature(a), _feature(b)).ratio()
        changed.append({"old": name, "new": name, "similarity": round(ratio, 4),
                        "old_fingerprint": a["fingerprint"], "new_fingerprint": b["fingerprint"],
                        "old_size": a.get("size", 0), "new_size": b.get("size", 0),
                        "security_tokens_added": sorted(_security_tokens(b) - _security_tokens(a)),
                        "security_tokens_removed": sorted(_security_tokens(a) - _security_tokens(b))})
        matched_old.add(id(a)); matched_new.add(id(b))
    remaining_old = [fn for fn in old if id(fn) not in matched_old]
    remaining_new = [fn for fn in new if id(fn) not in matched_new]
    fuzzy = []
    for a in list(remaining_old):
        best = None
        for b in remaining_new:
            ratio = difflib.SequenceMatcher(None, _feature(a), _feature(b)).ratio()
            if best is None or ratio > best[0]:
                best = (ratio, b)
        if best and best[0] >= similarity_threshold:
            ratio, b = best
            fuzzy.append({"old": a.get("name"), "new": b.get("name"), "similarity": round(ratio, 4),
                          "old_fingerprint": a["fingerprint"], "new_fingerprint": b["fingerprint"],
                          "security_tokens_added": sorted(_security_tokens(b) - _security_tokens(a)),
                          "security_tokens_removed": sorted(_security_tokens(a) - _security_tokens(b))})
            matched_old.add(id(a)); matched_new.add(id(b)); remaining_new.remove(b)
    added = [fn for fn in new if id(fn) not in matched_new]
    removed = [fn for fn in old if id(fn) not in matched_old]
    security_deltas = [row for row in changed + fuzzy if row.get("security_tokens_added") or row.get("security_tokens_removed")]
    return {
        "schema": "tbhm.binary-diff/1.0", "exact_matches": exact, "changed_functions": changed,
        "fuzzy_matches": fuzzy, "added_functions": [{"name": f.get("name"), "start": f.get("start"), "fingerprint": f["fingerprint"]} for f in added],
        "removed_functions": [{"name": f.get("name"), "start": f.get("start"), "fingerprint": f["fingerprint"]} for f in removed],
        "security_deltas": security_deltas,
        "counts": {"old": len(old), "new": len(new), "exact": len(exact), "changed": len(changed),
                   "fuzzy": len(fuzzy), "added": len(added), "removed": len(removed)},
    }
