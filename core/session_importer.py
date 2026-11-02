"""Import-only session and beacon evidence normalization."""
from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

_FIELDS = ["source_tool", "session_identifier", "hostname", "username", "operating_system", "architecture", "source_ip", "destination_ip", "transport", "first_seen", "last_seen", "status", "privilege_context", "tags", "evidence_source", "approval_reference"]
_ALIASES = {
    "source": "source_tool", "tool": "source_tool", "session_id": "session_identifier", "beacon_id": "session_identifier",
    "host": "hostname", "computer": "hostname", "user": "username", "os": "operating_system", "arch": "architecture",
    "src_ip": "source_ip", "source_address": "source_ip", "dst_ip": "destination_ip", "destination_address": "destination_ip",
    "protocol": "transport", "firstSeen": "first_seen", "lastSeen": "last_seen", "privilege": "privilege_context",
}


def _records(path: Path) -> list[dict]:
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if isinstance(data, list): return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("sessions", "beacons", "records", "items", "data"):
            if isinstance(data.get(key), list): return [x for x in data[key] if isinstance(x, dict)]
        return [data]
    raise ValueError("session evidence JSON must contain an object or list")


def _normalize(raw: dict, source_path: Path, *, redact_usernames: bool) -> tuple[dict | None, list[str]]:
    mapped: dict = {}
    for key, value in raw.items(): mapped[_ALIASES.get(str(key), str(key))] = value
    errors=[]
    sid=str(mapped.get("session_identifier") or "").strip()
    source_tool=str(mapped.get("source_tool") or "").strip()
    if not sid: errors.append("missing session_identifier")
    if not source_tool: errors.append("missing source_tool")
    if errors: return None, errors
    row={field: mapped.get(field, "") for field in _FIELDS}
    if isinstance(row["tags"], str): row["tags"]=[x.strip() for x in row["tags"].split(",") if x.strip()]
    elif not isinstance(row["tags"], list): row["tags"]=[]
    if redact_usernames and row["username"]:
        row["username_sha256"] = hashlib.sha256(str(row["username"]).lower().encode()).hexdigest(); row["username"]="[REDACTED]"
    row["evidence_source"] = str(row["evidence_source"] or source_path.name)
    basis="|".join(str(row.get(k) or "") for k in ("source_tool","session_identifier","hostname","source_ip","destination_ip"))
    row["normalized_id"]="session-"+hashlib.sha256(basis.encode()).hexdigest()[:20]
    row["import_timestamp"]=datetime.now(timezone.utc).isoformat()
    row["provenance"]={"path":str(source_path),"sha256":hashlib.sha256(source_path.read_bytes()).hexdigest()}
    return row, []


def import_evidence(path: str | Path, *, redact_usernames: bool = False, max_records: int = 10000) -> dict:
    root=Path(path)
    files=[root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in {".json",".csv"}] if root.is_dir() else []
    normalized=[]; malformed=[]; seen=set(); duplicate_count=0
    for source in files[:1000]:
        try: records=_records(source)
        except Exception as exc:
            malformed.append({"source":str(source),"record":None,"errors":[f"{type(exc).__name__}: {exc}"]}); continue
        for idx, raw in enumerate(records[:max_records]):
            row, errors=_normalize(raw,source,redact_usernames=redact_usernames)
            if errors: malformed.append({"source":str(source),"record":idx,"errors":errors}); continue
            if row["normalized_id"] in seen:
                duplicate_count += 1
                continue
            seen.add(row["normalized_id"]); normalized.append(row)
            if len(normalized)>=max_records: break
    return {"schema_version":"1","capability":"session_beacon_import","implementation_state":"import_only","records":normalized,"malformed_records":malformed,"summary":{"files":len(files),"normalized":len(normalized),"malformed":len(malformed),"deduplicated":duplicate_count},"boundary":"No C2 service, payload, beacon, or session-control function is implemented."}
