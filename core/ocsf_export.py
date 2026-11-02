"""Class-aware deterministic OCSF-oriented export."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

SEVERITY={"INFO":1,"LOW":2,"MEDIUM":3,"HIGH":4,"CRITICAL":5}
CLASS_MAP={
    "finding": (2,2004,200401),
    "vulnerability": (2,2004,200401),
    "cloud_iam": (3,3002,300201),
    "identity": (3,3002,300201),
    "session": (4,4001,400101),
    "wireless": (5,5001,500101),
    "compliance": (2,2006,200601),
    "cicd": (2,2004,200402),
    "osint": (1,1001,100101),
}
VOLATILE={"time","timestamp","created_at","updated_at","exported_at","import_timestamp","collected_at","started_at","ended_at","runtime_ms"}


def _stable(value):
    if isinstance(value,dict): return {k:_stable(v) for k,v in sorted(value.items()) if k not in VOLATILE}
    if isinstance(value,list): return sorted((_stable(v) for v in value),key=lambda x:json.dumps(x,sort_keys=True,default=str))
    return value


def fingerprint(event: dict) -> str:
    canonical=json.dumps(_stable(event),sort_keys=True,separators=(",",":"),ensure_ascii=False,default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def classify(record: dict, hint: str | None = None) -> str:
    text=" ".join(str(record.get(k) or "") for k in ("domain","phase","source_capability","kind","event_type","title")).lower()
    if hint in CLASS_MAP: return str(hint)
    for key in ("cloud_iam","session","wireless","compliance","cicd","osint","identity"):
        if key.replace("_"," ") in text or key in text: return key
    return "vulnerability" if record.get("cwe") or record.get("cvss") else "finding"


def event(record: dict, *, tool_version: str, profile: str = "", class_hint: str | None = None, observed_time: str | None = None) -> dict:
    cls=classify(record,class_hint); category_uid,class_uid,type_uid=CLASS_MAP[cls]
    severity=str(record.get("severity") or "INFO").upper(); target=str(record.get("url") or record.get("target") or record.get("hostname") or "")
    base={"activity_id":1,"category_uid":category_uid,"class_uid":class_uid,"type_uid":type_uid,"severity_id":SEVERITY.get(severity,1),"metadata":{"product":{"name":"TBHM","version":tool_version},"profiles":[profile] if profile else [],"version":"1.1.0-compatible"},"finding_info":{"uid":str(record.get("id") or record.get("normalized_id") or ""),"title":str(record.get("title") or record.get("event_type") or cls),"desc":str(record.get("description") or record.get("reason") or "")[:4000],"types":[str(record.get("phase") or record.get("source_capability") or cls)],"analytic":{"name":str(record.get("source_capability") or record.get("phase") or "TBHM")}},"resources":[{"name":target,"type":"url_or_asset"}] if target else [],"unmapped":{"confidence":record.get("confidence"),"status":record.get("status"),"source_module":record.get("phase") or record.get("source_module"),"source_capability":record.get("source_capability"),"evidence_references":record.get("evidence_paths") or record.get("evidence_references") or [],"original_id":record.get("id") or record.get("normalized_id"),"provenance":record.get("provenance")}}
    base["time"]=observed_time or str(record.get("discovered_at") or record.get("first_seen") or datetime.now(timezone.utc).isoformat())
    base["unmapped"]["stable_fingerprint"]=fingerprint(base)
    if not base["finding_info"]["uid"]: base["finding_info"]["uid"]=base["unmapped"]["stable_fingerprint"]
    return base
