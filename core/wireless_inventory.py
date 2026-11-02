"""Passive wireless observation import and risk annotation."""
from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ALIASES={"essid":"ssid","mac":"bssid","chan":"channel","freq":"frequency","privacy":"encryption_type","cipher":"encryption_type","power":"signal_strength","rssi":"signal_strength","first time seen":"first_seen","last time seen":"last_seen"}


def _rows(path: Path):
    if path.suffix.lower()==".csv":
        with path.open(newline="",encoding="utf-8-sig",errors="replace") as h: return [dict(x) for x in csv.DictReader(h)]
    data=json.loads(path.read_text(encoding="utf-8",errors="replace"))
    if isinstance(data,list): return [x for x in data if isinstance(x,dict)]
    for key in ("networks","observations","access_points","records"):
        if isinstance(data,dict) and isinstance(data.get(key),list): return [x for x in data[key] if isinstance(x,dict)]
    return [data] if isinstance(data,dict) else []


def _risk(encryption: str, ssid: str) -> list[str]:
    text=(encryption or "").lower(); risks=[]
    if not text or text in {"open","none","opn"}: risks.append("Open or unknown encryption; validate whether the network is intended to be public.")
    if "wep" in text: risks.append("WEP is obsolete and should be replaced with WPA2-AES or WPA3.")
    if "tkip" in text: risks.append("TKIP is deprecated; prefer AES/CCMP or WPA3.")
    if ssid.strip().lower() in {"linksys","default","netgear","wireless"}: risks.append("Default-like SSID may indicate incomplete hardening or asset identification.")
    return risks


def import_observations(path: str | Path, *, location_label: str = "", max_records: int = 50000) -> dict:
    root=Path(path); files=[root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in {".json",".csv"}] if root.is_dir() else []
    out=[]; malformed=[]; seen=set()
    for source in files[:1000]:
        try: records=_rows(source)
        except Exception as exc: malformed.append({"source":str(source),"error":f"{type(exc).__name__}: {exc}"}); continue
        for idx,raw in enumerate(records[:max_records]):
            normalized={ALIASES.get(str(k).strip().lower(),str(k).strip().lower().replace(" ","_")):v for k,v in raw.items()}
            bssid=str(normalized.get("bssid") or "").strip().lower(); ssid=str(normalized.get("ssid") or "").strip()
            if not (bssid or ssid): malformed.append({"source":str(source),"record":idx,"error":"missing ssid and bssid"}); continue
            row={"ssid":ssid,"bssid":bssid,"channel":normalized.get("channel"),"frequency":normalized.get("frequency"),"encryption_type":normalized.get("encryption_type") or normalized.get("encryption"),"signal_strength":normalized.get("signal_strength"),"vendor":normalized.get("vendor"),"first_seen":normalized.get("first_seen"),"last_seen":normalized.get("last_seen"),"observation_source":normalized.get("observation_source") or source.name,"location_label":normalized.get("location_label") or location_label}
            basis="|".join(str(row.get(x) or "") for x in ("bssid","ssid","observation_source","location_label")); row["observation_id"]="wifi-"+hashlib.sha256(basis.encode()).hexdigest()[:20]
            if row["observation_id"] in seen: continue
            seen.add(row["observation_id"]); row["risk_notes"]=_risk(str(row["encryption_type"] or ""),ssid); row["import_timestamp"]=datetime.now(timezone.utc).isoformat(); out.append(row)
    return {"schema_version":"1","capability":"passive_wireless_inventory","observations":out,"malformed":malformed,"summary":{"files":len(files),"observations":len(out),"malformed":len(malformed)},"boundary":"Passive/import-only inventory. No capture automation, deauthentication, cracking, impersonation, rogue access point, or credential interception."}
