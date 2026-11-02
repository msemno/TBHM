"""Small portable entity/relationship/timeline store for corporate intelligence.

SQLite is the source of truth.  The schema intentionally records provenance,
confidence, sensitivity and scope status so an OSINT hypothesis cannot silently
become a verified asset.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

DDL = """
CREATE TABLE IF NOT EXISTS entities(
 id TEXT PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL,
 display_name TEXT, confidence REAL, scope_status TEXT, sensitivity TEXT,
 first_seen TEXT, last_seen TEXT, sources_json TEXT, attributes_json TEXT,
 UNIQUE(type,value)
);
CREATE TABLE IF NOT EXISTS relationships(
 id TEXT PRIMARY KEY, src_id TEXT NOT NULL, rel TEXT NOT NULL, dst_id TEXT NOT NULL,
 confidence REAL, first_seen TEXT, last_seen TEXT, source TEXT, evidence_hash TEXT,
 attributes_json TEXT,
 FOREIGN KEY(src_id) REFERENCES entities(id), FOREIGN KEY(dst_id) REFERENCES entities(id)
);
CREATE TABLE IF NOT EXISTS timeline(
 id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, entity_id TEXT, event_type TEXT,
 summary TEXT, source TEXT, evidence_hash TEXT, attributes_json TEXT
);
CREATE TABLE IF NOT EXISTS collection_sources(
 id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT, collected_at TEXT, collector TEXT,
 trust_level TEXT, evidence_hash TEXT, notes TEXT
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(kind: str, value: str) -> str:
    raw = f"{kind.lower()}\0{value.strip().lower()}".encode()
    return f"{kind.lower()}:{hashlib.sha256(raw).hexdigest()[:20]}"


class EntityGraph:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path))
        self.db.row_factory = sqlite3.Row
        self.db.executescript(DDL)
        self.db.execute("PRAGMA foreign_keys=ON")

    def close(self):
        self.db.commit(); self.db.close()

    def entity(self, kind: str, value: str, *, display_name: str = "",
               confidence: float = 0.5, scope_status: str = "unknown",
               sensitivity: str = "corporate", source: str = "",
               attributes: dict | None = None) -> str:
        kind = str(kind or "unknown").strip().lower()
        value = str(value or "").strip()
        if not value:
            raise ValueError("entity value is required")
        eid = stable_id(kind, value)
        row = self.db.execute("SELECT sources_json, first_seen FROM entities WHERE id=?", (eid,)).fetchone()
        sources = []
        first = now()
        if row:
            try: sources = json.loads(row["sources_json"] or "[]")
            except Exception: sources = []
            first = row["first_seen"] or first
        if source and source not in sources: sources.append(source)
        self.db.execute(
            "INSERT INTO entities(id,type,value,display_name,confidence,scope_status,sensitivity,first_seen,last_seen,sources_json,attributes_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "display_name=excluded.display_name, confidence=MAX(entities.confidence,excluded.confidence), "
            "scope_status=CASE WHEN excluded.scope_status!='unknown' THEN excluded.scope_status ELSE entities.scope_status END, "
            "sensitivity=excluded.sensitivity,last_seen=excluded.last_seen,sources_json=excluded.sources_json,attributes_json=excluded.attributes_json",
            (eid, kind, value, display_name or value, float(confidence), scope_status, sensitivity,
             first, now(), json.dumps(sources), json.dumps(attributes or {}, default=str)))
        self.db.commit()
        return eid

    def relationship(self, src: str, rel: str, dst: str, *, confidence: float = 0.5,
                     source: str = "", evidence_hash: str = "", attributes: dict | None = None) -> str:
        rid = "rel:" + hashlib.sha256(f"{src}\0{rel}\0{dst}".encode()).hexdigest()[:24]
        self.db.execute(
            "INSERT INTO relationships(id,src_id,rel,dst_id,confidence,first_seen,last_seen,source,evidence_hash,attributes_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET confidence=MAX(relationships.confidence,excluded.confidence), "
            "last_seen=excluded.last_seen,source=excluded.source,evidence_hash=excluded.evidence_hash,attributes_json=excluded.attributes_json",
            (rid, src, rel, dst, float(confidence), now(), now(), source, evidence_hash,
             json.dumps(attributes or {}, default=str)))
        self.db.commit(); return rid

    def timeline(self, entity_id: str, event_type: str, summary: str, *, at: str = "",
                 source: str = "", evidence_hash: str = "", attributes: dict | None = None):
        self.db.execute("INSERT INTO timeline(at,entity_id,event_type,summary,source,evidence_hash,attributes_json) VALUES(?,?,?,?,?,?,?)",
                        (at or now(), entity_id, event_type, summary[:2000], source, evidence_hash,
                         json.dumps(attributes or {}, default=str)))
        self.db.commit()

    def counts(self) -> dict:
        return {
            "entities": self.db.execute("SELECT COUNT(*) FROM entities").fetchone()[0],
            "relationships": self.db.execute("SELECT COUNT(*) FROM relationships").fetchone()[0],
            "timeline_events": self.db.execute("SELECT COUNT(*) FROM timeline").fetchone()[0],
        }

    def export(self, directory: str | Path) -> dict:
        d = Path(directory); d.mkdir(parents=True, exist_ok=True)
        entities = [dict(r) for r in self.db.execute("SELECT * FROM entities ORDER BY type,value")]
        relationships = [dict(r) for r in self.db.execute("SELECT * FROM relationships ORDER BY rel,src_id,dst_id")]
        timeline = [dict(r) for r in self.db.execute("SELECT * FROM timeline ORDER BY at,id")]
        (d / "entities.json").write_text(json.dumps(entities, indent=2), encoding="utf-8")
        (d / "relationships.json").write_text(json.dumps(relationships, indent=2), encoding="utf-8")
        (d / "timeline.json").write_text(json.dumps(timeline, indent=2), encoding="utf-8")
        _csv(d / "entities.csv", entities)
        _csv(d / "relationships.csv", relationships)
        _graphml(d / "entity_graph.graphml", entities, relationships)
        _stix(d / "entity_graph.stix.json", entities, relationships)
        return {"entities": len(entities), "relationships": len(relationships), "timeline": len(timeline),
                "exports": ["entities.json", "relationships.json", "timeline.json",
                            "entities.csv", "relationships.csv", "entity_graph.graphml",
                            "entity_graph.stix.json"]}


def _csv(path: Path, rows: list[dict]):
    keys = []
    for row in rows:
        for k in row:
            if k not in keys: keys.append(k)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=keys or ["status"]); w.writeheader()
        for row in rows: w.writerow(row)


def _graphml(path: Path, entities: list[dict], relationships: list[dict]):
    import html
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
             '<key id="type" for="node" attr.name="type" attr.type="string"/>',
             '<key id="value" for="node" attr.name="value" attr.type="string"/>',
             '<key id="rel" for="edge" attr.name="relationship" attr.type="string"/>',
             '<graph id="TBHM" edgedefault="directed">']
    for e in entities:
        lines.append(f'<node id="{html.escape(e["id"])}"><data key="type">{html.escape(e["type"])}</data><data key="value">{html.escape(e["value"])}</data></node>')
    for r in relationships:
        lines.append(f'<edge id="{html.escape(r["id"])}" source="{html.escape(r["src_id"])}" target="{html.escape(r["dst_id"])}"><data key="rel">{html.escape(r["rel"])}</data></edge>')
    lines += ['</graph>', '</graphml>']
    path.write_text("\n".join(lines)+"\n", encoding="utf-8")


def _stix(path: Path, entities: list[dict], relationships: list[dict]):
    """Write a minimal STIX 2.1 bundle using custom TBHM entity objects.

    Custom objects preserve provenance without pretending a heuristic company
    entity is a standardized STIX identity/domain object. Consumers that allow
    custom STIX objects can import the bundle; JSON/CSV/GraphML remain the
    portable fallbacks.
    """
    namespace = uuid.UUID("f6ed6210-f366-4c45-9d02-e4f52f9a15d6")
    objects = []
    refs = {}
    for e in entities:
        sid = "x-tbhm-entity--" + str(uuid.uuid5(namespace, str(e["id"])))
        refs[e["id"]] = sid
        try: sources = json.loads(e.get("sources_json") or "[]")
        except Exception: sources = []
        objects.append({
            "type": "x-tbhm-entity", "spec_version": "2.1", "id": sid,
            "created": e.get("first_seen") or now(), "modified": e.get("last_seen") or now(),
            "name": e.get("display_name") or e.get("value"),
            "x_tbhm_entity_type": e.get("type"), "x_tbhm_value": e.get("value"),
            "x_tbhm_confidence": e.get("confidence"),
            "x_tbhm_scope_status": e.get("scope_status"),
            "x_tbhm_sensitivity": e.get("sensitivity"),
            "x_tbhm_sources": sources,
        })
    for r in relationships:
        src = refs.get(r.get("src_id")); dst = refs.get(r.get("dst_id"))
        if not src or not dst: continue
        objects.append({
            "type": "relationship", "spec_version": "2.1",
            "id": "relationship--" + str(uuid.uuid5(namespace, str(r["id"]))),
            "created": r.get("first_seen") or now(), "modified": r.get("last_seen") or now(),
            "relationship_type": re.sub(r"[^a-z0-9-]+", "-", str(r.get("rel") or "related-to").lower().replace("_", "-"))[:250] or "related-to",
            "source_ref": src, "target_ref": dst,
            "confidence": max(0, min(100, int(float(r.get("confidence") or 0.5) * 100))),
            "description": f"TBHM source={r.get('source') or ''}; evidence_hash={r.get('evidence_hash') or ''}",
        })
    bundle = {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": objects}
    path.write_text(json.dumps(bundle, indent=2, default=str), encoding="utf-8")
