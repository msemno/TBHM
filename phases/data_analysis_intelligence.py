"""Dedicated entity, relationship, timeline and data-quality analysis phase.

The phase is offline. It correlates TBHM findings and operator-supplied tabular
or JSON evidence, produces SQLite/GraphML/CSV and optional DuckDB/Parquet
artifacts, and never changes vulnerability confirmation by correlation alone.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from core import redteam_utils as RT
from core.ai_plane.findings import confirmation_status
from core.entity_graph import EntityGraph

DOMAIN_RE = re.compile(r"(?<![@A-Za-z0-9_-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_file(path: Path) -> str:
    try:
        return _hash_bytes(path.read_bytes())
    except Exception:
        return ""


def _iter_records(path: Path, hard_cap: int = 100_000):
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open(newline="", encoding="utf-8", errors="ignore") as fh:
            for i, row in enumerate(csv.DictReader(fh)):
                if i >= hard_cap: break
                yield row
    elif suffix == ".jsonl":
        for i, line in enumerate(path.read_text(errors="ignore").splitlines()):
            if i >= hard_cap: break
            try:
                value = json.loads(line)
                if isinstance(value, dict): yield value
            except Exception:
                continue
    elif suffix == ".json":
        data = json.loads(path.read_text(errors="ignore"))
        values = data if isinstance(data, list) else data.get("records", data.get("items", [data])) if isinstance(data, dict) else []
        for i, value in enumerate(values):
            if i >= hard_cap: break
            if isinstance(value, dict): yield value


def _record_text(record: dict) -> str:
    return " ".join(str(v) for v in record.values() if isinstance(v, (str, int, float, bool)))[:50_000]


def _ingest_record(graph: EntityGraph, record: dict, *, source: str, allow_pii: bool) -> int:
    text = _record_text(record)
    record_digest = _hash_bytes(json.dumps(record, sort_keys=True, default=str).encode())
    rid = graph.entity("data_record", f"{source}:{record_digest}", display_name=source,
                       confidence=0.5, scope_status="analytical-input", source=source,
                       sensitivity="pii-limited" if allow_pii else "redacted-corporate",
                       attributes={"fields": sorted(record)[:100], "record_sha256": record_digest})
    count = 1
    entities: list[tuple[str, str, str]] = []
    entities += [("domain", x.lower(), "mentions_domain") for x in sorted(set(DOMAIN_RE.findall(text)))[:200]]
    entities += [("url", x[:2000], "mentions_url") for x in sorted(set(URL_RE.findall(text)))[:200]]
    entities += [("ip", x, "mentions_ip") for x in sorted(set(IP_RE.findall(text)))[:200]]
    entities += [("cve", x.upper(), "mentions_vulnerability") for x in sorted(set(CVE_RE.findall(text)))[:200]]
    for email in sorted(set(EMAIL_RE.findall(text)))[:200]:
        value = email.lower() if allow_pii else "sha256:" + _hash_bytes(email.lower().encode())
        entities.append(("email" if allow_pii else "email_hash", value, "mentions_identity"))
    for kind, value, rel in entities:
        eid = graph.entity(kind, value, confidence=0.45, scope_status="analytical-candidate",
                           source=source, sensitivity="pii-limited" if kind == "email" else "corporate")
        graph.relationship(rid, rel, eid, confidence=0.45, source=source, evidence_hash=record_digest)
        count += 1
    return count


def _duckdb_export(out: Path, finding_rows: list[dict], input_rows: list[dict]) -> dict:
    """Export through the current interpreter or TBHM's isolated DuckDB venv."""
    try:
        import duckdb
    except Exception:
        tool_home = Path(os.environ.get("TBHM_TOOL_HOME", Path.home() / ".local/share/tbhm-tools"))
        vpy = tool_home / "venvs/duckdb/bin/python"
        helper = Path(__file__).resolve().parents[1] / "scripts/data/duckdb_export.py"
        if not vpy.is_file() or not helper.is_file():
            return {"available": False, "reason": "duckdb is not installed in the runtime or isolated tool environment"}
        try:
            with tempfile.TemporaryDirectory(prefix="tbhm-duckdb-") as td:
                td_path = Path(td)
                findings_path = td_path / "findings.json"
                inputs_path = td_path / "inputs.json"
                result_path = td_path / "result.json"
                findings_path.write_text(json.dumps(finding_rows), encoding="utf-8")
                inputs_path.write_text(json.dumps(input_rows), encoding="utf-8")
                cp = subprocess.run(
                    [str(vpy), str(helper), "--output", str(out), "--findings", str(findings_path),
                     "--inputs", str(inputs_path), "--result", str(result_path)],
                    text=True, capture_output=True, timeout=180, check=False,
                )
                if cp.returncode == 0 and result_path.is_file():
                    return json.loads(result_path.read_text(encoding="utf-8"))
                return {"available": False, "reason": "isolated duckdb export failed",
                        "return_code": cp.returncode, "error": cp.stderr[-2000:]}
        except Exception as exc:
            return {"available": False, "reason": f"isolated duckdb export error: {type(exc).__name__}: {exc}"}
    db_path = out / "analysis.duckdb"
    conn = duckdb.connect(str(db_path))
    try:
        conn.execute("CREATE OR REPLACE TABLE findings(id VARCHAR,title VARCHAR,severity VARCHAR,confirmation VARCHAR,phase VARCHAR,target VARCHAR)")
        if finding_rows:
            conn.executemany("INSERT INTO findings VALUES (?,?,?,?,?,?)", [
                (str(r.get("id", "")), str(r.get("title", "")), str(r.get("severity", "")),
                 str(r.get("confirmation", "")), str(r.get("phase", "")), str(r.get("target", "")))
                for r in finding_rows])
        conn.execute("CREATE OR REPLACE TABLE input_files(file VARCHAR,size BIGINT,sha256 VARCHAR,suffix VARCHAR,records BIGINT)")
        if input_rows:
            conn.executemany("INSERT INTO input_files VALUES (?,?,?,?,?)", [
                (r["file"], int(r["size"]), r["sha256"], r["suffix"], int(r.get("records", 0)))
                for r in input_rows])
        conn.execute(f"COPY findings TO '{str(out / 'findings.parquet')}' (FORMAT PARQUET)")
        conn.execute(f"COPY input_files TO '{str(out / 'input_files.parquet')}' (FORMAT PARQUET)")
        return {"available": True, "database": str(db_path),
                "parquet": ["findings.parquet", "input_files.parquet"],
                "execution_environment": "runtime"}
    finally:
        conn.close()


def run(ctx):
    _profile_name=str((getattr(ctx, "profile", {}) or {}).get("name", ""))
    _corporate_profile=_profile_name in {"authorized_redteam", "authorized_assumed_breach"}
    if not (_corporate_profile or getattr(ctx.args, "data_analysis", False) or getattr(ctx.args, "corporate_osint", False)
            or getattr(ctx.args, "redteam", False) or getattr(ctx.args, "data_input", None)):
        return
    out = RT.evidence_dir(ctx, "105_data_analysis_intelligence")
    graph_path = ctx.phase_state.get("corporate_osint_db")
    graph = EntityGraph(graph_path or (out / "analysis_graph.db"))
    findings = ctx.storage.all_findings()
    severity = Counter(); phases = Counter(); statuses = Counter(); duplicate = Counter(); missing = []
    finding_rows = []
    for finding in findings:
        sev = str(finding.get("severity") or "INFO").upper()
        phase = str(finding.get("phase") or "unknown")
        state = confirmation_status(finding)
        severity[sev] += 1; phases[phase] += 1; statuses[state] += 1
        target = str(finding.get("url") or finding.get("target") or "")
        duplicate[(str(finding.get("title", "")).lower(), target.lower())] += 1
        if not finding.get("evidence") or not target:
            missing.append(int(finding.get("id") or 0))
        finding_rows.append({"id": finding.get("id"), "title": finding.get("title"),
                             "severity": sev, "confirmation": state, "phase": phase, "target": target})
        if target:
            eid = graph.entity("asset_reference", target, confidence=.7, scope_status="from-finding", source=f"finding:{finding.get('id')}")
            vid = graph.entity("finding", str(finding.get("id")), display_name=str(finding.get("title")),
                               confidence=.8, scope_status=state, source=f"phase:{phase}",
                               attributes={"severity": sev, "phase": phase})
            graph.relationship(eid, "has_finding", vid, confidence=.8, source=f"finding:{finding.get('id')}")
            graph.timeline(eid, "finding_observed", str(finding.get("title")),
                           at=str(finding.get("discovered_at") or ""), source=phase)

    allow_pii = bool(getattr(ctx.args, "osint_pii_policy", None))
    input_rows = []
    source = getattr(ctx.args, "data_input", None)
    if source:
        q = Path(source)
        files = [q] if q.is_file() else [p for p in q.rglob("*") if p.is_file()] if q.is_dir() else []
        for p in files[:1000]:
            row = {"file": str(p), "size": p.stat().st_size, "sha256": _hash_file(p),
                   "suffix": p.suffix.lower(), "records": 0}
            if p.suffix.lower() in {".csv", ".json", ".jsonl"} and p.stat().st_size <= 100_000_000:
                try:
                    for record in _iter_records(p):
                        _ingest_record(graph, record, source=p.name, allow_pii=allow_pii)
                        row["records"] += 1
                except Exception as exc:
                    row["parse_error"] = str(exc)
            input_rows.append(row)

    graph_stats = graph.export(out / "graph_exports")
    graph.close()
    duplicates = sum(n - 1 for n in duplicate.values() if n > 1)
    quality = {
        "findings_missing_evidence_or_target": len(missing),
        "duplicate_finding_candidates": duplicates,
        "input_files_hashed": len(input_rows),
        "input_records_normalized": sum(int(x.get("records", 0)) for x in input_rows),
        "pii_policy_declared": allow_pii,
        "email_values_hashed_without_pii_policy": not allow_pii,
        "provenance_files_present": sum(1 for p in ctx.output.rglob("*") if p.is_file() and p.suffix.lower() in {".json", ".csv", ".md"}),
    }
    duckdb_result = _duckdb_export(out, finding_rows, input_rows)
    summary = {"severity": dict(severity), "confirmation": dict(statuses),
               "top_phases": phases.most_common(25), "graph": graph_stats,
               "quality": quality, "duckdb": duckdb_result}
    (out / "analysis_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    RT.write_csv(out / "input_provenance.csv", input_rows)
    RT.write_csv(out / "phase_distribution.csv", [{"phase": k, "findings": v} for k, v in phases.most_common()])
    RT.write_md(out / "DATA_ANALYSIS_INTELLIGENCE.md", "Data Analysis, Entity Graph and Timeline", [
        ("Risk distribution", json.dumps({"severity": dict(severity), "confirmation": dict(statuses)}, indent=2)),
        ("Entity graph", json.dumps(graph_stats, indent=2)),
        ("Data quality", json.dumps(quality, indent=2)),
        ("Analytical stores", json.dumps(duckdb_result, indent=2)),
        ("Principle", "Correlation increases investigative value but never changes confirmation status by itself."),
    ])
    ctx.phase_state["data_analysis_summary"] = summary
    ctx.log("OK", "data_analysis_intelligence", f"graph {graph_stats.get('entities', 0)} entities; {len(findings)} findings analyzed")
