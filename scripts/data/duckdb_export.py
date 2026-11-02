#!/usr/bin/env python3
"""Isolated DuckDB exporter used by the data-analysis phase."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--findings", required=True)
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--result", required=True)
    ns = parser.parse_args()
    import duckdb

    out = Path(ns.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    finding_rows = json.loads(Path(ns.findings).read_text(encoding="utf-8"))
    input_rows = json.loads(Path(ns.inputs).read_text(encoding="utf-8"))
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
        payload = {"available": True, "database": str(db_path),
                   "parquet": ["findings.parquet", "input_files.parquet"],
                   "execution_environment": "isolated"}
    finally:
        conn.close()
    Path(ns.result).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
