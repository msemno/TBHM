"""Content-addressed artifact store and campaign index for reverse projects."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import time
from pathlib import Path
from typing import Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS artifacts (
 sha256 TEXT PRIMARY KEY, size INTEGER NOT NULL, first_seen REAL NOT NULL,
 stored_path TEXT, media_type TEXT, metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS observations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, campaign TEXT NOT NULL, project TEXT NOT NULL,
 product TEXT NOT NULL, version TEXT NOT NULL, source_path TEXT NOT NULL,
 sha256 TEXT NOT NULL, observed_at REAL NOT NULL,
 UNIQUE(campaign, project, product, version, source_path, sha256)
);
CREATE INDEX IF NOT EXISTS idx_observations_sha ON observations(sha256);
CREATE INDEX IF NOT EXISTS idx_observations_campaign ON observations(campaign, project, product, version);
"""


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


class ArtifactStore:
    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.objects = self.root / "objects" / "sha256"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "campaign.sqlite3"
        self.db = sqlite3.connect(self.db_path)
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    def object_path(self, digest: str) -> Path:
        return self.objects / digest[:2] / digest[2:4] / digest

    def add(self, path: str | Path, *, campaign: str = "default", project: str = "default",
            product: str = "unknown", version: str = "unknown", copy: bool = False,
            metadata: dict | None = None) -> dict:
        source = Path(path).expanduser().resolve(strict=True)
        if not source.is_file() or source.is_symlink():
            raise ValueError("artifact must be a regular non-symlink file")
        digest = sha256_file(source)
        size = source.stat().st_size
        dest = self.object_path(digest)
        stored_path = ""
        if copy:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists():
                tmp = dest.with_suffix(".tmp")
                shutil.copyfile(source, tmp)
                os.chmod(tmp, 0o600)
                tmp.replace(dest)
            stored_path = str(dest)
        now = time.time()
        self.db.execute(
            "INSERT OR IGNORE INTO artifacts(sha256,size,first_seen,stored_path,media_type,metadata_json) VALUES(?,?,?,?,?,?)",
            (digest, size, now, stored_path, str((metadata or {}).get("media_type", "")), json.dumps(metadata or {}, sort_keys=True)),
        )
        if stored_path:
            self.db.execute("UPDATE artifacts SET stored_path=? WHERE sha256=? AND (stored_path='' OR stored_path IS NULL)", (stored_path, digest))
        self.db.execute(
            "INSERT OR IGNORE INTO observations(campaign,project,product,version,source_path,sha256,observed_at) VALUES(?,?,?,?,?,?,?)",
            (campaign, project, product, version, str(source), digest, now),
        )
        self.db.commit()
        count = self.db.execute("SELECT COUNT(*) FROM observations WHERE sha256=?", (digest,)).fetchone()[0]
        return {"sha256": digest, "size": size, "source": str(source), "stored_path": stored_path,
                "deduplicated": count > 1, "observation_count": count}

    def stats(self) -> dict:
        artifacts = self.db.execute("SELECT COUNT(*), COALESCE(SUM(size),0) FROM artifacts").fetchone()
        observations = self.db.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
        reused = self.db.execute("SELECT COUNT(*) FROM (SELECT sha256 FROM observations GROUP BY sha256 HAVING COUNT(*)>1)").fetchone()[0]
        return {"unique_artifacts": artifacts[0], "unique_bytes": artifacts[1], "observations": observations,
                "reused_artifacts": reused, "database": str(self.db_path), "root": str(self.root)}

    def find_reuse(self, digest: str) -> list[dict]:
        rows = self.db.execute(
            "SELECT campaign,project,product,version,source_path,observed_at "
            "FROM observations WHERE sha256=? ORDER BY observed_at",
            (digest,),
        ).fetchall()
        return [
            {
                "campaign": r[0],
                "project": r[1],
                "product": r[2],
                "version": r[3],
                "source_path": r[4],
                "observed_at": r[5],
            }
            for r in rows
        ]
