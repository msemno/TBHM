"""
Knowledge Engine — the platform's long-term memory.

Stored in a separate SQLite DB at ~/.tbhm/knowledge.db (NOT per-scan).
This lets the tool learn from past scans:

  - Which technologies (e.g. "Apache Tomcat 9.x") were vulnerable to which checks
  - Which subdomain patterns existed on which orgs (e.g. "api-staging.X.com")
  - Which payloads succeeded against which contexts
  - Which endpoints proved vulnerable historically (for re-check workflows)

This is the difference between "scanner" and "platform":
  Scanner = stateless: every scan starts from zero.
  Platform = stateful: every scan benefits from the last.
"""
from __future__ import annotations
import json
import os
import sqlite3
import time
from pathlib import Path


def _kb_path() -> Path:
    home = Path(os.environ.get("TBHM_HOME", Path.home() / ".tbhm"))
    home.mkdir(parents=True, exist_ok=True)
    return home / "knowledge.db"


SCHEMA = """
CREATE TABLE IF NOT EXISTS tech_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    technology TEXT NOT NULL,           -- "Apache Tomcat", "WordPress 5.x"
    finding_type TEXT NOT NULL,         -- "SQLi", "XSS", "Path Traversal"
    confidence TEXT NOT NULL,
    target_host TEXT NOT NULL,
    payload TEXT,
    url TEXT,
    seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tech ON tech_findings(technology);
CREATE INDEX IF NOT EXISTS idx_type ON tech_findings(finding_type);

CREATE TABLE IF NOT EXISTS subdomain_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    root_domain TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    source TEXT,                        -- which recon tool found it
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    UNIQUE(root_domain, subdomain)
);
CREATE INDEX IF NOT EXISTS idx_root ON subdomain_history(root_domain);

CREATE TABLE IF NOT EXISTS endpoint_outcomes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_normalized TEXT NOT NULL,       -- /api/users/{id}
    method TEXT NOT NULL,
    test_class TEXT NOT NULL,           -- "SQLi", "IDOR", etc.
    result TEXT NOT NULL,               -- "vulnerable" or "clean"
    target_host TEXT NOT NULL,
    seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_url_norm ON endpoint_outcomes(url_normalized);

CREATE TABLE IF NOT EXISTS payload_success (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload TEXT NOT NULL,
    context TEXT NOT NULL,              -- "query_param", "json_body", etc.
    finding_type TEXT NOT NULL,
    target_tech TEXT,                   -- detected tech (if any)
    seen_at INTEGER NOT NULL
);
"""


class Knowledge:
    def __init__(self):
        self.db_path = _kb_path()
        self.conn = sqlite3.connect(str(self.db_path), isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    # ── Recording (called during scan) ─────────────────────────────────────
    def record_tech_finding(self, tech: str, finding_type: str, confidence: str,
                            target_host: str, payload: str = "", url: str = ""):
        self.conn.execute(
            "INSERT INTO tech_findings(technology, finding_type, confidence, "
            "target_host, payload, url, seen_at) VALUES (?,?,?,?,?,?,?)",
            (tech, finding_type, confidence, target_host, payload, url, int(time.time()))
        )

    def record_subdomain(self, root: str, sub: str, source: str = ""):
        now = int(time.time())
        self.conn.execute(
            "INSERT INTO subdomain_history(root_domain, subdomain, source, first_seen, last_seen) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(root_domain, subdomain) DO UPDATE SET last_seen=excluded.last_seen",
            (root, sub, source, now, now)
        )

    def record_endpoint_outcome(self, url_norm: str, method: str, test_class: str,
                                 result: str, target_host: str):
        self.conn.execute(
            "INSERT INTO endpoint_outcomes(url_normalized, method, test_class, "
            "result, target_host, seen_at) VALUES (?,?,?,?,?,?)",
            (url_norm, method, test_class, result, target_host, int(time.time()))
        )

    def record_payload_success(self, payload: str, context: str, finding_type: str,
                                target_tech: str = ""):
        self.conn.execute(
            "INSERT INTO payload_success(payload, context, finding_type, target_tech, seen_at) "
            "VALUES (?,?,?,?,?)",
            (payload, context, finding_type, target_tech, int(time.time()))
        )

    # ── Querying (called by phases for smart targeting) ────────────────────
    def known_subdomains(self, root_domain: str) -> list[str]:
        """Return subdomains seen on this root in past scans."""
        rows = self.conn.execute(
            "SELECT subdomain FROM subdomain_history WHERE root_domain=? "
            "ORDER BY last_seen DESC LIMIT 5000",
            (root_domain,)
        ).fetchall()
        return [r["subdomain"] for r in rows]

    def successful_payloads_for(self, context: str, finding_type: str,
                                limit: int = 20) -> list[str]:
        """Get historically successful payloads — try these FIRST in future scans."""
        rows = self.conn.execute(
            "SELECT payload, COUNT(*) as cnt FROM payload_success "
            "WHERE context=? AND finding_type=? "
            "GROUP BY payload ORDER BY cnt DESC, MAX(seen_at) DESC LIMIT ?",
            (context, finding_type, limit)
        ).fetchall()
        return [r["payload"] for r in rows]

    def previously_vulnerable_endpoints(self, target_host: str) -> list[dict]:
        """Endpoints found vulnerable on this host before — re-test priority."""
        rows = self.conn.execute(
            "SELECT url_normalized, method, test_class, MAX(seen_at) as last "
            "FROM endpoint_outcomes WHERE target_host=? AND result='vulnerable' "
            "GROUP BY url_normalized, method, test_class ORDER BY last DESC LIMIT 500",
            (target_host,)
        ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        """Total counts (for the dashboard / status display)."""
        c = self.conn.execute("SELECT COUNT(*) FROM tech_findings").fetchone()[0]
        s = self.conn.execute("SELECT COUNT(DISTINCT subdomain) FROM subdomain_history").fetchone()[0]
        e = self.conn.execute("SELECT COUNT(*) FROM endpoint_outcomes WHERE result='vulnerable'").fetchone()[0]
        p = self.conn.execute("SELECT COUNT(*) FROM payload_success").fetchone()[0]
        return {
            "total_findings_logged": c,
            "unique_subdomains_seen": s,
            "vulnerable_endpoints_logged": e,
            "successful_payloads": p,
            "db_path": str(self.db_path),
            "db_size_bytes": self.db_path.stat().st_size if self.db_path.exists() else 0,
        }

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


# Singleton accessor (lazy)
_INSTANCE = None
def get() -> Knowledge:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = Knowledge()
    return _INSTANCE
