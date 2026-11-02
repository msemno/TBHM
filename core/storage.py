"""
SQLite-backed storage layer.

Tables:
  runs            — one row per scan run
  findings        — every persisted finding
  hunter_memory   — A1: per-finding decisions ("FP", "valid", "duplicate") for learning
  pattern_library — I1: cumulative bug patterns across all scans
  endpoint_scores — 3.1: precomputed endpoint scores
  phase_state     — track which phases completed (for --resume)
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from core.evidence_redaction import redact_text, redact_value


def _clean_parameter(value):
    if not isinstance(value, str):
        return value
    try:
        parsed = json.loads(value)
    except (ValueError, TypeError):
        return redact_text(value)
    if isinstance(parsed, (dict, list)):
        return json.dumps(redact_value(parsed), ensure_ascii=False, default=str)
    return redact_text(value)


def _clean_parameters(parameters):
    return ({k: _clean_parameter(v) for k, v in parameters.items()}
            if isinstance(parameters, dict) else tuple(_clean_parameter(v) for v in parameters))


class _EvidenceCursor(sqlite3.Cursor):
    def execute(self, sql, parameters=()):
        return super().execute(sql, _clean_parameters(parameters))

    def executemany(self, sql, parameters):
        return super().executemany(sql, (_clean_parameters(row) for row in parameters))


class _EvidenceConnection(sqlite3.Connection):
    """All parameterized SQL routes share the persistence redaction boundary."""
    def execute(self, sql, parameters=()):
        return super().execute(sql, _clean_parameters(parameters))

    def executemany(self, sql, parameters):
        return super().executemany(sql, (_clean_parameters(row) for row in parameters))

    def cursor(self, factory=_EvidenceCursor):
        return super().cursor(factory)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    profile TEXT NOT NULL,
    targets TEXT NOT NULL,
    excludes TEXT,
    args TEXT,
    bug_bounty_program TEXT,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    fingerprint TEXT UNIQUE,
    phase TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    title TEXT NOT NULL,
    target TEXT,
    url TEXT,
    method TEXT,
    parameter TEXT,
    payload TEXT,
    description TEXT,
    evidence TEXT,
    impact TEXT,
    remediation TEXT,
    cwe TEXT,
    cvss TEXT,
    references_json TEXT,
    request_raw TEXT,
    response_raw TEXT,
    discovered_at TEXT NOT NULL,
    verified_at TEXT,
    verification_method TEXT,
    mrs_score INTEGER,
    user_decision TEXT,
    extra_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);

CREATE TABLE IF NOT EXISTS hunter_memory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_fingerprint TEXT NOT NULL,
    finding_pattern TEXT,         -- e.g. "express:idor:numeric_id"
    decision TEXT NOT NULL,       -- 'valid' | 'fp' | 'duplicate' | 'unsure'
    note TEXT,
    decided_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hunter_pattern ON hunter_memory(finding_pattern);

CREATE TABLE IF NOT EXISTS pattern_library (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tech_stack TEXT,              -- e.g. "django"
    vuln_type TEXT,               -- e.g. "idor"
    payload_variant TEXT,
    context_hash TEXT,
    success_count INTEGER DEFAULT 0,
    fp_count INTEGER DEFAULT 0,
    last_seen TEXT
);

-- v2.11: needed so update_pattern() can UPSERT (the old ON CONFLICT(rowid) was a
-- no-op — rowid is unique on every insert, so the counters never accumulated).
CREATE UNIQUE INDEX IF NOT EXISTS idx_pattern_unique
    ON pattern_library(tech_stack, vuln_type, payload_variant);

CREATE TABLE IF NOT EXISTS endpoint_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE,
    score REAL NOT NULL,
    components TEXT,              -- JSON of score breakdown
    last_scanned TEXT,
    scan_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS phase_state (
    phase TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT
);

-- v2.9: every finding the tool dropped as a "false positive" is recorded here
-- so the user can manually review them — some may be real bugs the tool
-- mistakenly suppressed.
CREATE TABLE IF NOT EXISTS dropped_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dropped_at TEXT NOT NULL,
    drop_reason TEXT NOT NULL,        -- e.g. 'third-party host', 'SPA fallback'
    drop_source TEXT NOT NULL,        -- which filter dropped it ('noise_filter', 'fp_engine')
    phase TEXT,
    severity TEXT,
    title TEXT,
    target TEXT,
    url TEXT,
    method TEXT,
    parameter TEXT,
    payload TEXT,
    evidence TEXT,
    full_finding_json TEXT            -- full original finding for re-review
);

-- v3.9.7.3+ lifecycle separation. Findings are no longer the only record of
-- what happened. Negative tests, observations, candidates and verification
-- attempts remain queryable even when no vulnerability is confirmed.
CREATE TABLE IF NOT EXISTS test_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    test_id TEXT NOT NULL,
    test_version TEXT,
    phase TEXT NOT NULL,
    target TEXT,
    operation TEXT,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    scope_decision TEXT,
    policy_id TEXT,
    identity_context_json TEXT,
    request_model_json TEXT,
    assertion_json TEXT,
    result_summary TEXT,
    error TEXT,
    artifact_refs_json TEXT,
    extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_test_execution_phase ON test_executions(phase);
CREATE INDEX IF NOT EXISTS idx_test_execution_status ON test_executions(status);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    test_execution_id INTEGER,
    phase TEXT NOT NULL,
    observation_type TEXT NOT NULL,
    target TEXT,
    summary TEXT,
    evidence_json TEXT,
    artifact_sha256 TEXT,
    observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observation_test ON observations(test_execution_id);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    observation_id INTEGER,
    finding_id INTEGER,
    root_cause_fingerprint TEXT,
    candidate_type TEXT,
    state TEXT NOT NULL,
    hypothesis TEXT,
    required_validation TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_candidate_state ON candidates(state);
CREATE INDEX IF NOT EXISTS idx_candidate_root ON candidates(root_cause_fingerprint);

CREATE TABLE IF NOT EXISTS validation_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    finding_id INTEGER,
    candidate_id INTEGER,
    test_execution_id INTEGER,
    verifier TEXT NOT NULL,
    assertion_json TEXT,
    proof_json TEXT,
    result TEXT NOT NULL,
    assertion_passed INTEGER NOT NULL DEFAULT 0,
    negative_control_passed INTEGER NOT NULL DEFAULT 0,
    repeatability_passed INTEGER NOT NULL DEFAULT 0,
    reasons_json TEXT,
    artifact_refs_json TEXT,
    attempted_at TEXT NOT NULL,
    reviewer TEXT
);
CREATE INDEX IF NOT EXISTS idx_validation_finding ON validation_attempts(finding_id);

CREATE TABLE IF NOT EXISTS program_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    policy_id TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    source_sha256 TEXT,
    loaded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_contexts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    identity_id TEXT NOT NULL,
    role TEXT,
    tenant TEXT,
    session_label TEXT,
    metadata_json TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workflow_models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    workflow_id TEXT NOT NULL,
    name TEXT NOT NULL,
    invariant TEXT NOT NULL,
    model_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS redteam_campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    campaign_id TEXT NOT NULL,
    name TEXT NOT NULL,
    objective TEXT NOT NULL,
    approval_json TEXT,
    status TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_id ON redteam_campaigns(run_id, campaign_id);

CREATE TABLE IF NOT EXISTS redteam_operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_db_id INTEGER,
    operation_id TEXT NOT NULL,
    operation_type TEXT NOT NULL,
    execution_class TEXT NOT NULL,
    risk TEXT NOT NULL,
    target TEXT,
    objective TEXT,
    attack_ids_json TEXT,
    approval_status TEXT NOT NULL,
    status TEXT NOT NULL,
    expected_telemetry_json TEXT,
    stop_conditions_json TEXT,
    cleanup_steps_json TEXT,
    evidence_required_json TEXT,
    result_json TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_operation_id ON redteam_operations(campaign_db_id, operation_id);

CREATE TABLE IF NOT EXISTS detection_outcomes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_db_id INTEGER,
    prevented TEXT,
    logged TEXT,
    detected TEXT,
    alert_routed TEXT,
    analyst_response TEXT,
    response_correct TEXT,
    timing_json TEXT,
    telemetry_gaps_json TEXT,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cleanup_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_db_id INTEGER,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence_json TEXT,
    verified_at TEXT,
    recorded_at TEXT NOT NULL
);
"""


class Storage:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(str(self.db_path), isolation_level=None,
                                    check_same_thread=False, factory=_EvidenceConnection)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute('PRAGMA secure_delete=ON')
        self.conn.executescript(SCHEMA)
        self._run_id = None
        self._migrate_redaction()

    def _migrate_redaction(self):
        """Redact legacy text in place once; keep all tables and record IDs."""
        if self.conn.execute('PRAGMA user_version').fetchone()[0] >= 410:
            return
        import re
        tables = re.findall(r'CREATE TABLE IF NOT EXISTS (\w+)', SCHEMA)
        self.conn.execute('BEGIN IMMEDIATE')
        try:
            for table in tables:
                for row in self.conn.execute(f'SELECT rowid AS _migration_rowid, * FROM "{table}"').fetchall():
                    updates = {key: _clean_parameter(value) for key, value in dict(row).items()
                               if key != '_migration_rowid' and isinstance(value, str) and _clean_parameter(value) != value}
                    if updates:
                        assignments = ','.join(f'"{key}"=?' for key in updates)
                        self.conn.execute(f'UPDATE "{table}" SET {assignments} WHERE rowid=?',
                                          tuple(updates.values()) + (row['_migration_rowid'],))
            self.conn.execute('PRAGMA user_version=410')
            self.conn.execute('COMMIT')
        except BaseException:
            self.conn.execute('ROLLBACK')
            raise

    # ── runs ────────────────────────────────────────────────────────────────
    def save_run(self, run: dict) -> int:
        # Keep the caller's runtime credentials in memory; persist only a copy
        # sanitized by the same boundary used for findings and process evidence.
        from core.evidence_redaction import redact_value
        run = redact_value(run)
        cur = self.conn.execute(
            "INSERT INTO runs (started_at, profile, targets, excludes, args, bug_bounty_program) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (run["started_at"], run["profile"], json.dumps(run["targets"]),
             json.dumps(run.get("excludes", [])), json.dumps(run.get("args", {})),
             run.get("bug_bounty_program", ""))
        )
        self._run_id = cur.lastrowid
        return self._run_id

    def complete_run(self):
        if self._run_id:
            self.conn.execute("UPDATE runs SET completed_at=? WHERE id=?",
                              (_utcnow(), self._run_id))

    # ── findings ────────────────────────────────────────────────────────────
    @staticmethod
    def fingerprint(finding: dict) -> str:
        """Stable hash for dedup. Same target+url+param+payload+title = same fp."""
        keys = ["target", "url", "method", "parameter", "payload", "title", "phase"]
        s = "|".join(str(finding.get(k, "")) for k in keys)
        return hashlib.sha256(s.encode()).hexdigest()[:24]

    def save_finding(self, f: dict) -> int:
        # Persistence boundary: keep proof metadata and artifact hashes, but never
        # write credential values, auth headers, cookies, JWTs, or private keys.
        try:
            from core.evidence_redaction import sanitize_finding
            f = sanitize_finding(f)
        except Exception:
            f = dict(f)
        # v2.4: drop known-noise findings before persisting (chrome-extension, FB, etc)
        try:
            from core import noise_filter
            in_scope = getattr(self, "_in_scope_hosts", None)
            drop, reason = noise_filter.should_drop_finding(f, in_scope_hosts=in_scope)
            if drop:
                self._noise_dropped = getattr(self, "_noise_dropped", 0) + 1
                # v2.9: keep a record so user can re-review what we dropped
                self._record_drop(f, reason, "noise_filter")
                return -1
        except Exception:
            pass

        # v2.5: auto-attach a curl reproducer if the finding doesn't have one.
        # Stored in request_raw if no explicit field — reporter.py will surface it.
        try:
            from core import curl_reproducer
            if not f.get("reproducer_curl") and not (f.get("request_raw") or "").startswith("curl "):
                cmd = curl_reproducer.build(f)
                if cmd:
                    f["reproducer_curl"] = cmd
                    # A suggested curl command is NOT the original HTTP request.
                    # Keep it separate, so evidence audits never count it as a capture.
        except Exception:
            pass

        fp = self.fingerprint(f)
        # Check for duplicate
        existing = self.conn.execute(
            "SELECT id FROM findings WHERE fingerprint=?", (fp,)
        ).fetchone()
        if existing:
            return existing["id"]
        extra_payload = {}
        supplied_extra = f.get("extra_json")
        if isinstance(supplied_extra, dict):
            extra_payload.update(supplied_extra)
        for key in (
            "finding_class", "validation_required", "verified", "verification_method", "verified_at",
            "proof_of_concept", "poc", "confirmed_steps", "steps_to_reproduce",
            "playbook_branch", "status", "tier", "fp_note", "scanner_source", "scanner_rule",
            "artifact_id", "reachability_corroborated", "sanitized",
            "assertion", "proof", "assertion_passed", "negative_control_passed",
            "repeatability_passed", "validation_attempt_id", "verification_state",
            "test_execution_id", "candidate_id", "root_cause_fingerprint",
            "scope_decision", "policy_id", "identity_context", "workflow_id",
            "evidence_capture_status", "reproducer_curl", "http_exchange_refs",
            "attack_ids", "operation_id", "campaign_id", "cleanup_status",
        ):
            if key in f:
                extra_payload[key] = f[key]

        cur = self.conn.execute(
            """INSERT INTO findings
               (run_id, fingerprint, phase, severity, confidence, title, target, url, method,
                parameter, payload, description, evidence, impact, remediation, cwe, cvss,
                references_json, request_raw, response_raw, discovered_at, mrs_score, extra_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (self._run_id, fp, f.get("phase", ""), f["severity"], f["confidence"],
             f["title"], f.get("target", ""), f.get("url", ""),
             f.get("method", ""), f.get("parameter", ""), f.get("payload", ""),
             f.get("description", ""), f.get("evidence", ""), f.get("impact", ""),
             f.get("remediation", ""), f.get("cwe", ""), f.get("cvss", ""),
             json.dumps(f.get("references", [])),
             f.get("request_raw", "") or "", (f.get("response_raw", "") or "")[:200000],
             f["discovered_at"], f.get("mrs_score"),
             json.dumps(extra_payload, default=str))
        )
        return cur.lastrowid

    # v2.9: dropped findings (false-positive archive for manual review) ───────
    def _record_drop(self, finding: dict, reason: str, source: str):
        """Save a redacted dropped finding so user can safely re-review it."""
        try:
            from core.evidence_redaction import sanitize_finding
            finding = sanitize_finding(finding)
        except Exception:
            finding = dict(finding)
        try:
            self.conn.execute(
                "INSERT INTO dropped_findings ("
                "dropped_at, drop_reason, drop_source, phase, severity, title, "
                "target, url, method, parameter, payload, evidence, full_finding_json"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (_utcnow(),
                 reason or "(no reason given)",
                 source,
                 finding.get("phase", ""),
                 (finding.get("severity") or "INFO").upper(),
                 (finding.get("title") or "")[:500],
                 finding.get("target", ""),
                 finding.get("url", ""),
                 finding.get("method", ""),
                 finding.get("parameter", ""),
                 (finding.get("payload") or "")[:1000],
                 (finding.get("evidence") or "")[:2000],
                 json.dumps(finding, default=str)[:50000])
            )
        except Exception:
            # never let archive failure break the main flow
            pass

    def all_dropped(self) -> list[dict]:
        """Return every finding that was dropped during the scan."""
        try:
            rows = self.conn.execute(
                "SELECT * FROM dropped_findings ORDER BY "
                "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
                "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, id"
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def dropped_count(self) -> int:
        try:
            row = self.conn.execute("SELECT COUNT(*) c FROM dropped_findings").fetchone()
            return row["c"] if row else 0
        except Exception:
            return 0

    def all_findings(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM findings ORDER BY "
            "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
            "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, id"
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            # v2.23: rehydrate finding_class / validation_required / verified.
            raw = d.pop("extra_json", None)
            if raw:
                try:
                    extra = json.loads(raw)
                    if isinstance(extra, dict):
                        protected = {'id', 'run_id', 'fingerprint', 'phase', 'severity', 'confidence', 'title', 'target', 'url', 'discovered_at'}
                        d.update({k: v for k, v in extra.items() if k not in protected})
                except Exception:
                    pass
            # JSON flags cannot authenticate a confirmation. Recheck the linked
            # stored validation and its captured artifacts on every read.
            from core.proof_contracts import restore_confirmation
            restore_confirmation(self, d)
            out.append(d)
        return out

    def severity_counts(self) -> dict:
        rows = self.conn.execute(
            "SELECT severity, COUNT(*) c FROM findings GROUP BY severity"
        ).fetchall()
        return {r["severity"]: r["c"] for r in rows}

    def enrich_finding(self, finding_id: int, enrichment: dict,
                       cwe: str = "", cvss: str = "") -> bool:
        """Attach non-authoritative enrichment without changing finding status.

        Local LLM and scanner enrichment is stored in ``extra_json``. Empty CWE
        or CVSS fields may be filled, but existing human/tool values are never
        overwritten. This keeps the original evidence and classification intact.
        """
        try:
            row = self.conn.execute(
                "SELECT extra_json, cwe, cvss FROM findings WHERE id=?", (finding_id,)
            ).fetchone()
            if not row:
                return False
            extra = {}
            if row["extra_json"]:
                try:
                    parsed = json.loads(row["extra_json"])
                    if isinstance(parsed, dict):
                        extra.update(parsed)
                except Exception:
                    pass
            extra.setdefault("enrichment", {})
            if isinstance(extra["enrichment"], dict):
                extra["enrichment"].update(enrichment or {})
            else:
                extra["enrichment"] = enrichment or {}
            new_cwe = row["cwe"] or cwe or ""
            new_cvss = row["cvss"] or cvss or ""
            self.conn.execute(
                "UPDATE findings SET extra_json=?, cwe=?, cvss=? WHERE id=?",
                (json.dumps(extra, default=str), new_cwe, new_cvss, finding_id),
            )
            self.conn.commit()
            return True
        except Exception:
            return False

    # ── A1: hunter decision memory ─────────────────────────────────────────
    def record_decision(self, finding_fp: str, decision: str, pattern: str = "", note: str = ""):
        self.conn.execute(
            "INSERT INTO hunter_memory (finding_fingerprint, finding_pattern, decision, note, decided_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (finding_fp, pattern, decision, note, _utcnow())
        )

    def predict_decision(self, pattern: str) -> tuple[str, float] | None:
        """A1: predict user decision based on past similar findings."""
        rows = self.conn.execute(
            "SELECT decision, COUNT(*) c FROM hunter_memory WHERE finding_pattern=? "
            "GROUP BY decision ORDER BY c DESC", (pattern,)
        ).fetchall()
        if not rows:
            return None
        total = sum(r["c"] for r in rows)
        top = rows[0]
        return (top["decision"], top["c"] / total)

    # ── I1: pattern library ────────────────────────────────────────────────
    def update_pattern(self, tech: str, vuln: str, payload: str, success: bool):
        # Upsert keyed on (tech_stack, vuln_type, payload_variant) — see unique index.
        self.conn.execute(
            "INSERT INTO pattern_library (tech_stack, vuln_type, payload_variant, "
            "success_count, fp_count, last_seen) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(tech_stack, vuln_type, payload_variant) DO UPDATE SET "
            "success_count=success_count+?, fp_count=fp_count+?, last_seen=?",
            (tech, vuln, payload, 1 if success else 0, 0 if success else 1,
             _utcnow(),
             1 if success else 0, 0 if success else 1, _utcnow())
        )

    def best_payloads(self, tech: str, vuln: str, limit: int = 5) -> list[str]:
        rows = self.conn.execute(
            "SELECT payload_variant, success_count, fp_count FROM pattern_library "
            "WHERE tech_stack=? AND vuln_type=? "
            "ORDER BY (success_count*1.0 / (success_count+fp_count+1)) DESC LIMIT ?",
            (tech, vuln, limit)
        ).fetchall()
        return [r["payload_variant"] for r in rows]

    # ── endpoint scoring ───────────────────────────────────────────────────
    def save_endpoint_score(self, url: str, score: float, components: dict):
        self.conn.execute(
            "INSERT INTO endpoint_scores (url, score, components, last_scanned) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(url) DO UPDATE SET "
            "score=excluded.score, components=excluded.components",
            (url, score, json.dumps(components), _utcnow())
        )

    def top_endpoints(self, n: int = 30) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM endpoint_scores ORDER BY score DESC LIMIT ?", (n,)
        ).fetchall()
        return [dict(r) for r in rows]

    def boost_endpoint_score(self, url: str, delta: float):
        """Increase an endpoint's score (e.g. smart_crawl finds it has a form)."""
        try:
            self.conn.execute(
                "UPDATE endpoint_scores SET score = score + ? WHERE url = ?",
                (delta, url)
            )
            # Insert if not present
            self.conn.execute(
                "INSERT OR IGNORE INTO endpoint_scores(url, score, components, last_scanned) "
                "VALUES (?, ?, '{}', ?)",
                (url, max(0, delta), _utcnow())
            )
        except Exception:
            pass

    # ── phase state ────────────────────────────────────────────────────────
    def mark_phase_done(self, phase: str):
        self.conn.execute(
            "INSERT INTO phase_state (phase, status, started_at, completed_at) "
            "VALUES (?, 'done', ?, ?) ON CONFLICT(phase) DO UPDATE SET "
            "status='done', completed_at=excluded.completed_at",
            (phase, _utcnow(), _utcnow())
        )

    def is_phase_done(self, phase: str) -> bool:
        r = self.conn.execute(
            "SELECT status FROM phase_state WHERE phase=?", (phase,)
        ).fetchone()
        # v3.9.4: only a genuinely completed phase is skippable on --resume.
        return bool(r and r["status"] in ("done", "succeeded"))

    def set_phase_state(self, phase: str, status: str):
        """v3.9.4: record a distinct phase state (e.g. 'failed', 'interrupted').

        Fixes the resume bug where a crashed phase was marked 'done' and then
        silently skipped by a later --resume. Only 'done'/'succeeded' are treated
        as skippable by is_phase_done(); 'failed' and 'interrupted' are retried.
        """
        self.conn.execute(
            "INSERT INTO phase_state (phase, status, started_at, completed_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(phase) DO UPDATE SET "
            "status=excluded.status, completed_at=excluded.completed_at",
            (phase, status, _utcnow(), _utcnow())
        )

    # ── Typed test / evidence lifecycle ───────────────────────────────────
    def start_test_execution(self, *, test_id: str, phase: str, target: str = "",
                             operation: str = "", test_version: str = "1",
                             scope_decision: str = "", policy_id: str = "",
                             identity_context: dict | None = None,
                             request_model: dict | None = None,
                             assertion: dict | None = None, extra: dict | None = None) -> int:
        now = _utcnow()
        cur = self.conn.execute(
            """INSERT INTO test_executions
               (run_id,test_id,test_version,phase,target,operation,status,started_at,
                scope_decision,policy_id,identity_context_json,request_model_json,
                assertion_json,artifact_refs_json,extra_json)
               VALUES (?,?,?,?,?,?,'running',?,?,?,?,?,?,?,?)""",
            (self._run_id, test_id, test_version, phase, target, operation, now,
             scope_decision, policy_id, json.dumps(identity_context or {}, default=str),
             json.dumps(request_model or {}, default=str), json.dumps(assertion or {}, default=str),
             json.dumps([], default=str), json.dumps(extra or {}, default=str)))
        return int(cur.lastrowid)

    def complete_test_execution(self, test_execution_id: int, *, status: str,
                                result_summary: str = "", error: str = "",
                                artifact_refs: list | None = None, extra: dict | None = None) -> None:
        allowed = {"passed", "failed-security-control", "inconclusive", "blocked",
                   "not-authorized", "not-applicable", "tool-error",
                   "manual-review-required", "succeeded", "failed"}
        normalized = status if status in allowed else "inconclusive"
        self.conn.execute(
            """UPDATE test_executions SET status=?,completed_at=?,result_summary=?,
               error=?,artifact_refs_json=?,extra_json=? WHERE id=?""",
            (normalized, _utcnow(), result_summary, error,
             json.dumps(artifact_refs or [], default=str), json.dumps(extra or {}, default=str),
             test_execution_id))

    def save_observation(self, *, phase: str, observation_type: str, target: str = "",
                         summary: str = "", evidence: dict | None = None,
                         test_execution_id: int | None = None, artifact_sha256: str = "") -> int:
        cur = self.conn.execute(
            """INSERT INTO observations
               (run_id,test_execution_id,phase,observation_type,target,summary,evidence_json,
                artifact_sha256,observed_at) VALUES (?,?,?,?,?,?,?,?,?)""",
            (self._run_id, test_execution_id, phase, observation_type, target, summary,
             json.dumps(evidence or {}, default=str), artifact_sha256, _utcnow()))
        return int(cur.lastrowid)

    @staticmethod
    def root_cause_fingerprint(finding: dict) -> str:
        keys = ["target", "cwe", "parameter", "candidate_type", "root_cause", "affected_component"]
        value = "|".join(str(finding.get(k, "")).strip().lower() for k in keys)
        if not value.strip("|"):
            value = "|".join(str(finding.get(k, "")).strip().lower() for k in ("target", "title"))
        return hashlib.sha256(value.encode()).hexdigest()[:24]

    def save_candidate(self, *, finding_id: int | None = None, observation_id: int | None = None,
                       finding: dict | None = None, state: str = "candidate",
                       hypothesis: str = "", required_validation: str = "",
                       extra: dict | None = None) -> int:
        finding = finding or {}
        root = str(finding.get("root_cause_fingerprint") or self.root_cause_fingerprint(finding))
        now = _utcnow()
        cur = self.conn.execute(
            """INSERT INTO candidates
               (run_id,observation_id,finding_id,root_cause_fingerprint,candidate_type,state,
                hypothesis,required_validation,created_at,updated_at,extra_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (self._run_id, observation_id, finding_id, root,
             str(finding.get("candidate_type") or finding.get("cwe") or finding.get("phase") or "unknown"),
             state, hypothesis or str(finding.get("description") or finding.get("title") or ""),
             required_validation or str(finding.get("validation_required") or ""),
             now, now, json.dumps(extra or {}, default=str)))
        return int(cur.lastrowid)

    def record_validation_attempt(self, *, verifier: str, result: dict,
                                  assertion: dict | None = None, proof: dict | None = None,
                                  finding_id: int | None = None, candidate_id: int | None = None,
                                  test_execution_id: int | None = None,
                                  artifact_refs: list | None = None, reviewer: str = "") -> int:
        cur = self.conn.execute(
            """INSERT INTO validation_attempts
               (run_id,finding_id,candidate_id,test_execution_id,verifier,assertion_json,proof_json,
                result,assertion_passed,negative_control_passed,repeatability_passed,reasons_json,
                artifact_refs_json,attempted_at,reviewer) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (self._run_id, finding_id, candidate_id, test_execution_id, verifier,
             json.dumps(assertion or {}, default=str), json.dumps(proof or {}, default=str),
             str(result.get("result") or "inconclusive"),
             1 if result.get("assertion_passed") else 0,
             1 if result.get("negative_control_passed") else 0,
             1 if result.get("repeatability_passed") else 0,
             json.dumps(result.get("reasons") or [], default=str),
             json.dumps(artifact_refs or [], default=str), _utcnow(), reviewer))
        return int(cur.lastrowid)

    def update_finding_verification(self, finding_id: int, fields: dict) -> None:
        row = self.conn.execute("SELECT extra_json FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            return
        extra = {}
        try:
            extra = json.loads(row["extra_json"] or "{}")
            if not isinstance(extra, dict): extra = {}
        except Exception:
            extra = {}
        extra.update(fields or {})
        current = self.conn.execute(
            "SELECT verified_at,verification_method FROM findings WHERE id=?", (finding_id,)).fetchone()
        verified_at = fields.get("verified_at") if "verified_at" in fields else (current["verified_at"] if current else None)
        verification_method = fields.get("verification_method") if "verification_method" in fields else (current["verification_method"] if current else "")
        self.conn.execute(
            """UPDATE findings SET verified_at=?,verification_method=?,extra_json=? WHERE id=?""",
            (verified_at, verification_method, json.dumps(extra, default=str), finding_id))
        if any(key in fields for key in ("verified", "verification_state", "finding_class")):
            candidate_state = "confirmed" if fields.get("verified") is True else str(fields.get("finding_class") or "supported")
            self.conn.execute("UPDATE candidates SET state=?,updated_at=? WHERE finding_id=?",
                              (candidate_state, _utcnow(), finding_id))

    def all_test_executions(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM test_executions ORDER BY id").fetchall()
        out = []
        for row in rows:
            item = dict(row)
            for key in ("identity_context_json", "request_model_json", "assertion_json",
                        "artifact_refs_json", "extra_json"):
                try: item[key[:-5] if key.endswith("_json") else key] = json.loads(item.get(key) or "{}")
                except Exception: pass
            out.append(item)
        return out

    def save_program_policy(self, policy: dict, source_sha256: str = "") -> int:
        cur = self.conn.execute(
            "INSERT INTO program_policies(run_id,policy_id,policy_json,source_sha256,loaded_at) VALUES (?,?,?,?,?)",
            (self._run_id, str(policy.get("policy_id") or "unknown"), json.dumps(policy, default=str),
             source_sha256, _utcnow()))
        return int(cur.lastrowid)

    def save_identity_context(self, row: dict) -> int:
        # Persist only a provider/reference label, never session material itself.
        metadata = dict(row.get("metadata") or {})
        if row.get("session_provider_ref"):
            metadata["session_provider_ref"] = str(row.get("session_provider_ref"))
        cur = self.conn.execute(
            "INSERT INTO identity_contexts(run_id,identity_id,role,tenant,session_label,metadata_json,created_at) VALUES (?,?,?,?,?,?,?)",
            (self._run_id, str(row.get("identity_id") or row.get("id") or ""),
             str(row.get("role") or ""), str(row.get("tenant") or ""),
             str(row.get("session_label") or ""), json.dumps(metadata, default=str),
             _utcnow()))
        return int(cur.lastrowid)

    def save_workflow_model(self, row: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO workflow_models(run_id,workflow_id,name,invariant,model_json,created_at) VALUES (?,?,?,?,?,?)",
            (self._run_id, str(row.get("workflow_id") or row.get("id") or ""),
             str(row.get("name") or "workflow"), str(row.get("invariant") or ""),
             json.dumps(row, default=str), _utcnow()))
        return int(cur.lastrowid)

    def save_campaign(self, campaign: dict, approval: dict | None = None) -> int:
        cur = self.conn.execute(
            """INSERT OR REPLACE INTO redteam_campaigns
               (run_id,campaign_id,name,objective,approval_json,status,plan_json,created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (self._run_id, str(campaign.get("campaign_id")), str(campaign.get("name")),
             str(campaign.get("objective")), json.dumps(approval or {}, default=str),
             str(campaign.get("status") or "planned"), json.dumps(campaign, default=str),
             _utcnow()))
        return int(cur.lastrowid)

    def save_operation(self, campaign_db_id: int, operation: dict, approval_status: str) -> int:
        cur = self.conn.execute(
            """INSERT OR REPLACE INTO redteam_operations
               (campaign_db_id,operation_id,operation_type,execution_class,risk,target,objective,
                attack_ids_json,approval_status,status,expected_telemetry_json,stop_conditions_json,
                cleanup_steps_json,evidence_required_json,result_json,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (campaign_db_id, operation.get("operation_id"), operation.get("operation_type"),
             operation.get("execution_class"), operation.get("risk"), operation.get("target"),
             operation.get("objective"), json.dumps(operation.get("attack_ids") or []), approval_status,
             operation.get("status") or "planned", json.dumps(operation.get("expected_telemetry") or []),
             json.dumps(operation.get("stop_conditions") or []), json.dumps(operation.get("cleanup_steps") or []),
             json.dumps(operation.get("evidence_required") or []), json.dumps({
                 "tactic": operation.get("tactic"),
                 "authorization_reference": operation.get("authorization_reference"),
                 "scope_reference": operation.get("scope_reference"),
                 "side_effect_budget": operation.get("side_effect_budget"),
             }, default=str),
             _utcnow()))
        return int(cur.lastrowid)

    def update_operation_result(self, operation_db_id: int, result: dict, *, status: str) -> None:
        self.conn.execute("UPDATE redteam_operations SET status=?,result_json=?,completed_at=? WHERE id=?",
                          (status, json.dumps(result, default=str), _utcnow(), operation_db_id))

    def save_detection_outcome(self, operation_db_id: int, row: dict) -> int:
        cur = self.conn.execute(
            """INSERT INTO detection_outcomes
               (operation_db_id,prevented,logged,detected,alert_routed,analyst_response,response_correct,
                timing_json,telemetry_gaps_json,recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (operation_db_id, str(row.get("prevented") or "unknown"), str(row.get("logged") or "unknown"),
             str(row.get("detected") or "unknown"), str(row.get("alert_routed") or "unknown"),
             str(row.get("analyst_response") or "unknown"), str(row.get("response_correct") or "unknown"),
             json.dumps(row.get("timing") or {}, default=str), json.dumps(row.get("telemetry_gaps") or [], default=str),
             _utcnow()))
        return int(cur.lastrowid)

    def save_cleanup_action(self, operation_db_id: int, row: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO cleanup_actions(operation_db_id,action,status,evidence_json,verified_at,recorded_at) VALUES (?,?,?,?,?,?)",
            (operation_db_id, str(row.get("action") or "cleanup"), str(row.get("status") or "unknown"),
             json.dumps(row.get("evidence") or {}, default=str), row.get("verified_at"),
             _utcnow()))
        return int(cur.lastrowid)

    def close(self):
        self.conn.close()
