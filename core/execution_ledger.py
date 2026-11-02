"""Actual phase/tool outcomes, separate from finding counts and test coverage."""
from __future__ import annotations
import json
import hashlib
import uuid
import threading
import time
import shutil
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from core.evidence_redaction import redact_value, safe_argv

_TOOL_IDENTITIES = {}


def tool_identity(tool):
    resolved = shutil.which(str(tool))
    if resolved is None:
        return {'path':None, 'sha256':None, 'version':'UNVERIFIED'}
    path = Path(resolved)
    try:
        st = path.stat()
        key = (str(path.resolve()), st.st_size, st.st_mtime_ns)
        if key not in _TOOL_IDENTITIES:
            h = hashlib.sha256()
            with path.open('rb') as handle:
                for block in iter(lambda:handle.read(1024*1024), b''):
                    h.update(block)
            _TOOL_IDENTITIES[key] = {'path':str(path.resolve()), 'sha256':h.hexdigest(), 'version':'UNVERIFIED'}
        return _TOOL_IDENTITIES[key]
    except OSError:
        return {'path':str(path), 'sha256':None, 'version':'UNVERIFIED'}


class ExecutionLedger:
    def __init__(self, output, *, recover=False):
        self.path = Path(output) / 'execution_ledger.json'
        self.journal = Path(output) / 'execution_ledger.events.jsonl'
        self.lock = threading.Lock()
        self.rows = []
        self.current_phase = 'preflight'
        self.plan = []
        self.context_fingerprint = ""
        self._last_flush = 0.0
        self._flushed_count = 0
        if recover:
            if self.path.is_file():
                saved = json.loads(self.path.read_text())
                self.plan = saved.get('planned_phases', [])
                self.context_fingerprint = saved.get('context_fingerprint', '')
                self.rows = saved.get('events', [])
            if self.journal.is_file():
                # The journal is authoritative after the most recent snapshot.
                rows = []
                with self.journal.open() as handle:
                    for line in handle:
                        try:
                            row = json.loads(line)
                        except ValueError:
                            if not line.endswith('\n'):
                                break  # interrupted final append
                            raise ValueError('corrupt execution journal record')
                        if not isinstance(row, dict):
                            raise ValueError('invalid execution journal record')
                        rows.append(row)
                self.rows = rows
        else:
            self.journal.write_text('')
            self.journal.chmod(0o600)

    def record(self, **row):
        with self.lock:
            event = redact_value({'phase': self.current_phase, **row,
                'sequence': len(self.rows)+1,
                'timestamp': datetime.now(timezone.utc).isoformat()})
            with self.journal.open('a') as handle:
                handle.write(json.dumps(event, ensure_ascii=False)+'\n')
            self.rows.append(event)
            # Per-request durability is provided by the append journal. Avoid
            # rewriting megabytes after every denied request or capability check.
            if (event.get('kind') not in {'http', 'capability', 'service_http'}
                    or len(self.rows)-self._flushed_count >= 256
                    or time.monotonic()-self._last_flush >= 2):
                self.flush()

    def flush(self):
        temp = self.path.with_suffix('.tmp')
        temp.write_text(json.dumps({'schema': 'tbhm.execution/1', 'planned_phases': self.plan, 'context_fingerprint': self.context_fingerprint,
                                   'events': self.rows,
                                   'coverage_note': 'Phase completion is not vulnerability-test coverage.'}, indent=2) + '\n')
        temp.replace(self.path)
        self._last_flush = time.monotonic()
        self._flushed_count = len(self.rows)

    def issues(self, phase):
        return [r for r in self.rows if r.get('phase') == phase
                and (r.get('kind') != 'service_http' or r.get('required') is True)
                and r.get('status') in {'tool-error', 'parser-error', 'network-error',
                    'missing-required-tool', 'blocked', 'partial', 'timed_out', 'cancelled'}]


def tracked_tool(function):
    @wraps(function)
    def call(self, cmd, *args, **kwargs):
        ledger = getattr(self, 'execution_ledger', None)
        start = time.monotonic()
        try:
            result = function(self, cmd, *args, **kwargs)
            rc, out, err = result
            if '[REDACTED_OVERSIZE_LINE]' in out or '[REDACTED_OVERSIZE_LINE]' in err:
                rc, err = (rc or 65), err + '\nScanner output exceeded the bounded evidence record size; results are incomplete.'
                result = rc, out, err
            if ledger:
                ledger.record(kind='tool', argv=safe_argv(cmd), returncode=rc,
                              status='executed' if rc == 0 else 'tool-error',
                              outcome='EXECUTED' if rc == 0 else ('TIMED_OUT' if rc == 124 else ('CANCELLED' if rc == 130 else 'TOOL_ERROR')),
                              executable=tool_identity(cmd[0]),
                              seconds=round(time.monotonic() - start, 3))
            return result
        except Exception as exc:
            if ledger:
                ledger.record(kind='tool', argv=safe_argv(cmd), status='tool-error', error=str(exc))
            raise
    return call


def sanitize_output(output):
    """Sanitize ordinary text artifacts written directly by scanner subprocesses.

    Binary inputs and captured proof records are not rewritten. Private scanner
    work directories are excluded from delivery separately.
    """
    from core.evidence_redaction import redact_text
    extensions = {'.json', '.jsonl', '.log', '.txt', '.md', '.html', '.xml', '.csv', '.yaml', '.yml', '.js', '.map', '.sarif', '.har', '.toml', '.ini', '.cfg', '.svg'}
    root = Path(output)
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root)
        if (not path.is_file() or path.is_symlink() or rel.parts[0] == 'delivery'
                or 'captures' in rel.parts or path.suffix.lower() not in extensions):
            continue
        data = path.read_bytes()
        try:
            original = data.decode('utf-8')
        except UnicodeDecodeError:
            continue
        try:
            value = json.loads(original)
        except (ValueError, TypeError):
            clean = redact_text(original)
        else:
            clean = json.dumps(redact_value(value), indent=2, ensure_ascii=False)
        if clean != original:
            path.write_text(clean, encoding='utf-8')


def input_fingerprint(args, profile, targets):
    """Conservative resume identity, including actual local input contents."""
    options = {k: v for k, v in vars(args).items() if k not in
               {'resume', 'output', 'silent', 'verbose', 'background', 'dry_run'}}
    # New disabled options must not invalidate a legacy saved run by their mere presence.
    for key, disabled in (('strict_replay_plan', None), ('approve_strict_replay', False),
                          ('ai_learning', None), ('approve_ai_learning', False), ('ai_learning_output', None), ('ai_scenario_context', None),
                          ('ai_knowledge_db', None), ('no_ai_knowledge', False)):
        if options.get(key) is disabled:
            options.pop(key, None)
    files = {}
    total = 0
    for key, value in options.items():
        if not isinstance(value, str) or not value or key.endswith(('token', 'password', 'secret')):
            continue
        if not (key.endswith(('_file', '_dir', '_path', '_input', '_results', '_plan', '_manifest'))
                or key in {'apk', 'ipa', 'session_har', 'openapi_baseline', 'api_observations'}):
            continue
        path = Path(value)
        if not path.exists():
            continue
        paths = [path] if path.is_file() else sorted(path.rglob('*'))
        for item in paths:
            if not item.is_file() or any(p in {'.git', '.venv', '__pycache__'} for p in item.parts):
                continue
            if item.is_symlink() or len(files) >= 50000 or total + item.stat().st_size > 1024**3:
                return 'unbounded-input-' + uuid.uuid4().hex
            h = hashlib.sha256()
            with item.open('rb') as handle:
                for block in iter(lambda: handle.read(1024*1024), b''): h.update(block)
            total += item.stat().st_size
            files[str(item.resolve())] = h.hexdigest()
    from core.version import source_fingerprint
    return hashlib.sha256(json.dumps({'source_build':source_fingerprint(), 'args': options, 'profile': profile, 'targets': targets,
                                      'files': files}, sort_keys=True, default=str).encode()).hexdigest()
