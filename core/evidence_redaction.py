"""Conservative persistence-boundary redaction.

This sanitizer intentionally does *not* redact generic hexadecimal hashes, so
artifact SHA-256 evidence remains usable. It targets credential-bearing headers,
assignments, common provider tokens, JWTs, private keys, and connection strings.
"""
from __future__ import annotations

import copy
import re
import threading
from typing import Any
from urllib.parse import urlsplit, urlunsplit, unquote_plus

_PATTERNS = [
    (re.compile(r"(?im)(authorization\s*:\s*)[^\r\n]+"), r"\1[REDACTED]", ("authorization",)),
    (re.compile(r"(?im)(cookie\s*:\s*)[^\r\n]+"), r"\1[REDACTED]", ("cookie",)),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?[^\s,'\";]{4,}"), r"\1=[REDACTED]", ("password", "passwd", "pwd", "secret", "key", "token")),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]", ("akia",)),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]", ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]", ("github_pat_",)),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "[REDACTED_GITLAB_TOKEN]", ("glpat-",)),
    (re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), "[REDACTED_SENDGRID_KEY]", ("sg.",)),
    (re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b"), "[REDACTED_PROVIDER_KEY]", ("_live_", "_test_")),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED_API_KEY]", ("sk-",)),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED_SLACK_TOKEN]", ("xox",)),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "[REDACTED_GOOGLE_API_KEY]", ("aiza",)),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED_JWT]", ("eyj",)),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", re.S), "[REDACTED_PRIVATE_KEY]", ("-----begin ",)),
]

# Handle URI credentials separately so the scheme/host remain useful.
_URI_CREDS = re.compile(r"(?i)\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://)([^\s:/]+):([^\s@]+)@")

_CREDENTIAL_NAMES = r"password|passwd|pwd|secret|secret[_-]?key|api[_-]?key|auth[_-]?token|private[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|token|jwt|session(?:[_-]?id)?|authorization|cookie"
_SENSITIVE_KEY = re.compile(r"(?i)(?:^|[_-])(?:" + _CREDENTIAL_NAMES + r")$")
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/@\s]+@")
_QUERY_SECRET = re.compile(r"(?i)([?&](?:" + _CREDENTIAL_NAMES + r")=)[^&#\s]*")
_JSON_SECRET = re.compile(r'(?i)(["\'](?:' + _CREDENTIAL_NAMES + r')["\']\s*:\s*)["\'][^"\'\r\n]*["\']')
_URL = re.compile(r'''(?i)\b[a-z][a-z0-9+.-]*://[^\s<>"']+''')
_KNOWN_SECRETS: set[str] = set()
_SECRET_LOCK = threading.Lock()
_PROVIDER_FRAGMENTS = {
    'AWS Access Key ID':('akia',), 'AWS Secret Access Key':('aws_secret',),
    'Google API Key':('aiza',), 'Google OAuth Token':('ya29.',),
    'GitHub Token':('ghp_','gho_','ghu_','ghs_','ghr_'),
    'GitHub Fine-grained PAT':('github_pat_',), 'Slack Token':('xox',),
    'Slack Webhook':('hooks.slack.com/services/',),
    'Stripe Secret Key':('_live_',), 'Stripe Test Key':('_test_',),
    'JWT':('eyj',), 'Twilio API Key':('sk',), 'SendGrid API Key':('sg.',),
    'Mailgun Key':('key-',), 'Firebase Cloud Messaging':('aaaa',),
    'Heroku API Key':('heroku',), 'npm Token':('npm_',),
    'Square Access Token':('sq0atp-',), 'PayPal Braintree Token':('access_token$production$',),
}


def _redact_url(match):
    try:
        # The presentation marker is not an IPv6 literal. Normalize it before
        # parsing so repeated persistence boundaries remain idempotent.
        url = urlsplit(match.group(0).replace('://[REDACTED]@', '://redacted@'))
        authority = url.netloc
        if '@' in authority:
            authority = '[REDACTED]@' + authority.rsplit('@', 1)[1]
        query = []
        for part in url.query.split('&'):
            key, sep, value = part.partition('=')
            if _SENSITIVE_KEY.search(unquote_plus(key)):
                value = '[REDACTED]'
            query.append(key + sep + value)
        return urlunsplit((url.scheme, authority, url.path, '&'.join(query),
                           '[REDACTED_FRAGMENT]' if url.fragment else ''))
    except ValueError:
        return '[REDACTED_URL]'


def register_secrets(values) -> None:
    """Remember opaque runtime values for persistence only; never serialize this set."""
    with _SECRET_LOCK:
        _KNOWN_SECRETS.update(str(v) for v in values if v is not None and len(str(v)) >= 4)


def safe_argv(cmd, secrets=()) -> list[str]:
    """Redact metadata without changing the executable argv supplied to a child."""
    values = [str(v) for v in cmd]
    tool = values[0].replace('\\', '/').rsplit('/', 1)[-1] if values else ''
    provider_flags = {'chaos': {'-key'}, 'github-subdomains': {'-t'}}.get(tool, set())
    known = list(secrets or ())
    result = []
    hide_next = False
    for value in values:
        key, separator, inline = value.partition('=')
        if hide_next:
            known.append(value)
            result.append('[REDACTED]')
            hide_next = False
        elif key.lower() in provider_flags or (key.startswith('-') and _SENSITIVE_KEY.search(key.lstrip('-'))):
            if separator:
                known.append(inline)
                result.append(key + '=[REDACTED]')
            else:
                result.append(value)
                hide_next = True
        else:
            result.append(redact_text(value))
    register_secrets(known)
    return [redact_text(v) for v in result]


def redact_text(value: Any) -> str:
    text = str(value or "")
    with _SECRET_LOCK:
        known = tuple(_KNOWN_SECRETS)
    for secret in sorted(known, key=len, reverse=True):
        text = text.replace(secret, '[REDACTED]')
    if '://' in text:
        text = _URL.sub(_redact_url, text)
        text = _URL_USERINFO.sub(r'\1[REDACTED]@', text)
        text = _URI_CREDS.sub(r"\1[REDACTED_USER]:[REDACTED_PASSWORD]@", text)
    if '?' in text or '&' in text:
        text = _QUERY_SECRET.sub(r'\1[REDACTED]', text)
    if ':' in text:
        text = _JSON_SECRET.sub(r'\1"[REDACTED]"', text)
    # Required literal fragments avoid repeated regex scans of megabyte lines.
    # They only skip impossible matches; unknown/new rules still run normally.
    lowered = text.lower()
    for rule in _PATTERNS:
        pattern, replacement = rule[:2]
        fragments = rule[2] if len(rule) > 2 else ()
        if fragments and not any(fragment in lowered for fragment in fragments):
            continue
        text = pattern.sub(replacement, text)
    # Keep recognized provider credentials aligned with the native detector.
    # Public identifiers/URLs and partial PEM markers are not credential values.
    from core.code_patterns import _SECRETS
    for name, pattern, _severity in _SECRETS:
        if name not in {'Firebase Database URL', 'Twilio Account SID', 'Private Key Block', 'Generic Secret Assignment'}:
            fragments = _PROVIDER_FRAGMENTS.get(name)
            if fragments and not any(fragment in lowered for fragment in fragments):
                continue  # Required literal absent; unknown/new rules still run.
            text = pattern.sub('[REDACTED_PROVIDER_CREDENTIAL]', text)
    return text


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if _SENSITIVE_KEY.search(str(k)) else redact_value(v)
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_value(v) for v in value)
    return value


def sanitize_finding(finding: dict) -> dict:
    return redact_value(copy.deepcopy(finding))


class StreamRedactor:
    """Line framing handles arbitrary pipe chunks, including split UTF-8/tokens.

    Oversize lines and multiline private-key bodies fail closed. Normal lines
    retain their bytes except credential substitutions. No raw spill file exists.
    """
    def __init__(self, secrets=(), max_line_bytes=16 * 1024 * 1024):
        register_secrets(secrets)
        self.maximum = max(64, int(max_line_bytes))
        self.pending = bytearray()
        self.discard = False
        self.private_key = False

    def _line(self, line: bytes) -> bytes:
        text = line.decode('utf-8', errors='replace')
        if self.private_key:
            if re.search(r'-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', text):
                self.private_key = False
            return b''
        start = re.search(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', text)
        if start:
            self.private_key = not bool(re.search(r'-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', text[start.end():]))
            return (redact_text(text[:start.start()]) + '[REDACTED_PRIVATE_KEY]\n').encode()
        return redact_text(text).encode('utf-8')

    def feed(self, data: bytes) -> bytes:
        output = bytearray()
        for part in data.splitlines(keepends=True):
            ended = part.endswith((b'\n', b'\r'))
            if not self.discard:
                if len(self.pending) + len(part) > self.maximum:
                    # An oversize BEGIN line must not expose following PEM body
                    # lines after the oversized line itself has been discarded.
                    if b'PRIVATE KEY-----' in self.pending + part and b'-----BEGIN ' in self.pending + part:
                        self.private_key = True
                    self.pending.clear()
                    self.discard = True
                    output.extend(b'[REDACTED_OVERSIZE_LINE]\n')
                else:
                    self.pending.extend(part)
            if ended:
                if not self.discard:
                    output.extend(self._line(bytes(self.pending)))
                self.pending.clear()
                self.discard = False
        return bytes(output)

    def finish(self) -> bytes:
        result = self._line(bytes(self.pending)) if self.pending and not self.discard else b''
        self.pending.clear()
        return result
