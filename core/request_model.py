"""Redacted exact-request metadata for authorised replay and workflow tests.

The workspace stores request shape, hashes and secret references—not live
credentials. Authentication values must be supplied at execution time by a
separate operator-controlled session provider. This prevents HAR imports from
turning the evidence database into a credential store.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SECRET_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}
_SECRET_KEYS = {
    "password", "passwd", "pass", "token", "access_token", "refresh_token",
    "id_token", "api_key", "apikey", "secret", "client_secret", "otp",
    "code", "session", "sessionid", "csrf", "xsrf", "jwt",
}


def _is_secret_key(value: str) -> bool:
    key = str(value or "").lower().replace("-", "_")
    return key in _SECRET_KEYS or any(x in key for x in ("password", "token", "secret", "api_key", "session"))


def _redact_headers(headers: dict) -> dict:
    out = {}
    for k, v in list((headers or {}).items())[:200]:
        name = str(k)[:256]
        out[name] = "[REDACTED]" if name.lower() in _SECRET_HEADERS else str(v)[:8192]
    return out


def _redact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        query = [(k, "[REDACTED]" if _is_secret_key(k) else v)
                 for k, v in parse_qsl(parts.query, keep_blank_values=True)]
        netloc = parts.netloc
        if parts.username is not None or parts.password is not None:
            host = parts.hostname or ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            try:
                port = f":{parts.port}" if parts.port is not None else ""
            except ValueError:
                port = ""
            netloc = f"[REDACTED]@{host}{port}"
        fragment = "[REDACTED_FRAGMENT]" if parts.fragment else ""
        return urlunsplit((parts.scheme, netloc, parts.path,
                           urlencode(query, doseq=True), fragment))
    except Exception:
        # Fail closed rather than returning a potentially credential-bearing URL.
        return "[REDACTED_MALFORMED_URL]"


def _redact_object(value):
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if _is_secret_key(k) else _redact_object(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_object(x) for x in value]
    return value


def _redact_body(body: str, content_type: str) -> tuple[str, str]:
    original = str(body or "")
    ctype = str(content_type or "").lower()
    # Avoid expanding very large JSON/form bodies in memory. Their exact hash
    # and length remain available to a separately governed request provider.
    if len(original.encode()) > 2 * 1024 * 1024:
        return "[REDACTED_LARGE_BODY; SHA256_PRESERVED]", "opaque-large"
    try:
        if "json" in ctype or original.lstrip().startswith(("{", "[")):
            parsed = json.loads(original)
            return json.dumps(_redact_object(parsed), sort_keys=True), "json"
    except Exception:
        pass
    if "application/x-www-form-urlencoded" in ctype:
        try:
            pairs = [(k, "[REDACTED]" if _is_secret_key(k) else v) for k, v in parse_qsl(original, keep_blank_values=True)]
            return urlencode(pairs, doseq=True), "form"
        except Exception:
            pass
    # Multipart and opaque bodies are not safe to retain because field/value
    # boundaries may include credentials or personal data.
    if "multipart/" in ctype or original:
        return "[REDACTED_BODY; SHA256_PRESERVED]", "opaque"
    return "", "empty"



def _safe_host(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except Exception:
        return ""


def _secret_refs(values) -> list[str]:
    out = []
    for value in values or []:
        text = str(value).strip()
        if not text:
            continue
        safe_reference = (
            len(text) <= 300
            and not any(ch.isspace() for ch in text)
            and "=" not in text
            and ("://" in text or text.startswith(("env:", "keyring:", "session:", "provider:")))
        )
        if safe_reference:
            out.append(text)
        else:
            out.append(f"[REDACTED_REF; SHA256={hashlib.sha256(text.encode()).hexdigest()}]")
        if len(out) >= 50:
            break
    return out

def normalize_request(row: dict, *, source: str = "operator") -> dict:
    method = str(row.get("method") or "GET").upper()
    original_url = str(row.get("url") or row.get("request_url") or "")
    headers = _redact_headers(row.get("headers") if isinstance(row.get("headers"), dict) else {})
    raw_body = row.get("body") if row.get("body") is not None else row.get("postData", "")
    if isinstance(raw_body, (dict, list)):
        raw_body = json.dumps(raw_body, sort_keys=True)
    raw_body = str(raw_body or "")
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    body, body_format = _redact_body(raw_body, content_type)
    url = _redact_url(original_url)
    digest_material = json.dumps({
        "method": method, "url": url, "headers": headers,
        "body_sha256": hashlib.sha256(raw_body.encode()).hexdigest(),
    }, sort_keys=True)
    return {
        "request_id": hashlib.sha256(digest_material.encode()).hexdigest()[:24],
        "method": method,
        "url": url,
        "host": _safe_host(original_url),
        "headers": headers,
        "body": body[:200000],
        "body_format": body_format,
        "body_length": len(raw_body.encode()),
        "body_sha256": hashlib.sha256(raw_body.encode()).hexdigest(),
        "content_type": content_type,
        "secret_refs": _secret_refs(row.get("secret_refs") or []),
        "source": source,
        "replay_boundary": "Live credentials are not stored; an approved session provider must supply secret references at execution time.",
    }


def import_har(path: str | Path, *, max_entries: int = 5000,
               max_file_bytes: int = 512 * 1024 * 1024) -> list[dict]:
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"HAR file not found: {p}")
    if p.stat().st_size > max_file_bytes:
        raise ValueError(f"HAR exceeds maximum size of {max_file_bytes} bytes")
    data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    entries = (((data.get("log") or {}).get("entries")) or []) if isinstance(data, dict) else []
    out = []
    for entry in entries[:max_entries]:
        request = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(request, dict):
            continue
        headers = {str(x.get("name")): str(x.get("value")) for x in request.get("headers", []) if isinstance(x, dict)}
        post = request.get("postData") or {}
        body = post.get("text", "") if isinstance(post, dict) else ""
        out.append(normalize_request({"method": request.get("method"), "url": request.get("url"),
                                      "headers": headers, "body": body}, source=p.name))
    return out
