"""
Insertion Point discovery — Burp/ZAP style.

The single most important architectural concept in DAST:
> Before you can attack, you have to know WHERE you can attack.

An "insertion point" is anywhere a user-controlled value enters the request.
The audit phase tests each insertion point INDEPENDENTLY with context-appropriate
payloads, rather than blasting one payload at every URL.

Insertion point types:
  - QUERY_PARAM      ?key=value
  - BODY_FORM        form-encoded key=value
  - BODY_JSON        JSON value (recursive walking)
  - BODY_XML         XML element/attribute value
  - HEADER           HTTP header value
  - COOKIE           Cookie value
  - PATH_SEGMENT     /api/users/{id}/posts  (the {id} is an insertion point)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote


# Types of insertion points
QUERY_PARAM   = "query_param"
BODY_FORM     = "body_form"
BODY_JSON     = "body_json"
BODY_XML      = "body_xml"
HEADER        = "header"
COOKIE        = "cookie"
PATH_SEGMENT  = "path_segment"


@dataclass
class InsertionPoint:
    type: str                          # one of the constants above
    name: str                          # human-readable name (e.g. "id", "Authorization")
    original_value: str = ""           # the original string value
    json_path: str = ""                # for BODY_JSON, e.g. "$.user.email"
    path_index: int = -1               # for PATH_SEGMENT, e.g. index 2 in /api/users/123/posts
    location_desc: str = ""            # for reports: "URL query parameter 'id'"

    def __repr__(self):
        return f"<InsertionPoint {self.type}:{self.name}={self.original_value[:30]!r}>"


# ──────────────────────────────────────────────────────────────────────────────
# Heuristics: which path segments look like IDs (suitable for fuzzing)?
# ──────────────────────────────────────────────────────────────────────────────
ID_PATTERNS = [
    re.compile(r"^\d+$"),                                   # numeric ID
    re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-"),   # UUID
    re.compile(r"^[a-f0-9]{24,32}$"),                       # MongoDB ObjectId / hash
    re.compile(r"^[A-Za-z0-9_-]{20,40}$"),                  # short token / slug
]
PATH_KEYWORDS_BEFORE_ID = {
    "users", "user", "accounts", "account", "orders", "order",
    "invoices", "invoice", "tickets", "ticket", "messages", "items",
    "products", "files", "documents", "posts", "comments", "id",
}


def _looks_like_id(segment: str, prev_segment: str = "") -> bool:
    """A path segment is treated as an insertion point if it looks ID-shaped."""
    if not segment:
        return False
    if prev_segment.lower().rstrip("s") + "s" in PATH_KEYWORDS_BEFORE_ID:
        return True
    if prev_segment.lower() in PATH_KEYWORDS_BEFORE_ID:
        return True
    return any(p.match(segment) for p in ID_PATTERNS)


# ──────────────────────────────────────────────────────────────────────────────
# Discovery
# ──────────────────────────────────────────────────────────────────────────────
def discover(method: str, url: str,
             headers: dict | None = None,
             body: str | bytes | None = None,
             content_type: str = "") -> list[InsertionPoint]:
    """
    Return the list of insertion points for a request.
    headers, body, content_type are optional but improve coverage.
    """
    points: list[InsertionPoint] = []
    parsed = urlparse(url)

    # 1. QUERY_PARAM
    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        points.append(InsertionPoint(
            type=QUERY_PARAM, name=k, original_value=v,
            location_desc=f"URL query parameter '{k}'"))

    # 2. PATH_SEGMENT — only if segment looks ID-shaped
    segments = [s for s in parsed.path.split("/") if s]
    for i, seg in enumerate(segments):
        prev = segments[i - 1] if i > 0 else ""
        if _looks_like_id(seg, prev):
            points.append(InsertionPoint(
                type=PATH_SEGMENT, name=f"path[{i}]", original_value=seg,
                path_index=i, location_desc=f"URL path segment '{seg}' (after '{prev}')"))

    # 3. HEADERS — only "tainted" headers worth attacking
    if headers:
        for hname, hval in headers.items():
            hl = hname.lower()
            if hl in ("user-agent", "referer", "x-forwarded-for", "x-real-ip",
                     "x-forwarded-host", "x-host", "x-original-url",
                     "x-rewrite-url", "x-api-key", "authorization"):
                # We don't fuzz Authorization for credential abuse, only structurally
                if hl == "authorization":
                    points.append(InsertionPoint(
                        type=HEADER, name=hname, original_value=hval,
                        location_desc=f"HTTP header '{hname}' (structural fuzz only)"))
                else:
                    points.append(InsertionPoint(
                        type=HEADER, name=hname, original_value=hval,
                        location_desc=f"HTTP header '{hname}'"))

    # 4. COOKIES (parse Cookie header)
    if headers:
        cookie_hdr = headers.get("Cookie") or headers.get("cookie") or ""
        for kv in cookie_hdr.split(";"):
            if "=" in kv:
                k, v = kv.strip().split("=", 1)
                points.append(InsertionPoint(
                    type=COOKIE, name=k.strip(), original_value=v.strip(),
                    location_desc=f"Cookie '{k.strip()}'"))

    # 5. BODY (form / json / xml)
    if body:
        body_str = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
        ct = (content_type or "").lower()
        if ("application/json" in ct) or _looks_like_json(body_str):
            points += _walk_json(body_str)
        elif "application/xml" in ct or "text/xml" in ct or body_str.lstrip().startswith("<"):
            points += _walk_xml(body_str)
        elif "application/x-www-form-urlencoded" in ct or "=" in body_str:
            for k, v in parse_qsl(body_str, keep_blank_values=True):
                points.append(InsertionPoint(
                    type=BODY_FORM, name=k, original_value=v,
                    location_desc=f"Form body parameter '{k}'"))

    return points


def _looks_like_json(s: str) -> bool:
    s = s.strip()
    return (s.startswith("{") and s.endswith("}")) or \
           (s.startswith("[") and s.endswith("]"))


def _walk_json(body: str) -> list[InsertionPoint]:
    out = []
    try:
        data = json.loads(body)
    except Exception:
        return out

    def walk(obj, path):
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, f"{path}.{k}" if path else f"$.{k}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{path}[{i}]")
        elif isinstance(obj, (str, int, float, bool)):
            out.append(InsertionPoint(
                type=BODY_JSON, name=path, original_value=str(obj),
                json_path=path, location_desc=f"JSON body value at '{path}'"))
    walk(data, "")
    return out


def _walk_xml(body: str) -> list[InsertionPoint]:
    """Lightweight XML insertion point discovery (regex-based, avoids xml.etree DoS)."""
    out = []
    # Match <element>text</element> pairs
    for m in re.finditer(r"<([A-Za-z][\w-]*)[^>]*>([^<]+)</\1>", body):
        tag, text = m.group(1), m.group(2).strip()
        if text and 1 <= len(text) <= 200:
            out.append(InsertionPoint(
                type=BODY_XML, name=tag, original_value=text,
                location_desc=f"XML element '{tag}'"))
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Apply: build a modified request with payload injected at insertion point
# ──────────────────────────────────────────────────────────────────────────────
def apply(method: str, url: str, headers: dict, body: str,
          point: InsertionPoint, payload: str,
          append: bool = False) -> tuple[str, dict, str]:
    """
    Return (new_url, new_headers, new_body) with payload applied at the point.
    If append=True, the payload is appended to the original value (useful for
    bypass tests). Otherwise it replaces the value.
    """
    new_url = url
    new_headers = dict(headers or {})
    new_body = body or ""

    new_value = (point.original_value + payload) if append else payload

    if point.type == QUERY_PARAM:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        new_pairs = [(k, new_value if k == point.name else v) for k, v in pairs]
        new_query = urlencode(new_pairs, safe=":/")
        new_url = urlunparse(parsed._replace(query=new_query))

    elif point.type == PATH_SEGMENT:
        parsed = urlparse(url)
        segments = parsed.path.split("/")
        # path_index is in non-empty-segment space; map back
        non_empty_indices = [i for i, s in enumerate(segments) if s]
        if 0 <= point.path_index < len(non_empty_indices):
            target = non_empty_indices[point.path_index]
            segments[target] = quote(new_value, safe="")
            new_url = urlunparse(parsed._replace(path="/".join(segments)))

    elif point.type == HEADER:
        new_headers[point.name] = new_value

    elif point.type == COOKIE:
        cookie_hdr = new_headers.get("Cookie") or new_headers.get("cookie") or ""
        parts = []
        for kv in cookie_hdr.split(";"):
            kv = kv.strip()
            if "=" in kv:
                k, _, _ = kv.partition("=")
                if k.strip() == point.name:
                    parts.append(f"{k.strip()}={new_value}")
                else:
                    parts.append(kv)
        new_headers["Cookie"] = "; ".join(parts)

    elif point.type == BODY_FORM:
        pairs = parse_qsl(new_body, keep_blank_values=True)
        new_pairs = [(k, new_value if k == point.name else v) for k, v in pairs]
        new_body = urlencode(new_pairs)

    elif point.type == BODY_JSON:
        try:
            data = json.loads(new_body)
            _set_by_path(data, point.json_path, new_value)
            new_body = json.dumps(data)
        except Exception:
            pass

    elif point.type == BODY_XML:
        # Naive replace — assumes name uniqueness (good enough for fuzzing)
        new_body = re.sub(
            rf"(<{re.escape(point.name)}[^>]*>)[^<]*(</{re.escape(point.name)}>)",
            lambda m: m.group(1) + new_value + m.group(2),
            new_body, count=1)

    return new_url, new_headers, new_body


def _set_by_path(data: Any, path: str, value: str):
    """Walk a $.foo.bar[0].baz path and set the value."""
    tokens = re.findall(r"\.([A-Za-z_][\w]*)|\[(\d+)\]", path)
    obj = data
    for i, (key, idx) in enumerate(tokens):
        is_last = (i == len(tokens) - 1)
        if key:
            if is_last:
                obj[key] = value
            else:
                obj = obj[key]
        elif idx != "":
            if is_last:
                obj[int(idx)] = value
            else:
                obj = obj[int(idx)]
