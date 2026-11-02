"""
IDOR Engine — reusable IDOR discovery + verification.

Workflow:
  1. baseline()  — call with a known-good URL + auth context; record response shape
  2. mutate()    — generate N alternative URLs (id-1, id+1, random uuid, etc)
  3. diff()      — compare each mutated response against baseline + against a
                   known-invalid response (e.g. id=999999)
  4. classify()  — IDOR_LEAK / NO_DIFFERENCE / PROPER_403

Critical: every check uses BASELINE COMPARISON. A 200 status alone means nothing
on SPAs that return their app shell for everything.
"""
from __future__ import annotations
import hashlib
import random
import re
import string
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# ──────────────────────────────────────────────────────────────────────────────
# ID detection
# ──────────────────────────────────────────────────────────────────────────────
NUMERIC_PATH_RE = re.compile(r"/(\d{1,12})(?:/|\?|$)")
UUID_RE         = re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I)
TICKET_KEY_RE   = re.compile(r"/([A-Z][A-Z0-9]{1,9}-\d{1,6})(?:/|\?|$)")    # PROJ-123, INFRA-42
BASE64ID_RE     = re.compile(r"/([A-Za-z0-9+/=_-]{16,32})(?:/|\?|$)")


def detect_ids(url: str) -> list[dict]:
    """Find all ID-like tokens in a URL with their positions."""
    out = []
    for m in NUMERIC_PATH_RE.finditer(url):
        if len(m.group(1)) >= 2:      # ignore single digits to reduce noise
            out.append({"kind": "numeric", "value": m.group(1),
                        "start": m.start(1), "end": m.end(1)})
    for m in UUID_RE.finditer(url):
        out.append({"kind": "uuid", "value": m.group(1),
                    "start": m.start(1), "end": m.end(1)})
    for m in TICKET_KEY_RE.finditer(url):
        out.append({"kind": "ticket_key", "value": m.group(1),
                    "start": m.start(1), "end": m.end(1)})
    # Also check query string
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for k, vs in qs.items():
        if k.lower() in ("id", "user", "user_id", "uid", "account", "ticket",
                         "issue", "project", "key", "doc", "page", "ref",
                         "ownerid", "customer", "client"):
            for v in vs:
                if v.isdigit():
                    out.append({"kind": "numeric_query", "value": v,
                                "query_param": k})
                elif UUID_RE.match("/" + v):
                    out.append({"kind": "uuid_query", "value": v,
                                "query_param": k})
                elif TICKET_KEY_RE.match("/" + v):
                    out.append({"kind": "ticket_query", "value": v,
                                "query_param": k})
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Mutation
# ──────────────────────────────────────────────────────────────────────────────
def mutate_id(id_info: dict, n: int = 6) -> list[str]:
    """Generate N alternative ID values to test."""
    kind = id_info["kind"]
    val = id_info["value"]
    out = []
    if kind in ("numeric", "numeric_query"):
        try:
            n_val = int(val)
            out += [str(max(1, n_val - 1)), str(n_val + 1),
                    str(max(1, n_val - 10)), str(n_val + 10),
                    "1", "999999"]
        except ValueError:
            pass
    elif kind in ("uuid", "uuid_query"):
        out += [str(uuid.uuid4()) for _ in range(3)]
        out.append("00000000-0000-0000-0000-000000000000")
        out.append("ffffffff-ffff-ffff-ffff-ffffffffffff")
    elif kind in ("ticket_key", "ticket_query"):
        # Parse PROJ-123 → try PROJ-1, PROJ-124, PROJ-2, INFRA-1
        m = re.match(r"([A-Z][A-Z0-9]+)-(\d+)", val)
        if m:
            proj, num = m.group(1), int(m.group(2))
            out += [f"{proj}-{max(1, num-1)}", f"{proj}-{num+1}",
                    f"{proj}-1", f"{proj}-{num+10}", f"{proj}-999"]
            # Try other project keys (common: SUPPORT, OPS, SEC, INFRA, INT)
            for alt in ("SUPPORT", "INTERNAL", "SEC", "INFRA", "OPS", "ADMIN"):
                if alt != proj:
                    out.append(f"{alt}-1")
    return out[:n]


def build_mutated_url(original_url: str, id_info: dict, new_id: str) -> str:
    """Replace one ID in a URL with `new_id`."""
    if "query_param" in id_info:
        parsed = urlparse(original_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[id_info["query_param"]] = [new_id]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    # Path-based replacement using start/end
    s, e = id_info["start"], id_info["end"]
    return original_url[:s] + new_id + original_url[e:]


# ──────────────────────────────────────────────────────────────────────────────
# Response fingerprint + diff
# ──────────────────────────────────────────────────────────────────────────────
def fingerprint_response(status: int, body: bytes, headers: dict) -> dict:
    body = body or b""
    return {
        "status":       status,
        "length":       len(body),
        "content_type": (headers.get("Content-Type", "") or "").split(";")[0].strip().lower(),
        "body_hash":    hashlib.sha256(body[:5000]).hexdigest(),
        "body_prefix":  body[:300],
    }


def classify_idor(baseline_fp: dict, target_fp: dict,
                  invalid_fp: dict | None = None) -> tuple[str, str]:
    """
    Returns (verdict, reason).
    verdict ∈ {
        "IDOR_LEAK",        — target response looks like baseline → access granted
        "PROPER_DENIAL",    — target response looks like invalid → access denied
        "NEW_CONTENT",      — target is new but neither leak nor denial
        "INCONCLUSIVE",
    }
    """
    if baseline_fp["body_hash"] == target_fp["body_hash"]:
        # Identical to baseline → same content as authorized user sees
        return "IDOR_LEAK", "Response identical to baseline (authorized user view)"

    # If we have an invalid baseline, check against it
    if invalid_fp:
        if target_fp["body_hash"] == invalid_fp["body_hash"]:
            return "PROPER_DENIAL", "Response identical to known-invalid baseline"
        if target_fp["status"] == invalid_fp["status"]:
            len_invalid = invalid_fp["length"]
            if len_invalid > 0:
                diff_ratio = abs(target_fp["length"] - len_invalid) / max(1, len_invalid)
                if diff_ratio < 0.05:
                    return "PROPER_DENIAL", "Length matches invalid baseline (±5%)"

    if target_fp["status"] in (401, 403):
        return "PROPER_DENIAL", f"Status {target_fp['status']} — access denied"

    if target_fp["status"] in (200, 206):
        # Same status as baseline but different content → could be IDOR_LEAK
        # if the response shape looks like a real object response
        if target_fp["content_type"] in ("application/json", "application/xml") and \
           target_fp["length"] > 50:
            len_baseline = baseline_fp["length"]
            if len_baseline > 0:
                diff_ratio = abs(target_fp["length"] - len_baseline) / max(1, len_baseline)
                if diff_ratio < 0.5:    # within 50% of baseline size = similar shape
                    return "IDOR_LEAK", (
                        f"200 OK with JSON content (len={target_fp['length']}, "
                        f"baseline={baseline_fp['length']}). Likely returning another user's object."
                    )
        return "NEW_CONTENT", "200 OK with different content from baseline"

    return "INCONCLUSIVE", f"Status {target_fp['status']}, length {target_fp['length']}"


# ──────────────────────────────────────────────────────────────────────────────
# Soft-404 / SPA fallback detection
# ──────────────────────────────────────────────────────────────────────────────
SPA_INDICATORS = (
    b"__NEXT_DATA__", b"window.__INITIAL_STATE__", b"__NUXT__",
    b"ng-version=", b"data-reactroot", b'<div id="root"',
    b'<div id="app"', b"_app-",
)


def looks_like_spa_fallback(body: bytes) -> bool:
    """True if response body looks like an SPA's catch-all index.html."""
    sample = body[:50000]
    return any(ind in sample for ind in SPA_INDICATORS)


def random_invalid_path(base_url: str) -> str:
    """Generate a path that's guaranteed to not exist for soft-404 detection."""
    parsed = urlparse(base_url)
    canary = "_tbhm_404probe_" + "".join(random.choices(string.ascii_lowercase, k=16))
    return f"{parsed.scheme}://{parsed.netloc}/{canary}"
