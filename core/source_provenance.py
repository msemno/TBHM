"""Bounded local source provenance labels for evidence prioritization.

Path indicators are weak provenance. Third-party libraries can still be vulnerable,
particularly when an application configures or calls them unsafely. Never drop a
finding solely because its filename resembles a vendored dependency.
"""
from __future__ import annotations
import hashlib
from pathlib import Path

_PATH_MARKERS = ('/node_modules/', '/vendor/', '/third_party/', '/3rdparty/', '/bower_components/')


def classify_source(path: str, text: str, verified_sha256: set[str] | None = None) -> dict:
    normalized = '/' + str(path or '').replace('\\', '/').lower().lstrip('/')
    digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
    if verified_sha256 and digest in verified_sha256:
        status, evidence = 'third-party-verified', 'approved-content-hash'
    elif any(segment in normalized for segment in _PATH_MARKERS):
        status, evidence = 'third-party-likely', 'path-indicator-only'
    else:
        status, evidence = 'unknown-or-first-party', 'no-independent-provenance'
    return {'status':status,'provenance_evidence':evidence,'source_sha256':digest,
            'suppress_automatically':False}
