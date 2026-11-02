"""ProjectDiscovery HTTPX JSON contract; Python httpx is not this adapter.

The stable -json flag is used by recon. An unsupported invocation is an execution
error, never a clean absence of hosts. Banner stderr is separate from stdout.
"""
from __future__ import annotations
import json
from urllib.parse import urlsplit


def parse_records(stdout):
    records, errors = [], []
    for number, line in enumerate(str(stdout or '').splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            if not isinstance(row, dict) or not isinstance(row.get('url'), str):
                raise ValueError('expected object with a URL')
            parsed = urlsplit(row['url'])
            if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username:
                raise ValueError('invalid URL authority')
        except (ValueError, TypeError) as exc:
            errors.append({'line':number, 'reason':str(exc)[:160]})
            continue
        records.append(row)
    return records, errors
