"""Bounded JSON data access for optional research capabilities; never executes it."""
from __future__ import annotations
import json
import math
from pathlib import Path


def _pairs(values):
    result = {}
    for key, value in values:
        if key in result: raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def loads(text):
    def invalid(_): raise ValueError('non-finite JSON number')
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=invalid)
    except RecursionError as exc:
        raise ValueError('JSON nesting limit') from exc
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop(); count += 1
        if depth > 40 or count > 100000: raise ValueError('JSON complexity budget')
        if isinstance(item, float) and not math.isfinite(item): raise ValueError('non-finite JSON number')
        if isinstance(item, (dict, list)):
            pending.extend((child, depth+1) for child in (item.values() if isinstance(item, dict) else item))
    return value


def read_bytes(path, maximum=8*1024*1024):
    path = Path(path).absolute()
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):
        raise ValueError('linked research input is not accepted')
    with path.open('rb') as handle: raw = handle.read(maximum+1)
    if len(raw) > maximum: raise ValueError('research input byte budget exceeded')
    return raw


def load(path, maximum=8*1024*1024):
    return loads(read_bytes(path, maximum).decode('utf-8'))
