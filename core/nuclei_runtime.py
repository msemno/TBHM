"""Bounded, read-only Nuclei template and result readiness checks.

No subprocesses, network calls or installer side effects are used here.
"""
from __future__ import annotations
import json


def records(ctx, path):
    """Keep valid partial records and account for invalid parser input."""
    errors = 0
    for line in path.read_text(errors='replace').splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if not isinstance(value, dict) or not isinstance(value.get('info', {}), dict):
                raise ValueError('invalid nuclei record')
            info = value.get('info', {})
            if (not isinstance(info.get('classification', {}), dict)
                    or not isinstance(info.get('severity', 'info'), str)):
                raise ValueError('invalid nuclei classification/severity fields')
        except (ValueError, TypeError):
            errors += 1
            continue
        yield value
    if errors:
        ledger = getattr(ctx, 'execution_ledger', None)
        if ledger:
            ledger.record(kind='parser', status='parser-error', tool='nuclei',
                          reason=f'{errors} invalid JSON result records')
        ctx.log('WARN', 'nuclei', f'{errors} invalid result records; valid partial results retained')


def installed_templates(bootstrap):
    root = bootstrap.nuclei_templates_root()
    count = bootstrap.nuclei_template_count() if root is not None else 0
    return {"path": str(root) if root else None, "count": max(0, count),
            "ready": bool(root and count > 0), "action": "read-only-check"}


def interpret_execution(rc, stderr='', stdout='', output_present=False):
    text = ' '.join(str(stderr or stdout or '').lower().split())[:600]
    if rc == 124:
        return 'timeout'
    if rc == -9:
        return 'killed'  # SIGKILL does not identify an OOM or a timeout by itself.
    if rc == 130:
        return 'cancelled'
    if any(x in text for x in ('flag provided but not defined', 'unknown flag', 'unknown shorthand flag')):
        return 'tool-incompatible'
    if any(x in text for x in ('no templates provided', 'could not find any templates', 'no templates found', 'no templates to run')):
        return 'missing-templates'
    if rc not in (0, 1):
        return 'tool-error'
    if rc == 1 and not output_present:
        return 'tool-error'  # do not assume every version uses 1 for clean no match
    return 'results-present' if output_present else 'no-matches'


def evidence_fields(record):
    req, resp = record.get('request') or '', record.get('response') or ''
    if not isinstance(req, str): req = str(req)
    if not isinstance(resp, str): resp = str(resp)
    # Nuclei findings without both original capture components are leads only.
    valid = bool(req.strip() and resp.strip())
    return {'evidence_capture_status': 'capture-present' if valid else 'missing-http-exchange',
            'finding_class': 'supported' if valid else 'lead',
            'validation_required': 'Nuclei match is not vulnerability proof; replay with class-specific negative controls and repeats.' if valid else
                'Original HTTP request AND response are missing; obtain an approved capture before verification.'}
