"""Offline origin attribution and WAF behavior review.

Never performs DNS lookups, active requests, or an origin-bypass. A historical
IP is only a *candidate*; scanning requires explicit authorization for that IP.
"""
from __future__ import annotations
import ipaddress
from urllib.parse import urlsplit


def _ip(value):
    try:
        ip = ipaddress.ip_address(str(value).strip('[]'))
        if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
            return None
        return str(ip)
    except ValueError:
        return None


def review_origin_candidates(records: list[dict], authorized_ips: list[str]) -> list[dict]:
    approved = {val for x in authorized_ips if (val := _ip(x))}
    results = {}
    for row in records:
        address = _ip(row.get('ip', ''))
        if not address:
            continue
        host = str(row.get('hostname') or '').strip().lower().rstrip('.')
        source = str(row.get('source') or 'unspecified')[:80]
        if not host:
            continue
        key = (host, address)
        item = results.setdefault(key, {'hostname': host, 'ip': address,
                                        'authorization': 'approved-ip' if address in approved else 'not-approved',
                                        'state': 'candidate-only', 'sources': []})
        if source not in item['sources']:
            item['sources'].append(source)
    return sorted(results.values(), key=lambda x:(x['hostname'],x['ip']))


def review_firewall_pairs(samples: list[dict]) -> list[dict]:
    """Compare externally collected benign/control responses. Not a vulnerability oracle."""
    out=[]
    for sample in samples:
        baseline=sample.get('baseline') or {}
        variant=sample.get('variant') or {}
        bs=baseline.get('status');vs=variant.get('status')
        if type(bs) is not int or type(vs) is not int or not (100 <= bs <= 599 and 100 <= vs <= 599):
            label='incomplete-evidence'
        elif bs < 400 and vs in (403,406,429):
            label='possible-filter-differential'
        elif bs == vs:
            label='same-http-status'
        else:
            label='different-http-behavior'
        out.append({'test_id': str(sample.get('test_id') or '')[:100],
                    'observation': label, 'baseline_status': bs, 'variant_status': vs,
                    'security_conclusion': 'unverified',
                    'next_step': 'Review complete redacted exchanges, approval scope, and repeatable controls.'})
    return out
