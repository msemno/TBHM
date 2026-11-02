"""Review anonymous route responses without treating public 200s as auth bypass.

Path names guide inventory only. Static assets and HTML/SPA shells are retained
as observations. Sensitive structured fields produce leads for independent
validation; this phase alone cannot prove an authorization violation.
"""
from __future__ import annotations
import json
import re
from urllib.parse import urlparse

from core import anti_block, noise_filter
from core.targets import get_root_domains
try:
    import requests
except ImportError:
    requests = None

_NAMES = {
    'admin': ('admin', 'HIGH'), 'internal': ('internal', 'HIGH'),
    'sudo': ('admin', 'HIGH'), 'moderation': ('moderation', 'HIGH'),
    'billing': ('billing', 'MEDIUM'), 'invoices?': ('billing', 'MEDIUM'),
    'payment': ('payment', 'MEDIUM'), 'checkout': ('payment', 'MEDIUM'),
    'settings?': ('settings', 'LOW'), 'profile': ('profile', 'LOW'),
    'account': ('account', 'MEDIUM'), 'dashboard': ('dashboard', 'LOW'),
    'debug': ('debug', 'HIGH'), 'console': ('debug-console', 'HIGH'),
    'swagger': ('api-docs', 'MEDIUM'), 'openapi': ('api-docs', 'MEDIUM'),
    'graphql': ('graphql', 'MEDIUM'), 'metrics': ('monitoring', 'MEDIUM'),
    'health': ('monitoring', 'LOW'), 'actuator': ('spring-actuator', 'HIGH'),
}
ROUTE_CLASSES = [(re.compile(r'/(?:' + name + r')(?:/|$)', re.I), cls, risk)
                 for name, (cls, risk) in _NAMES.items()]
_STATIC = re.compile(r'\.(?:ico|png|jpe?g|gif|svg|webp|css|js|mjs|map|woff2?|ttf|eot)$', re.I)
_SENSITIVE_KEYS = {'password_hash', 'passwordhash', 'private_key', 'privatekey',
                   'access_token', 'refresh_token', 'session_secret'}


def route_class(url):
    path = urlparse(url).path or '/'
    if _STATIC.search(path):
        return None
    return next(((cls, risk) for pattern, cls, risk in ROUTE_CLASSES
                 if pattern.search(path)), None)


def response_assessment(status, text):
    if status not in (200, 206):
        return {'outcome': 'access_denied' if status in (401, 403) else 'inconclusive',
                'sensitive_fields': []}
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        return {'outcome': 'public_or_spa_response', 'sensitive_fields': []}
    fields = set()
    def walk(item, depth=0):
        if depth > 8:
            return
        if isinstance(item, dict):
            for key, child in list(item.items())[:100]:
                if str(key).lower() in _SENSITIVE_KEYS and isinstance(child, str) and len(child) > 8:
                    fields.add(str(key))
                walk(child, depth+1)
        elif isinstance(item, list):
            for child in item[:100]:
                walk(child, depth+1)
    walk(value)
    return {'outcome': 'sensitive_field_lead' if fields else 'structured_response_inventory',
            'sensitive_fields': sorted(fields)}


def run(ctx):
    if not requests:
        return
    urls = set()
    for name in ('alive.txt', 'urls.txt', 'crawl_urls.txt'):
        path = ctx.output/'recon'/name
        if path.exists():
            urls.update(ctx.runner.read_lines(path))
    in_scope = set(get_root_domains(ctx))
    observations, count, attempted = [], 0, 0
    for url in sorted(urls):
        if noise_filter.is_noise(url, in_scope_hosts=in_scope)[0]:
            continue
        classified = route_class(url)
        if not classified:
            observations.append({'url': url, 'outcome': 'not_an_auth_candidate'})
            continue
        cls, risk = classified
        if attempted >= 50:
            observations.append({'url': url, 'class': cls, 'outcome': 'budget_deferred'})
            continue
        attempted += 1
        ctx.storage.boost_endpoint_score(url, +15)
        host = urlparse(url).hostname or ''
        try:
            headers = {k: v for k, v in anti_block.headers_for(host).items()
                       if k.lower() not in {'authorization', 'cookie', 'proxy-authorization'}}
            response = requests.get(url, headers=headers, timeout=10, verify=True,
                                    allow_redirects=False, cookies={})
            assessment = response_assessment(response.status_code, response.text)
            row = {'url': url, 'class': cls, 'http_status': response.status_code,
                   'bytes': len(response.content), **assessment}
        except Exception as exc:
            row = {'url': url, 'class': cls, 'outcome': 'inconclusive',
                   'error_type': type(exc).__name__}
        observations.append(row)
        if hasattr(ctx.storage, 'save_observation'):
            ctx.storage.save_observation(phase='protected_routes',
                observation_type='anonymous_route', target=url,
                summary=row['outcome'], evidence=row)
        if row['outcome'] != 'sensitive_field_lead':
            continue
        ctx.save_finding({
            'phase': 'protected_routes', 'severity': 'LOW', 'confidence': 'LOW',
            'finding_class': 'lead', 'title': 'Sensitive response fields require access-control review',
            'target': host, 'url': url, 'method': 'GET', 'cwe': '',
            'evidence': json.dumps(row),
            'description': 'An anonymous JSON response included potentially sensitive field names. '
                           'Field values, intended public access, and actor controls require verification.',
            'impact': 'Unverified; field names alone do not establish a data leak or auth bypass.',
            'remediation': 'Establish the intended authorization invariant and test with owned actors.',
        })
        count += 1
    (ctx.output/'protected_routes_review.json').write_text(json.dumps({
        'schema': 'tbhm.route-review/1', 'observations': observations,
        'requests_attempted': attempted, 'leads': count,
        'authorization_matrix_tested': False, 'confirmed': 0}, indent=2)+'\n')
    ctx.log('OK', 'protected_routes', f'{attempted} route responses reviewed; {count} sensitive-field lead(s)')
