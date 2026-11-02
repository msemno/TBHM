"""Offline OpenAPI inventory/diff. Documentation and traffic are not auth proof.

No external references, server URLs, callbacks or examples are executed/fetched.
This intentionally is not a JSON Schema conformance engine.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit
import yaml

METHODS = {'get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'trace'}
MAX_BYTES = 4*1024*1024
MAX_OPERATIONS = 2000


def load_document(path):
    path = Path(path).expanduser()
    with path.open('rb') as handle:
        raw = handle.read(MAX_BYTES+1)
    if len(raw) > MAX_BYTES:
        raise ValueError('input exceeds 4 MiB')
    value = yaml.safe_load(raw.decode('utf-8'))
    budget = [0]
    def check(node, parents, depth):
        budget[0] += 1
        if depth > 60 or budget[0] > 100000:
            raise ValueError('document complexity limit')
        if isinstance(node, (dict, list)):
            if id(node) in parents:
                raise ValueError('cyclic YAML aliases are unsupported')
            children = node.values() if isinstance(node, dict) else node
            for child in children:
                check(child, parents | {id(node)}, depth+1)
    check(value, set(), 0)
    if not isinstance(value, dict):
        raise ValueError('document root must be an object')
    return value, hashlib.sha256(raw).hexdigest()


def inventory(document):
    version = str(document.get('openapi') or document.get('swagger') or '')
    if not (version == '2.0' or re.fullmatch(r'3\.[01]\.\d+', version)):
        raise ValueError('supported contract versions: Swagger 2.0, OpenAPI 3.0.x/3.1.x')
    issues = []
    summaries, parameter_budget = {}, [10000]
    def bounded_shape(value, maximum):
        identity = (id(value), maximum)
        if identity not in summaries:
            encoded = json.dumps(value, sort_keys=True, default=str)
            summaries[identity] = value if len(encoded) <= maximum else {
                'shape_summarized': True, 'sha256': hashlib.sha256(encoded.encode()).hexdigest(),
                'reason': 'large repeated structure; compare source contract for details'}
        return summaries[identity]
    def resolve(value, seen=()):
        if not isinstance(value, dict):
            raise ValueError('expected object')
        ref = value.get('$ref')
        if ref is None:
            return value
        if not isinstance(ref, str) or not ref.startswith('#/'):
            raise ValueError('external/remote reference not followed')
        if ref in seen or len(seen) >= 24:
            raise ValueError('reference cycle/depth limit')
        target = document
        try:
            for key in unquote(ref[2:]).split('/'):
                target = target[key.replace('~1', '/').replace('~0', '~')]
        except (KeyError, TypeError):
            raise ValueError('unresolved local reference: '+ref)
        target = resolve(target, seen+(ref,))
        # Reference siblings differ between OAS versions/object types. Rather
        # than guess which wins, retain uncertainty for conflicting siblings.
        if any(k != '$ref' for k in value):
            raise ValueError('reference siblings require manual review')
        return target
    schemes = document.get('securityDefinitions', {}) if version == '2.0' else (document.get('components') or {}).get('securitySchemes', {})
    if not isinstance(schemes, dict):
        schemes = {}
    paths = document.get('paths')
    if not isinstance(paths, dict):
        raise ValueError('paths must be an object')
    operations = []
    for path, raw_item in list(paths.items())[:10000]:
        if len(operations) >= MAX_OPERATIONS:
            issues.append({'error': 'operation limit reached; inventory incomplete'}); break
        if not isinstance(path, str) or not path.startswith('/') or '\n' in path or '\r' in path:
            issues.append({'path': str(path)[:200], 'error': 'invalid path template'}); continue
        try:
            item = resolve(raw_item)
        except ValueError as exc:
            issues.append({'path': path, 'error': str(exc)}); continue
        for method in sorted(METHODS & set(item)):
            if len(operations) >= MAX_OPERATIONS:
                issues.append({'error': 'operation limit reached; inventory incomplete'}); break
            op = item[method]
            if not isinstance(op, dict):
                issues.append({'path': path, 'method': method, 'error': 'operation must be an object'}); continue
            op_issues, params = [], {}
            for owner in (item, op):
                raw_params = owner.get('parameters', [])
                if not isinstance(raw_params, list):
                    op_issues.append('parameters must be an array'); continue
                if len(raw_params) > 1000:
                    op_issues.append('per-operation parameter input limit reached')
                for raw_param in raw_params[:1000]:
                    if parameter_budget[0] <= 0:
                        op_issues.append('total parameter inventory limit reached'); break
                    try:
                        param = resolve(raw_param)
                        key = (param['in'], param['name'])
                        if not all(isinstance(x, str) for x in key):
                            raise ValueError('invalid parameter identity')
                        if key not in params: parameter_budget[0] -= 1
                        params[key] = {'in': key[0], 'name': key[1], 'required': param.get('required') is True,
                                       'schema': bounded_shape(param.get('schema', {'type': param.get('type', 'unknown')}), 512)}
                    except (ValueError, KeyError, TypeError) as exc:
                        op_issues.append(str(exc))
            explicit = 'security' in op or 'security' in document
            security = op.get('security', document.get('security'))
            auth = 'unspecified'
            if explicit:
                if not isinstance(security, list) or any(not isinstance(s, dict) for s in security):
                    auth = 'unknown'; op_issues.append('malformed security requirement')
                else:
                    auth = 'anonymous_allowed_by_contract' if not security or {} in security else 'required_by_contract'
                    for alternative in security:
                        for name, scopes in alternative.items():
                            if name not in schemes or not isinstance(scopes, list) or any(not isinstance(x, str) for x in scopes):
                                auth = 'unknown'; op_issues.append('unresolved/malformed security scheme: '+str(name))
            body = op.get('requestBody')
            if body is not None:
                try:
                    body = bounded_shape(resolve(body), 2048)
                except ValueError as exc:
                    op_issues.append(str(exc)); body = {'unresolved': True}
            prefix = document.get('basePath', '') if version == '2.0' else ''
            if not isinstance(prefix, str):
                prefix = ''; op_issues.append('invalid basePath')
            endpoint = (prefix.rstrip('/')+path) or '/'
            servers = op.get('servers', item.get('servers', document.get('servers', [])))
            if not isinstance(servers, list):
                servers = []; op_issues.append('servers must be an array')
            if len(servers) > 20:
                op_issues.append('server inventory limit reached')
            servers = [{'url': s['url'][:2048]} for s in servers[:20] if isinstance(s, dict) and isinstance(s.get('url'), str)]
            security_shape = bounded_shape(security, 4096)
            if isinstance(security_shape, dict) and security_shape.get('shape_summarized'):
                op_issues.append('large security requirement summarized; review source')
                auth = 'unknown'
            operations.append({'key': method.upper()+' '+endpoint, 'method': method.upper(),
                               'path': endpoint, 'operation_id': op.get('operationId', ''),
                               'security_source': 'operation' if 'security' in op else 'root' if explicit else 'unspecified',
                               'security': security_shape, 'authorization': auth,
                               'parameters': list(params.values()), 'request_body': body,
                               'servers': servers,
                               'issues': op_issues, 'test_status': 'not_tested'})
    if len(paths) > 10000:
        issues.append({'error': 'path limit reached; inventory incomplete'})
    schemas = document.get('definitions', {}) if version == '2.0' else (document.get('components') or {}).get('schemas', {})
    return {'version': version, 'operations': operations, 'issues': issues,
            'shared_schema_sha256': hashlib.sha256(json.dumps(schemas, sort_keys=True, default=str).encode()).hexdigest(),
            'security_schemes': sorted(schemes), 'servers': document.get('servers', []),
            'host': document.get('host', ''),
            'limits': {'max_paths': 10000, 'max_operations': MAX_OPERATIONS, 'max_parameter_records': 10000, 'external_refs_followed': False},
            'meaning': 'Static contract declarations only; auth enforcement and runtime coverage remain unverified.'}


def compare(previous, current):
    old, new = ({o['key']: o for o in doc['operations']} for doc in (previous, current))
    fields = ('security', 'authorization', 'parameters', 'request_body', 'servers')
    return {'added': sorted(new.keys()-old.keys()), 'removed': sorted(old.keys()-new.keys()),
            'shared_schemas_changed': previous.get('shared_schema_sha256') != current.get('shared_schema_sha256'),
            'changed': [{'operation': key, 'fields': [field for field in fields if old[key].get(field) != new[key].get(field)]}
                        for key in sorted(old.keys() & new.keys())
                        if any(old[key].get(field) != new[key].get(field) for field in fields)]}


def traffic_inventory(har, contract):
    entries = (har.get('log') or {}).get('entries')
    if not isinstance(entries, list):
        raise ValueError('HAR log.entries must be an array')
    observed, invalid = set(), 0
    for entry in entries[:10000]:
        try:
            req = entry['request']; url = urlsplit(req['url']); method = req['method'].upper()
            if url.scheme not in {'http', 'https'} or not url.hostname or method.lower() not in METHODS:
                raise ValueError('invalid request')
            # Never retain query values, credentials, request/response bodies.
            observed.add((method, url.hostname.lower(), url.path or '/'))
        except (KeyError, ValueError, TypeError, AttributeError):
            invalid += 1
    results, matched = [], set()
    hosts = set()
    for server in contract.get('servers', []):
        if isinstance(server, dict) and isinstance(server.get('url'), str):
            h = urlsplit(server['url']).hostname
            if h: hosts.add(h.lower())
    if contract.get('host'):
        h = urlsplit('//'+str(contract['host'])).hostname
        if h: hosts.add(h.lower())
    for op in contract['operations']:
        # A path/method match is an observation, not an executed security test.
        routes = []
        for server in op.get('servers', []):
            if isinstance(server, dict) and isinstance(server.get('url'), str):
                parsed = urlsplit(server['url'])
                if '{' not in server['url']:
                    routes.append((parsed.hostname.lower() if parsed.hostname else None,
                                   parsed.path.rstrip('/')+op['path']))
        if not routes:
            routes = [(h, op['path']) for h in hosts] if hosts else [(None, op['path'])]
        hits = []
        for x in sorted(observed):
            for host, route in routes:
                pattern = '^'+re.sub(r'\\\{[^}]+\\\}', '[^/]+', re.escape(route))+'$'
                if x[0] == op['method'] and (host is None or x[1] == host) and re.fullmatch(pattern, x[2]):
                    hits.append(x); break
        matched.update(hits)
        results.append({'operation': op['key'], 'status': 'path_method_observed' if hits else 'not_observed',
                        'observations': len(hits), 'host_alignment': 'declared_host' if all(h for h, _ in routes) else 'unknown',
                        'security_tested': False})
    return {'operations': results,
            'undocumented_observations': [{'method': m, 'host': h, 'path': p} for m, h, p in sorted(observed-matched)],
            'invalid_entries': invalid, 'truncated': len(entries) > 10000,
            'meaning': 'Traffic inventory only. Absence from this HAR does not prove a dead endpoint.'}


def review_files(ctx, out):
    source = getattr(ctx.args, 'openapi_input', None)
    if not source:
        return None
    result = {'schema': 'tbhm.api-contract-review/1', 'status': 'complete', 'errors': []}
    try:
        document, digest = load_document(source)
        result.update({'input_sha256': digest, 'contract': inventory(document)})
        baseline = getattr(ctx.args, 'openapi_baseline', None)
        if baseline:
            try:
                previous, before_hash = load_document(baseline)
                result['diff'] = compare(inventory(previous), result['contract'])
                result['baseline_sha256'] = before_hash
            except Exception as exc:
                result['errors'].append('baseline: '+str(exc))
        observations = getattr(ctx.args, 'api_observations', None)
        if observations:
            try:
                har, traffic_hash = load_document(observations)
                result['traffic'] = traffic_inventory(har, result['contract'])
                result['traffic_sha256'] = traffic_hash
            except Exception as exc:
                result['errors'].append('traffic: '+str(exc))
        paths = {o['path'] for o in result['contract']['operations']}
        destination = out/'endpoints.txt'
        if destination.exists():
            paths.update(destination.read_text().splitlines())
        destination.write_text('\n'.join(sorted(paths))+'\n', encoding='utf-8')
        if result['contract']['issues'] or any(o['issues'] for o in result['contract']['operations']):
            result['status'] = 'partial'
    except Exception as exc:
        result['errors'].append('contract: '+str(exc))
    if result['errors']:
        result['status'] = 'partial' if 'contract' in result else 'error'
    import io
    buffer, size = io.StringIO(), 0
    for chunk in json.JSONEncoder(indent=2, default=str).iterencode(result):
        size += len(chunk.encode('utf-8'))
        if size > 16*1024*1024:
            result = {'schema': 'tbhm.api-contract-review/1', 'status': 'error', 'errors': ['normalized contract output exceeds 16 MiB; split input for review']}
            break
        buffer.write(chunk)
    (out/'contract_review.json').write_text((json.dumps(result, indent=2) if result['status'] == 'error' else buffer.getvalue())+'\n', encoding='utf-8')
    ctx.phase_state['api_contract_review'] = result['status']
    if result['status'] != 'complete' and getattr(ctx, 'execution_ledger', None):
        ctx.execution_ledger.record(kind='artifact', status='partial', artifact='spec/contract_review.json', reason='contract review incomplete')
    ctx.log('WARN' if result['status'] != 'complete' else 'OK', 'spec_scan',
            'offline contract review: '+result['status'])
    return result
