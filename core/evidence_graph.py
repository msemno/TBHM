"""Bounded, read-only evidence relationships. Correlation is never proof."""
from __future__ import annotations

from collections import defaultdict
import hashlib
import ipaddress
from urllib.parse import urlsplit
from core.finding_class import proof_authority


def canonical_asset(finding):
    """Exact normalized host identity; no DNS, ownership or scope inference."""
    value = str(finding.get('url') or finding.get('target') or '').strip()
    if not finding.get('url') and (finding.get('file') or finding.get('source_tool') == 'slither'):
        return 'local:'+value
    try:
        parsed = urlsplit(value if '://' in value else '//'+value)
        host = parsed.hostname or ''
        if parsed.username or parsed.password or not host:
            raise ValueError('invalid network asset')
        if '://' not in value and ('/' in value or '\\' in value or host.endswith(('.py', '.js', '.sol', '.apk', '.ipa'))):
            raise ValueError('local artifact')
        try:
            host = ipaddress.ip_address(host).compressed
        except ValueError:
            host = host.rstrip('.').encode('idna').decode('ascii').lower()
        return 'host:'+host
    except (ValueError, UnicodeError):
        return 'local:'+value if value else 'unknown'


def stable_key(finding):
    # A candidate root cause key: deliberately excludes a model-generated title.
    # Equal keys suggest review, never delete records or prove a shared cause.
    try:
        path = urlsplit(str(finding.get('url') or '')).path
    except ValueError:
        path = ''
    location = str(finding.get('file') or finding.get('source_file') or '')
    parts = (canonical_asset(finding), path or location,
             str(finding.get('method') or '').upper(), str(finding.get('parameter') or ''),
             str(finding.get('cwe') or ''), str(finding.get('line') or ''))
    return hashlib.sha256('\x1f'.join(parts).encode()).hexdigest()[:24]


def build(findings, limit=20000):
    items = [f for f in findings if f.get('phase') != 'attack_path'][:limit]
    nodes, edges, assets, roots = [], [], {}, defaultdict(list)
    for number, f in enumerate(items):
        fid = 'finding:'+str(f.get('id', number))
        asset = canonical_asset(f)
        asset_id = 'asset:'+hashlib.sha256(asset.encode()).hexdigest()[:20]
        assets.setdefault(asset_id, {'id': asset_id, 'kind': 'asset', 'label': asset,
                                    'ownership': 'unknown', 'active_permission': 'not_inferred'})
        nodes.append({'id': fid, 'kind': 'finding', 'finding_id': f.get('id'),
                      'label': str(f.get('title') or '')[:500],
                      'evidence_state': proof_authority(f)['evidence_state'],
                      'scope_decision': f.get('scope_decision', 'unknown'),
                      'proof_verified': proof_authority(f)['verified'],
                      'root_cause_candidate': stable_key(f)})
        edges.append({'from': fid, 'to': asset_id, 'type': 'observed_on',
                      'meaning': 'record association; ownership and exploitability not inferred'})
        # Empty CWE/location is too weak to suggest a shared root cause.
        if f.get('cwe') and (f.get('url') or f.get('file') or f.get('parameter')):
            roots[stable_key(f)].append(f.get('id', number))
    relationships, associations = {}, []
    def associate(fid, kind, key, relation, **metadata):
        node_id = kind+':'+hashlib.sha256(key.encode()).hexdigest()[:24]
        relationships.setdefault(node_id, {'id':node_id,'kind':kind,'label':key,**metadata})
        associations.append({'from':fid,'to':node_id,'type':relation,'evidence_state':'record_association',
                             'confirms_exploit_edge':False})
    for number, finding in enumerate(items):
        fid = 'finding:'+str(finding.get('id', number))
        try:
            u = urlsplit(str(finding.get('url') or ''))
            if u.scheme in {'http','https'} and u.hostname and not u.username:
                route = u.scheme+'://'+u.netloc+u.path
                associate(fid,'route',route[:2000],'observed_route')
                if finding.get('parameter'):associate(fid,'parameter',route[:2000]+'#'+str(finding['parameter'])[:100],'uses_parameter')
        except ValueError:pass
        assertion = finding.get('assertion') or {}
        if not isinstance(assertion,dict):continue
        if assertion.get('vulnerability_class') == 'bola':
            try:
                endpoint = urlsplit(str(finding.get('url') or ''))
                if endpoint.scheme not in {'http','https'} or not endpoint.hostname or endpoint.username:
                    raise ValueError('no explicit origin')
                boundary = endpoint.scheme+'://'+endpoint.netloc
                for name in ('owner_actor','challenger_actor'):
                    if isinstance(assertion.get(name),str):
                        associate(fid,'identity',boundary+'#'+assertion[name][:100],'declared_identity',authority='operator_declaration')
                for name in ('owner_tenant','challenger_tenant'):
                    if isinstance(assertion.get(name),str):
                        associate(fid,'tenant',boundary+'#'+assertion[name][:100],'declared_tenant',authority='operator_declaration')
                if isinstance(assertion.get('object_id'),str) and isinstance(assertion.get('owner_tenant'),str):
                    associate(fid,'object',boundary+'#'+assertion['owner_tenant'][:100]+'/'+assertion['object_id'][:100],
                              'declared_protected_object',authority='operator_declaration')
            except ValueError:
                pass
        for name in ('privileged_actor','limited_actor'):
            if isinstance(assertion.get(name),str):associate(fid,'identity',canonical_asset(finding)+'#'+assertion[name][:100],'declared_identity',authority='operator_declaration')
        proof=finding.get('proof') or {}
        if not isinstance(proof,dict) or not isinstance(proof.get('captures'),dict):continue
        for role,ref in list(proof['captures'].items())[:20]:
            for item in (ref if isinstance(ref,list) else [ref])[:10]:
                if not isinstance(item,dict):continue
                path=item.get('path');digest=item.get('sha256')
                if (isinstance(path,str) and path.startswith('evidence/captures/') and '..' not in path.split('/') and
                        len(path)<300 and isinstance(digest,str) and len(digest)==64):
                    associate(fid,'evidence',path+'#'+digest,'references_capture',role=role,
                              proof_authority=proof_authority(finding)['source'])
    return {'schema': 'tbhm.evidence-graph/1', 'nodes': list(assets.values())+nodes,
            'edges': edges, 'root_cause_candidates': [
                {'key': key, 'finding_ids': ids, 'status': 'review_required'}
                for key, ids in sorted(roots.items()) if len(ids) > 1],
            'truncated': len(findings) > limit,
            'limits': {'max_findings': limit},
            'relationship_nodes':list(relationships.values()), 'relationship_edges':associations,
            'semantics': 'Observations and candidate groups only. No exploit-enables edges or verified paths are inferred.'}
