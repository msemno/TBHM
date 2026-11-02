"""Web3 observations and offline Slither import; no contract execution."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import requests
from core.http_policy import BudgetedSession
from core.scoped_http import network_discovery_enabled, safe_get
from core.safe_writes import ctx_gate

RPC_PROBE_PORTS = [8545, 8546, 7545, 9545]


def indicators(body):
    """Require assignment context; prose and transaction hashes aren't keys."""
    results = []
    for m in re.finditer(r'''(?i)\b(?:private_?key|walletPrivateKey)\b["']?\s*[:=]\s*["'](?:0x)?([a-f0-9]{64})["']''', body):
        results.append({'kind': 'private-key assignment candidate', 'severity': 'HIGH',
                        'evidence': '[REDACTED_PRIVATE_KEY]', 'line': body.count('\n', 0, m.start())+1,
                        'status': 'static_candidate_not_validated'})
    for m in re.finditer(r'''(?i)\b(?:mnemonic|seed_phrase|seedPhrase)\b["']?\s*[:=]\s*["']([a-z]+(?:\s+[a-z]+){11,23})["']''', body):
        if len(m[1].split()) in (12, 24):
            results.append({'kind': 'mnemonic assignment candidate', 'severity': 'LOW',
                            'evidence': '[REDACTED_SEED_PHRASE]', 'line': body.count('\n', 0, m.start())+1,
                            'status': 'wordlist_and_checksum_not_validated'})
    return results


def _import_slither(ctx, path, out):
    result = {'schema': 'tbhm.slither-import/1', 'status': 'error', 'imported': 0, 'errors': []}
    try:
        with Path(path).expanduser().open('rb') as handle:
            raw = handle.read(4*1024*1024+1)
        if len(raw) > 4*1024*1024:
            raise ValueError('Slither input exceeds 4 MiB')
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get('success') is not True:
            raise ValueError('Slither success=true missing; results are incomplete')
        detectors = (data.get('results') or {}).get('detectors')
        if not isinstance(detectors, list):
            raise ValueError('results.detectors must be an array')
        result['input_sha256'] = hashlib.sha256(raw).hexdigest()
        seen = set()
        for index, d in enumerate(detectors[:5000]):
            if not isinstance(d, dict) or not all(isinstance(d.get(k), str) and d[k] for k in ('check', 'description', 'impact', 'confidence')):
                result['errors'].append(f'detector {index}: malformed record'); continue
            impact = d['impact'].lower()
            if impact not in {'high', 'medium', 'low', 'informational', 'optimization'}:
                result['errors'].append(f'detector {index}: unknown impact'); continue
            key = hashlib.sha256((d['check']+'\0'+d['description']).encode()).hexdigest()
            if key in seen:
                continue
            seen.add(key)
            fid = ctx.save_finding({'phase': 'web3',
                'severity': {'high': 'HIGH', 'medium': 'MEDIUM', 'low': 'LOW'}.get(impact, 'INFO'),
                'confidence': d['confidence'].upper() if d['confidence'].lower() in {'high', 'medium', 'low'} else 'LOW',
                'finding_class': 'lead', 'validation_required': True,
                'title': 'Slither static lead: '+d['check'][:120], 'target': Path(path).name, 'url': '',
                'description': d['description'][:5000],
                'evidence': 'Imported Slither result; SHA256 '+result['input_sha256'],
                'detector_id': d['check'], 'source_tool': 'slither', 'source_result_id': key,
                'impact': 'Static detector impact is unverified; review reachable contract state transitions.',
                'remediation': 'Review detector guidance and validate in an isolated, authorized test.', 'mrs_score': 35})
            result['imported'] += int(fid is not None and fid != -1)
        if len(detectors) > 5000:
            result['errors'].append('detector cap reached')
        result['status'] = 'partial' if result['errors'] else 'complete'
    except Exception as exc:
        result['errors'].append(str(exc))
    (out/'slither_import.json').write_text(json.dumps(result, indent=2)+'\n')
    ctx.phase_state['web3_import'] = result['status']
    if result['status'] != 'complete' and getattr(ctx, 'execution_ledger', None):
        ctx.execution_ledger.record(kind='artifact', status='partial', artifact='web3/slither_import.json', reason='Slither import incomplete')
    ctx.log('OK' if result['status'] == 'complete' else 'WARN', 'web3',
            f"Slither import {result['status']}: {result['imported']} persisted static leads")


def run(ctx):
    out = ctx.output/'web3'; out.mkdir(exist_ok=True)
    if getattr(ctx.args, 'web3_results', None):
        _import_slither(ctx, ctx.args.web3_results, out)
    if (getattr(ctx.args, 'offline', False) or not network_discovery_enabled(ctx)
            or getattr(ctx, 'targets', []) == ['local-analysis.invalid']):
        return
    from core.targets import get_domains
    _scan_js_for_web3(ctx, ctx.output/'recon'/'javascript.txt')
    for primary in get_domains(ctx):
        _probe_rpc(ctx, primary); _ipfs_api(ctx, primary)


def _scan_js_for_web3(ctx, js_urls_file):
    if not js_urls_file.exists() or getattr(ctx.args, 'offline', False) or not network_discovery_enabled(ctx):
        return
    session = requests.Session()
    session.trust_env = False
    try:
        for url in ctx.runner.read_lines(js_urls_file)[:100]:
            try:
                response, final, _ = safe_get(ctx, session, url, timeout=12)
                if response.status_code != 200: continue
                body = response.text[:2*1024*1024]
            except Exception:
                continue
            for item in indicators(body):
                ctx.save_finding({'phase': 'web3', 'severity': item['severity'], 'confidence': 'MEDIUM',
                    'finding_class': 'lead', 'validation_required': True,
                    'title': 'Web3: '+item['kind']+' in JS', 'url': final, 'target': final,
                    'evidence': item['evidence']+'; line '+str(item['line'])+'; '+item['status'],
                    'description': 'Assignment resembles wallet material. Validity, ownership and use are unverified.',
                    'impact': 'Potential credential disclosure; no wallet access or transaction attempted.',
                    'remediation': 'Review privately, remove shipped secrets and rotate confirmed credentials.',
                    'cwe': 'CWE-798', 'mrs_score': 35})
    finally:
        session.close()


def _observe(ctx, url, payload, marker, title):
    allowed, _ = ctx_gate(ctx, 'POST', url, marker)
    if not allowed: return
    session = BudgetedSession(ctx, requests.Session(), budget=1, max_rps=1)
    try:
        response = session.request('POST', url, json=payload, timeout=6)
        data = response.json()
        if not isinstance(data, dict) or response.status_code != 200: return
        valid = (isinstance(data.get('result'), str) and bool(re.fullmatch(r'0x[0-9a-fA-F]+', data['result']))) if marker == 'eth_blockNumber' else isinstance(data.get('Version'), str)
        if valid:
            ctx.save_finding({'phase': 'web3', 'severity': 'INFO', 'confidence': 'HIGH', 'finding_class': 'lead',
                'title': title, 'target': url, 'url': url, 'method': 'POST',
                'evidence': 'Read-only '+marker+' returned a structurally valid response.',
                'description': 'Reachability observation. Public read APIs may be intentional.',
                'impact': 'Privileged namespaces, signing, pinning, writes and authorization bypass were not tested.',
                'remediation': 'Compare exposed read APIs with the intended publication policy.', 'mrs_score': 5})
    except Exception:
        return
    finally:
        session.close()


def _probe_rpc(ctx, primary):
    for port in RPC_PROBE_PORTS:
        for proto in ('http', 'https'):
            _observe(ctx, f'{proto}://{primary}:{port}',
                     {'jsonrpc': '2.0', 'method': 'eth_blockNumber', 'params': [], 'id': 1},
                     'eth_blockNumber', f'Ethereum RPC read endpoint observed on port {port}')


def _ipfs_api(ctx, primary):
    for port in (5001, 5002):
        _observe(ctx, f'http://{primary}:{port}/api/v0/version', None, 'ipfs-version',
                 f'IPFS version endpoint observed on port {port}')
