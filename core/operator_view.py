"""One operator page derived from stored findings, ledger and actual artifacts."""
from __future__ import annotations
from collections import Counter
from html import escape
import json
from core.evidence_graph import build
from core.finding_class import proof_authority


def write(ctx):
    findings = ctx.storage.all_findings()
    graph = build(findings)
    (ctx.output/'evidence_graph.json').write_text(json.dumps(graph, indent=2, default=str)+'\n')
    artifacts = []
    candidates = ['LEARNING.html', 'learning_overview.json', 'REPORT_final.html', 'REPORT_confirmed.md', 'REPORT_leads.md',
                  'llm_analysis/runtime_decisions.json', 'protected_routes_review.json',
                  'mobile/capability_receipt.json', 'recon/port_scope_review.json',
                  'execution_ledger.json', 'evidence_graph.json', 'attack_path/attack_path.json',
                  'spec/contract_review.json', 'web3/slither_import.json',
                  'source_code_full/source_code/analysis_coverage.json',
                  'redteam/31_local_llm_triage/local_llm_enrichment.json', 'redteam/31_local_llm_triage/refutation_review.json']
    mobile = ctx.output/'mobile'
    if mobile.is_dir():
        candidates.extend(str(p.relative_to(ctx.output)) for p in sorted(mobile.glob('manifest_*.json'))[:100])
    for name in candidates:
        path = ctx.output/name
        if path.is_file() and not path.is_symlink():
            artifacts.append(name)
    queue = []
    for finding in findings[:5000]:
        authority = proof_authority(finding)
        verified = authority['verified'] and authority['evidence_state'] == 'confirmed'
        enrichment = finding.get('enrichment') or {}
        review = enrichment.get('refutation_review', {}) if isinstance(enrichment, dict) else {}
        if not isinstance(review, dict): review = {}
        queue.append({'finding_id': finding.get('id'), 'severity': finding.get('severity'),
            'title': finding.get('title'), 'evidence_state': authority['evidence_state'],
            'next_action': 'Review captured proof and remediation' if verified else 'Review evidence gaps and collect an independent controlled validation',
            'refutation_verdict': review.get('verdict', 'not_reviewed'), 'proof_verified': verified})
    payload = {'schema': 'tbhm.operator-view/1', 'finding_count': len(findings),
               'counts_by_class': dict(Counter(proof_authority(f)['evidence_state'] for f in findings)),
               'queue': queue, 'queue_truncated': len(findings) > 5000,
               'artifacts': artifacts, 'coverage': 'Phase completion and traffic observations are not security-test coverage.'}
    (ctx.output/'operator_queue.json').write_text(json.dumps(payload, indent=2, default=str)+'\n')
    e = lambda value: escape(str(value if value is not None else ''))
    links = ''.join(f'<li><a href="{e(name)}">{e(name)}</a></li>' for name in artifacts)
    rows = ''.join('<tr>'+''.join('<td>'+e(row[key])+'</td>' for key in ('finding_id', 'severity', 'evidence_state', 'title', 'refutation_verdict', 'next_action'))+'</tr>' for row in queue)
    ledger_path = ctx.output/'execution_ledger.json'
    ledger = {}
    if ledger_path.is_file() and ledger_path.stat().st_size <= 4*1024*1024:
        try: ledger = json.loads(ledger_path.read_text())
        except (ValueError, OSError): pass
    events = ledger.get('events', [])
    outcomes = Counter(str(row.get('status', 'recorded')) for row in events if isinstance(row, dict))
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TBHM Operator Review</title><style>body{font:16px/1.55 system-ui;margin:0;background:#f4f6fa;color:#172334}main{max-width:1320px;margin:auto;padding:34px}h1{font-size:34px}h2{margin-top:36px}a{color:#075c92}section{background:white;border:1px solid #dce3ee;border-radius:12px;padding:22px;margin:20px 0}.scroll{overflow:auto}table{border-collapse:collapse;min-width:850px;width:100%}td,th{text-align:left;vertical-align:top;border-bottom:1px solid #dce3ee;padding:12px}th{background:#eff4fb}input{font:inherit;padding:10px;max-width:95%;width:440px}small{color:#46556c}</style>
<main><h1>Operator review</h1><p>Persisted evidence, open review work and available artifacts.</p>'''
    page += '<section><h2>Evidence state</h2><p>'+e(len(findings))+' stored findings · '+e(payload['counts_by_class'])+'</p><p>'+e(payload['coverage'])+'</p><p>Recorded ledger outcomes: '+e(dict(outcomes))+'</p><small>The report phase and final seal may still be running when this view is written. The final execution ledger is authoritative for phase outcomes.</small></section>'
    page += '<section><h2>Review queue</h2><label for="filter">Filter findings</label><p><input id="filter" type="search" placeholder="Title, severity, evidence state…"></p><div class="scroll"><table><thead><tr><th>ID</th><th>Severity</th><th>Evidence state</th><th>Finding</th><th>AI advice</th><th>Next action</th></tr></thead><tbody>'+rows+'</tbody></table></div></section>'
    page += '<section><h2>Available evidence</h2><ul>'+links+'</ul><p>Candidate root cause groups: '+e(len(graph['root_cause_candidates']))+'. Groups retain every finding; correlations do not establish a verified path.</p></section></main><script>document.getElementById("filter").addEventListener("input",function(){const q=this.value.toLowerCase();document.querySelectorAll("tbody tr").forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(q))});</script></html>'
    (ctx.output/'OPERATOR.html').write_text(page, encoding='utf-8')
    return payload
