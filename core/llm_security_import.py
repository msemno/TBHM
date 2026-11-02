"""Offline, non-authoritative Garak/Promptfoo/export observation normalizer."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from core.evidence_redaction import redact_value
from core.research_input import load, loads, read_bytes

TAXONOMY = {'prompt-injection': 'LLM01:2025', 'data-leakage': 'LLM02:2025',
            'supply-chain': 'LLM03:2025', 'data-poisoning': 'LLM04:2025',
            'output-handling': 'LLM05:2025', 'tool-misuse': 'LLM06:2025',
            'system-prompt': 'LLM07:2025', 'rag-cross-tenant': 'LLM08:2025',
            'misinformation': 'LLM09:2025', 'resource-consumption': 'LLM10:2025'}


def _text(value, maximum=200):
    return str(value or '')[:maximum]


def _count(value):
    if type(value) is not int or not 0 <= value <= 10000000:
        raise ValueError('finite integer evaluation count required')
    return value


def normalize(path, format):
    if format not in {'garak', 'promptfoo', 'tbhm'}: raise ValueError('explicit supported LLM import format required')
    raw = read_bytes(path)
    if Path(path).suffix == '.jsonl':
        lines = raw.decode('utf-8').splitlines()
        if len(lines) > 10000: raise ValueError('LLM result row budget exceeded')
        rows = [loads(line) for line in lines if line.strip()]
    else:
        value = loads(raw.decode('utf-8'))
        if format == 'tbhm':
            if not isinstance(value, dict) or value.get('schema') != 'tbhm.llm-security-evidence/1':
                raise ValueError('expected tbhm.llm-security-evidence/1')
            rows = value.get('records')
        elif format == 'promptfoo' and isinstance(value, dict):
            results = value.get('results')
            rows = results.get('outputs', results.get('results')) if isinstance(results, dict) else results
        else: rows = value if isinstance(value, list) else [value]
    if not isinstance(rows, list) or len(rows) > 10000: raise ValueError('unsupported or oversized LLM result shape')
    normalized, errors, ignored = [], [], 0
    for ordinal, row in enumerate(rows):
        try:
            if not isinstance(row, dict): raise ValueError('LLM result must be an object')
            metadata = row.get('metadata') if isinstance(row.get('metadata'), dict) else {}
            category = metadata.get('tbhm_category', row.get('category', ''))
            identifier = _text(row.get('id') or row.get('uuid') or ordinal)
            record = {'ordinal': ordinal, 'id': identifier, 'source_format': format,
                'taxonomy_id': TAXONOMY.get(category), 'taxonomy_basis': 'explicit_import_annotation' if category in TAXONOMY else 'unmapped',
                'status': 'unresolved', 'authority': 'external_evaluator_observation', 'confirmed': False,
                'human_review_required': True}
            if format == 'garak':
                if row.get('entry_type') != 'eval': ignored += 1; continue
                total, passed = _count(row.get('total_evaluated')), _count(row.get('passed'))
                nones = _count(row.get('nones', 0))
                if passed > total: raise ValueError('Garak passed exceeds evaluated count')
                record.update(probe=_text(row.get('probe')), detector=_text(row.get('detector')),
                    evaluated=total, passed=passed, evaluator_failures=total-passed, unscoreable=nones,
                    status='evaluator_failure' if total > passed else 'evaluator_pass' if total else 'unresolved')
                if nones: record['incomplete'] = True
            elif format == 'promptfoo':
                record.update(test_index=row.get('testIdx'), prompt_index=row.get('promptIdx'))
                grade = row.get('gradingResult')
                success = row.get('success')
                if row.get('error') or not isinstance(grade, dict) or type(grade.get('pass')) is not bool:
                    record['reason'] = 'provider error or missing boolean assertion grade'
                elif type(success) is not bool or success != grade['pass']:
                    record['reason'] = 'missing or contradictory aggregate/assertion grade'
                else:
                    record['status'] = 'evaluator_pass' if success else 'evaluator_failure'
                # Scores and model-graded assertions are never vulnerability proof.
            else:
                outcome = row.get('evaluator_outcome')
                if outcome not in {'pass', 'fail', 'unresolved'}: raise ValueError('invalid exported evaluator outcome')
                record.update(status={'pass': 'evaluator_pass', 'fail': 'evaluator_failure', 'unresolved': 'unresolved'}[outcome],
                    producer=_text(row.get('producer')), application_impact_review=_text(row.get('application_impact_review'), 800),
                    program_policy_review=_text(row.get('program_policy_review'), 800))
            normalized.append(record)
        except (ValueError, TypeError, KeyError) as exc:
            errors.append({'ordinal': ordinal, 'status': 'unresolved', 'reason': str(exc)})
    return redact_value({'schema': 'tbhm.llm-security-review/1', 'source_sha256': hashlib.sha256(raw).hexdigest(),
        'format': format, 'status': 'partial' if errors or any(r.get('incomplete') or r['status'] == 'unresolved' for r in normalized) or not normalized else 'complete',
        'records': normalized, 'errors': errors, 'ignored_metadata_rows': ignored,
        'counts': {state: sum(r['status'] == state for r in normalized) for state in ('evaluator_pass', 'evaluator_failure', 'unresolved')},
        'taxonomy_edition': 'OWASP LLM 2025 (pinned research edition)', 'framework_coverage': 'not_asserted',
        'meaning': 'Imported evaluator observations only. Failure, jailbreak text, scores and model agreement do not establish application impact, bounty eligibility or strict proof confirmation.'})


def run(ctx):
    source = getattr(ctx.args, 'llm_security_input', None)
    if not source: return None
    report = normalize(source, getattr(ctx.args, 'llm_security_format', ''))
    out = ctx.output/'evidence'/'llm_security_review'; out.mkdir(parents=True, exist_ok=True)
    (out/'review.json').write_text(json.dumps(report, indent=2)+'\n')
    ctx.storage.save_observation(phase='ai_llm_tooling', observation_type='llm_external_evaluation',
        target='local-import', summary=report['status'], evidence={'source_sha256': report['source_sha256'], 'counts': report['counts']})
    ctx.save_finding({'phase': 'ai_llm_tooling', 'severity': 'INFO', 'confidence': 'LOW',
        'title': 'LLM evaluation evidence requires application-impact and program-policy review',
        'target': ctx.targets[0] if getattr(ctx, 'targets', None) else 'local-analysis.invalid', 'description': report['meaning'],
        'evidence': json.dumps(report['counts']), 'finding_class': 'lead', 'verified': False})
    ctx.log('OK', 'ai_llm_tooling', 'LLM evidence normalized: '+json.dumps(report['counts']))
    return report
