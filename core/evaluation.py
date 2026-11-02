"""Explicit labeled-fixture metrics; unknown labels/predictions stay unresolved."""
from __future__ import annotations
from collections import defaultdict
import json
from pathlib import Path


def _records(path, field):
    with Path(path).expanduser().open('rb') as handle:
        raw = handle.read(4*1024*1024+1)
    if len(raw) > 4*1024*1024: raise ValueError('evaluation input exceeds 4 MiB')
    value = json.loads(raw)
    if not isinstance(value, list) or len(value) > 50000:
        raise ValueError('evaluation requires an array of at most 50,000 records')
    out = {}
    for row in value:
        if not isinstance(row, dict) or not isinstance(row.get('id'), str) or not row['id']:
            raise ValueError('record needs a nonempty string id')
        if row['id'] in out: raise ValueError('duplicate evaluation id: '+row['id'])
        if type(row.get(field)) is not bool: raise ValueError(field+' must be a boolean')
        if 'category' in row and not isinstance(row['category'], str): raise ValueError('category must be text')
        out[row['id']] = row
    return out


def evaluate(labels_path, predictions_path):
    labels, predictions = _records(labels_path, 'vulnerable'), _records(predictions_path, 'detected')
    categories = defaultdict(lambda: dict(TP=0, FP=0, FN=0, TN=0))
    total = dict(TP=0, FP=0, FN=0, TN=0)
    for identity in sorted(labels.keys() & predictions.keys()):
        label, prediction = labels[identity], predictions[identity]
        key = ('TP' if prediction['detected'] else 'FN') if label['vulnerable'] else ('FP' if prediction['detected'] else 'TN')
        total[key] += 1; categories[label.get('category') or 'unspecified'][key] += 1
    def metrics(counts):
        tp, fp, fn, tn = (counts[k] for k in ('TP', 'FP', 'FN', 'TN'))
        return {**counts, 'precision': tp/(tp+fp) if tp+fp else None,
                'recall': tp/(tp+fn) if tp+fn else None,
                'false_positive_rate': fp/(fp+tn) if fp+tn else None,
                'f1': 2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None}
    missing = sorted(labels.keys()-predictions.keys())
    unlabeled = sorted(predictions.keys()-labels.keys())
    # Preserve original observed-only metrics; add the denominator and
    # conservative recall bound so omitted predictions cannot inflate a claim.
    unresolved_by_category = defaultdict(list)
    for identity in missing:
        unresolved_by_category[labels[identity].get('category') or 'unspecified'].append(identity)
    for label in labels.values():
        categories[label.get('category') or 'unspecified']
    category_results = {}
    for category, counts in sorted(categories.items()):
        identities = unresolved_by_category[category]
        unknown_positives = sum(labels[i]['vulnerable'] for i in identities)
        denominator = counts['TP']+counts['FN']+unknown_positives
        category_results[category] = {**metrics(counts), 'unresolved': len(identities),
            'unresolved_vulnerable': unknown_positives,
            'recall_lower_bound': counts['TP']/denominator if denominator else None}
    return {'schema': 'tbhm.fixture-evaluation/1', 'status': 'partial' if missing or unlabeled or not labels else 'complete',
            'evaluated': sum(total.values()), 'labeled': len(labels), 'predictions': len(predictions),
            'overall': metrics(total), 'by_category': category_results,
            'prediction_coverage': sum(total.values())/len(labels) if labels else None,
            'unresolved_missing_predictions': missing, 'unlabeled_predictions': unlabeled,
            'meaning': 'Metrics apply only to these operator-labeled cases. Missing predictions are unresolved, not clean; no general accuracy or payout claim follows.'}
