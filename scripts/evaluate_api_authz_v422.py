#!/usr/bin/env python3
"""Run the packaged paired-account loopback HTTP corpus, not public targets."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.evaluation import evaluate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('tbhm_authz_runtime_fixture', ROOT/'tests/test_api_authz_v422.py')
    fixtures = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixtures)
    cases = json.loads((ROOT/'examples/research-v422/api_cases.json').read_text())
    labels, predictions, measurements = [], [], []
    for case in cases:
        labels.append({key: case[key] for key in ('id', 'category', 'vulnerable')})
        with tempfile.TemporaryDirectory(prefix='tbhm-api-corpus-') as td:
            fixture = fixtures.AuthorizationFixture(td, mode=case['mode'])
            try:
                report = fixture.run()
                row = report['cases'][0]
                # An interrupted/blocked run has no prediction. Preserve the
                # unresolved denominator rather than recording a clean result.
                if len(fixture.server.seen) == 6 and 'result' in row:
                    predictions.append({'id': case['id'], 'detected': row['result'] == 'pass'})
                measurements.append({'id': case['id'], 'mode': case['mode'], 'http_requests': len(fixture.server.seen),
                                     'verification_result': row.get('result', 'unresolved')})
            finally:
                fixture.close()
    labels_file, predictions_file = args.output_dir/'api_labels.json', args.output_dir/'api_predictions.json'
    labels_file.write_text(json.dumps(labels, indent=2)+'\n')
    predictions_file.write_text(json.dumps(predictions, indent=2)+'\n')
    result = evaluate(labels_file, predictions_file)
    result['corpus_scope'] = 'Eight synthetic loopback HTTP cases: four paired owned-account BOLA positives and four secure/wrong-object negatives. Two repetitions of four scenarios; no held-out projects, mobile coverage, field precision, or payout claim.'
    result['measurements'] = measurements
    (args.output_dir/'api_runtime_evaluation.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'status': result['status'], 'overall': result['overall'], 'requests': sum(r['http_requests'] for r in measurements)}, indent=2))
    return 0 if result['status'] == 'complete' and result['overall']['FP'] == 0 and result['overall']['FN'] == 0 else 1


if __name__ == '__main__': raise SystemExit(main())
