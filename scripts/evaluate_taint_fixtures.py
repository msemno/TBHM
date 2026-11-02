#!/usr/bin/env python3
"""Reproduce a small regression corpus; this is not a real-world accuracy study."""
import argparse
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.taint_engine import analyze_python
from core.evaluation import evaluate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(); args.output_dir.mkdir(parents=True, exist_ok=True)
    cases = json.loads((ROOT/'examples/research-v420/taint_cases.json').read_text())
    labels = [{k: row[k] for k in ('id', 'category', 'vulnerable')} for row in cases]
    predictions = [{'id': row['id'], 'detected': any(f.sink_cwe == row['category'] and not f.sanitized
                    for f in analyze_python(row['source'], row['id']+'.py'))} for row in cases]
    labels_path, predictions_path = args.output_dir/'labels.json', args.output_dir/'predictions.json'
    labels_path.write_text(json.dumps(labels, indent=2)+'\n')
    predictions_path.write_text(json.dumps(predictions, indent=2)+'\n')
    result = evaluate(labels_path, predictions_path)
    result['corpus_scope'] = '18 artificial Python snippets selected for fixed regression cases; assumed source/sink semantics, no runtime exploitation, no generalization to projects or other languages.'
    (args.output_dir/'evaluation.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__': raise SystemExit(main())
