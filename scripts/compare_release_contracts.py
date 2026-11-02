#!/usr/bin/env python3
"""Compare source inventory, argparse signatures, phase order and SQLite DDL."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

PROBE = '''
import argparse,hashlib,json,tempfile
from unittest.mock import patch
import tbhm
from core.storage import SCHEMA,Storage
from core.ai_plane.store import Store,SCHEMA_VERSION
with patch.object(argparse.ArgumentParser,'parse_args',lambda self:self):
 parser=tbhm.parse_args()
actions={}
for a in parser._actions:
 if not a.option_strings: continue
 key='|'.join(a.option_strings)
 actions[key]={'dest':a.dest,'class':type(a).__name__,'default':a.default,'nargs':a.nargs,
  'const':a.const,'required':a.required,'choices':list(a.choices) if a.choices is not None else None,
  'type':getattr(a.type,'__name__',None)}
with tempfile.TemporaryDirectory() as td:
 store=Store(td+'/memory.db')
 ai_tables={r['name']:r['sql'] for r in store.query("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
 ai_columns={name:[list(r) for r in store.conn.execute('PRAGMA table_info("'+name.replace('"','""')+'")')] for name in ai_tables}
 store.close()
 runtime=Storage(__import__('pathlib').Path(td)/'run.db')
 run_tables={r[0]:r[1] for r in runtime.conn.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
 run_columns={name:[list(r) for r in runtime.conn.execute('PRAGMA table_info("'+name.replace('"','""')+'")')] for name in run_tables}
 runtime.close()
print(json.dumps({'actions':actions,'phases':tbhm.FULL_PHASE_ORDER,'ai_schema_version':SCHEMA_VERSION,'ai_tables':ai_tables,
 'ai_columns':ai_columns,'run_columns':run_columns,
 'sqlite_schema_sha256':hashlib.sha256(SCHEMA.encode()).hexdigest()}))
'''


def probe(root):
    env = os.environ.copy()
    # A frozen CLI contract compares canonical defaults, not the operator's
    # legitimate environment override. Actual scans still honor the override.
    env.pop('TBHM_LOCAL_LLM_MODEL', None)
    result = subprocess.run([sys.executable, '-c', PROBE], cwd=root, env=env,
                            capture_output=True, text=True, timeout=20)
    if result.returncode: raise RuntimeError(result.stderr)
    return json.loads(result.stdout)


def inventory(root):
    return {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()
            and not any(part in {'__pycache__', '.git', '.venv', '.pytest_cache'} for part in p.relative_to(root).parts)}


def additive_columns(before, after):
    """Allow added tables/nullable or defaulted columns; retain old contracts.

    This structural check supplements populated-database upgrade tests. Equal
    DDL hashes are informative, not a prerequisite for a compatible migration.
    """
    for table, columns in before.items():
        if table not in after:
            return False
        old = {r[1]: r[2:] for r in columns}
        new = {r[1]: r[2:] for r in after[table]}
        if any(new.get(name) != signature for name, signature in old.items()):
            return False
        if any(signature[1] and signature[2] is None for name, signature in new.items() if name not in old):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    before, after = probe(args.baseline), probe(args.candidate)
    old_files, new_files = inventory(args.baseline), inventory(args.candidate)
    old_actions, new_actions = before['actions'], after['actions']
    removed, changed = sorted(old_actions.keys()-new_actions.keys()), sorted(k for k in old_actions.keys() & new_actions.keys() if old_actions[k] != new_actions[k])
    result = {'baseline': str(args.baseline), 'candidate': str(args.candidate),
        'removed_files': sorted(old_files-new_files), 'added_files': sorted(new_files-old_files),
        'removed_cli_actions': removed, 'changed_existing_argument_signatures': changed,
        'added_cli_actions': sorted(new_actions.keys()-old_actions.keys()),
        'baseline_cli_actions': len(old_actions), 'candidate_cli_actions': len(new_actions),
        'existing_phase_prefix_unchanged': after['phases'][:len(before['phases'])] == before['phases'],
        'appended_phases': after['phases'][len(before['phases']):], 'dispatched_phases': len(after['phases']),
        'sqlite_schema_equal': before['sqlite_schema_sha256'] == after['sqlite_schema_sha256'],
        'ai_schema_baseline':before['ai_schema_version'],'ai_schema_candidate':after['ai_schema_version'],
        'ai_sqlite_schema_equal':before['ai_tables']==after['ai_tables'],
        'ai_legacy_ddl_preserved':all(after['ai_tables'].get(k)==v for k,v in before['ai_tables'].items()),
        'ai_added_tables':sorted(after['ai_tables'].keys()-before['ai_tables'].keys()),
        'intentional_behavior_changes': [
            'Passed scanner checks, parser errors, declaration signatures and feature presence are separated from vulnerability evidence.',
            'Anonymous public routes and API response deviations no longer imply authorization failures or exposure.',
            'Port scanning requires explicit network IP scope; inference budgets/circuits and explicit model selection are corrected.',
            'Opt-in runtime model scheduling is bounded to selected independent phase windows with deterministic proof and policy authority retained.',
            'Missing mobile and CI inputs are explicit; verified local dependencies retain contextual inventory.'],
        'behavior_change_note': 'Operator-declared changes for this candidate; structural compatibility is measured independently.'}
    result['sqlite_backward_compatible'] = (additive_columns(before['run_columns'], after['run_columns'])
        and additive_columns(before['ai_columns'], after['ai_columns'])
        and after['ai_schema_version'] >= before['ai_schema_version'])
    result['passed'] = not (result['removed_files'] or removed or changed) and result['existing_phase_prefix_unchanged'] and result['sqlite_backward_compatible']
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in {'added_files','intentional_behavior_changes'}}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
