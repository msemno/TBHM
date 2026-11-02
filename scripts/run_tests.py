#!/usr/bin/env python3
"""Run packaged regressions in private environments; never install dependencies."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.regression_support import regression_environment


def run_owned(command, *, cwd, env, timeout):
    """Retain timeout failure and stop only the process group created here."""
    process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate(timeout=5)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        return 124, stdout, stderr+'\nTest deadline exceeded; owned process group stopped.'


def select_tests(known, names=None, failures=None):
    selected = list(known)
    if failures is not None:
        rows = json.loads(Path(failures).read_text())
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError('Previous regression JSON must be an array of test results')
        wanted = {row.get('test') for row in rows if row.get('returncode') != 0}
        selected = [name for name in selected if name in wanted]
    if names:
        if set(names)-set(known):
            raise ValueError('Unknown test group: '+', '.join(sorted(set(names)-set(known))))
        selected = [name for name in selected if name in names]
    if not selected:
        raise ValueError('No failing/matching test groups were selected; no tests executed')
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, default=Path(tempfile.gettempdir())/'tbhm-test-results.json')
    parser.add_argument('--workers', type=int, default=1)
    parser.add_argument('--test', action='append', help='Run an exact packaged group; repeat for several groups.')
    parser.add_argument('--failures-from', type=Path, help='Rerun only failed groups from a previous regression JSON.')
    args = parser.parse_args()
    source = args.source.resolve()
    known = sorted(p.name for p in source.glob('integration_test*.py'))
    known += sorted(str(p.relative_to(source)) for p in (source/'tests').glob('test_*.py'))
    if 'tests/test_audit_boundary_regressions.py' in known:
        raise SystemExit('Run candidate duplex cases only through a watchdog; this source is a candidate comparison copy.')
    try:
        tests = select_tests(known, args.test, args.failures_from)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    def run(name):
        with tempfile.TemporaryDirectory(prefix='tbhm-release-suite-') as td:
            dest = Path(td)/'source'
            shutil.copytree(source, dest, ignore=shutil.ignore_patterns('.git', '.venv', '__pycache__', '.pytest_cache'))
            env = regression_environment(Path(td)/'state')
            env['PYTHONPATH'] = str(dest)
            start = time.monotonic()
            rc, stdout, stderr = run_owned([sys.executable, name], cwd=dest, env=env, timeout=110)
            return dict(test=name, returncode=rc, stdout=stdout, stderr=stderr,
                        seconds=round(time.monotonic()-start, 2), environment_isolated=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(args.workers, 3))) as pool:
        rows = list(pool.map(run, tests))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(rows, indent=2)+'\n')
    passing = sum(row['returncode'] == 0 for row in rows)
    print(f'{passing}/{len(rows)} script groups passed; details: {args.output}')
    for row in rows:
        if row['returncode']:
            print(row['test'] + ':\n' + (row['stdout'] + row['stderr'])[-10000:])
    return 0 if passing == len(rows) else 1


if __name__ == '__main__':
    raise SystemExit(main())
