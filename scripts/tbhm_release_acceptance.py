#!/usr/bin/env python3
"""Run every unit-test module in isolation and require a completion receipt.

An exit code, metadata flag or an empty test suite cannot establish acceptance.
This is incremental source QA, not the high-level scanner completion gate.
"""
from __future__ import annotations
import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def worker(filename, receipt):
    from core.version import source_fingerprint,VERSION
    expected_path=ROOT/'tests'/Path(filename).name
    if expected_path.name!=filename or not expected_path.is_file():
        raise ValueError('unknown test module')
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern=filename)
    # One historical module uses plain pytest-style functions and deliberately
    # has no TestCase class. Execute those functions instead of accepting zero.
    module=sys.modules.get(Path(filename).stem)
    if module is not None:
        for name,value in sorted(vars(module).items()):
            if name.startswith('test_') and inspect.isfunction(value) and not inspect.signature(value).parameters:
                suite.addTest(unittest.FunctionTestCase(value,description=filename+':'+name))
    expected=suite.countTestCases();started=time.monotonic()
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    payload={'schema':'tbhm.test-receipt/1','module':filename,'version':VERSION,
        'source_build_sha256':source_fingerprint(),'expected_cases':expected,
        'executed_cases':result.testsRun,'failures':len(result.failures),
        'errors':len(result.errors),'skipped':len(result.skipped),
        'seconds':round(time.monotonic()-started,3),'python':sys.version,
        'passed':bool(expected>0 and result.testsRun==expected and result.wasSuccessful() and not result.skipped)}
    Path(receipt).write_text(json.dumps(payload,indent=2)+'\n')
    return 0 if payload['passed'] else 1


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',required=True)
    p.add_argument('--module',action='append',help='Optional exact module filename; default every test_*.py')
    p.add_argument('--worker',help=argparse.SUPPRESS)
    args=p.parse_args()
    if args.worker:return worker(args.worker,args.output)
    from core.version import source_fingerprint,VERSION
    output=Path(args.output).resolve();output.mkdir(parents=True,exist_ok=True)
    modules=[ROOT/'tests'/name for name in args.module] if args.module else sorted((ROOT/'tests').glob('test_*.py'))
    build=source_fingerprint();results=[];started=time.monotonic()
    for module in modules:
        receipt=output/(module.stem+'.json');log=output/(module.stem+'.log')
        receipt.unlink(missing_ok=True)
        env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
        with log.open('w') as handle:
            try:
                proc=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--worker',module.name,
                    '--output',str(receipt)],cwd=ROOT,env=env,stdout=handle,stderr=subprocess.STDOUT,timeout=180)
                rc=proc.returncode
            except subprocess.TimeoutExpired:rc=124
        try:record=json.loads(receipt.read_text())
        except (OSError,ValueError):record={'module':module.name,'passed':False,'reason':'missing valid completion receipt'}
        record['returncode']=rc;record['log_sha256']=hashlib.sha256(log.read_bytes()).hexdigest()
        record['passed']=bool(rc==0 and record.get('passed') and record.get('source_build_sha256')==build)
        results.append(record)
        print(json.dumps({'module':module.name,'passed':record['passed'],'cases':record.get('executed_cases',0)}),flush=True)
    result={'schema':'tbhm.release-acceptance/1','version':VERSION,'source_build_sha256':build,
        'modules':len(results),'executed_cases':sum(r.get('executed_cases',0) for r in results),
        'passed':bool(results and all(r['passed'] for r in results)),
        'seconds':round(time.monotonic()-started,3),'results':results,
        'scope':'Isolated unit modules and their local workflows; actual Kali/Windows/model reasoning not certified.'}
    (output/'SUMMARY.json').write_text(json.dumps(result,indent=2)+'\n')
    return 0 if result['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
