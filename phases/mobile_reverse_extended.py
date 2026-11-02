"""Extended mobile/desktop reverse adapters: JADX, YARA, Quark, .NET imports."""
from __future__ import annotations
import json,re
from pathlib import Path
from core import redteam_utils as RT
from core.scanner_normalizer import parse_file, save_items

def run(ctx):
    artifact=getattr(ctx.args,'apk',None) or getattr(ctx.args,'ipa',None) or getattr(ctx.args,'binary_path',None)
    rp=getattr(ctx.args,'mobile_reverse_results',None)
    if not (getattr(ctx.args,'mobile_reverse_extended',False) or rp):return
    out=RT.evidence_dir(ctx,'37_mobile_reverse_extended'); generated=[]
    if artifact and Path(artifact).is_file():
        art=Path(artifact)
        if art.suffix.lower()=='.apk' and ctx.runner.has('jadx'):
            d=out/'jadx'; d.mkdir(exist_ok=True); ctx.runner.run(['jadx','--show-bad-code','-d',str(d),str(art)],timeout=1800,log_name='mobile_jadx', capture_mode="tail"); generated.append(d)
        if art.suffix.lower()=='.apk' and ctx.runner.has('quark'):
            p=out/'quark_report.json'; rc,stdout,stderr=ctx.runner.run(['quark','-a',str(art),'-o',str(p)],timeout=1200,log_name='mobile_quark'); generated.append(p)
        rules=getattr(ctx.args,'yara_rules',None)
        if rules and Path(rules).exists() and ctx.runner.has('yara'):
            p=out/'yara_matches.txt'; rc,stdout,stderr=ctx.runner.run(['yara','-r',str(rules),str(art)],timeout=600,log_name='mobile_yara'); p.write_text(stdout,encoding='utf-8'); generated.append(p)
    paths=[]
    if rp:
        q=Path(rp); paths=[q] if q.is_file() else list(q.rglob('*')) if q.is_dir() else []
    paths += list(out.rglob('*'))
    count=0
    for p in paths:
        if p.is_file() and p.suffix.lower() in {'.json','.jsonl','.sarif'}:
            count += save_items(ctx,'mobile_reverse_extended',parse_file(p,source=p.stem),p.stem,{'mobile_reverse':True})
        elif p.is_file() and p.name=='yara_matches.txt':
            for line in p.read_text(errors='ignore').splitlines():
                if line.strip():
                    fid=ctx.save_finding({'phase':'mobile_reverse_extended','severity':'MEDIUM','confidence':'MEDIUM','title':'YARA artifact match requiring analyst review','target':str(artifact or ''),'description':'A supplied YARA rule matched the artifact. Rule quality and maliciousness must be reviewed.','evidence':line[:1600],'impact':'May indicate embedded malware, a risky component, packer or known artifact family.','remediation':'Validate the rule and matched bytes, identify provenance, remove or replace the affected component, and retest.','cwe':'CWE-506','finding_class':'lead','status':'lead'})
                    if fid is not None: count+=1
    RT.write_md(out/'MOBILE_REVERSE_EXTENDED.md','Extended Mobile and Desktop Reverse Engineering',[("Normalized observations",str(count)),("Tools",'JADX, Quark Engine, YARA, Androguard/objection/r2frida result imports, ILSpy/dnSpyEx/CFR/FernFlower result imports.'),("Dynamic boundary",'Runtime instrumentation and untrusted binary execution remain operator-controlled and evidence-import only.')])
    ctx.log('OK','mobile_reverse_extended',f'{count} extended mobile/reverse observation(s)')
