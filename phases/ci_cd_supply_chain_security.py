"""CI/CD trust-boundary, dataflow, adapter, and attestation review."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from core import redteam_utils as RT
from core.cicd_dataflow import analyze_tree, workflow_files
from core.scanner_normalizer import parse_file, save_items


def _files(root: Path):
    """v3.9.6 compatibility alias for the canonical workflow iterator."""
    yield from workflow_files(root)


def run(ctx):
    if not (getattr(ctx.args,"cicd_security",False) or getattr(ctx.args,"cicd_results",None) or getattr(ctx.args,"attestation_dir",None)):
        return
    out=RT.evidence_dir(ctx,"47_ci_cd_supply_chain_security")
    source_raw=getattr(ctx.args,"code_dir",None)
    source=Path(source_raw or "")
    native={"schema_version":"1","files":[],"findings":[],"summary":{"files":0,"findings":0},"boundary":"Static analysis only. Workflow commands are never executed."}
    if source_raw and source.is_dir(): native=analyze_tree(source,max_files=max(1,min(int(getattr(ctx.args,"cicd_max_files",5000) or 5000),20000)))
    (out/"cicd_native_dataflow.json").write_text(json.dumps(native,indent=2,ensure_ascii=False),encoding="utf-8")
    findings=0
    for row in native.get("findings",[]):
        status="supported" if row.get("kind")=="dataflow" else "lead"
        saved=ctx.save_finding({"phase":"ci_cd_supply_chain_security","source_capability":"cicd.dataflow","severity":row.get("severity","MEDIUM"),"confidence":"MEDIUM","title":row.get("title"),"target":row.get("path"),"description":"Native static CI/CD analysis identified a workflow trust, permission, integrity, or dataflow condition requiring analyst validation.","evidence":row.get("evidence","")[:3000],"evidence_paths":[str(out/"cicd_native_dataflow.json")],"prerequisites":row.get("prerequisites",[]),"confirmed_behavior":"The listed workflow text/dataflow pattern is present in the supplied source.","unconfirmed_assumptions":"Trigger reachability, attacker control, repository settings, branch protection, runner isolation, and effective token permissions.","impact":"A compromised contribution, dependency, runner, token, artifact, or build step may affect source, secrets, artifacts, or deployment integrity when prerequisites are met.","remediation":"Pin actions to immutable revisions, minimize permissions, validate untrusted context, isolate self-hosted runners, protect secrets, harden OIDC trust, verify artifacts, and retest.","cwe":row.get("cwe","CWE-829"),"finding_class":status,"status":status,"verified":False,"provenance":{"fingerprint":row.get("fingerprint"),"line":row.get("line")}})
        if saved is not None: findings+=1
    adapters={"actionlint":"unavailable","zizmor":"unavailable","cosign":"unavailable","slsa-verifier":"unavailable"}
    if source_raw and source.is_dir() and ctx.runner.has("actionlint") and (source/".github/workflows").is_dir():
        adapters["actionlint"]="executed"
        rc,stdout,stderr=ctx.runner.run(["actionlint","-format","{{json .}}"],timeout=600,log_name="cicd_actionlint",cwd=source)
        (out/"actionlint.jsonl").write_text(stdout,encoding="utf-8")
    if source_raw and source.is_dir() and ctx.runner.has("zizmor") and (source/".github/workflows").is_dir():
        adapters["zizmor"]="executed"
        rc,stdout,stderr=ctx.runner.run(["zizmor","--format","sarif",str(source)],timeout=900,log_name="cicd_zizmor")
        (out/"zizmor.sarif").write_text(stdout,encoding="utf-8")
    for tool in ("cosign","slsa-verifier"):
        if ctx.runner.has(tool): adapters[tool]="installed_not_auto_executed"
    rp=getattr(ctx.args,"cicd_results",None)
    imported=0
    if rp:
        root=Path(rp); paths=[root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()] if root.is_dir() else []
        for path in paths[:2000]:
            if path.suffix.lower() in {".json",".jsonl",".sarif"}: imported+=save_items(ctx,"ci_cd_supply_chain_security",parse_file(path,source=path.stem),path.stem,{"cicd":True,"source_capability":"cicd.dataflow"})
    attestation=Path(getattr(ctx.args,"attestation_dir","") or ""); attest=[]
    # Path('') points at the current working directory; no attestation input
    # must not silently inventory/hash the operator's working tree.
    if getattr(ctx.args, 'attestation_dir', None) and attestation.is_dir():
        for path in list(attestation.rglob("*"))[:5000]:
            if path.is_file(): attest.append({"path":path.relative_to(attestation).as_posix(),"sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"type":path.suffix.lower()})
    payload={"native_summary":native.get("summary",{}),"saved_findings":findings,"imported_findings":imported,"adapters":adapters,"attestation_inventory":attest,"boundary":"No workflow command, pipeline trigger, artifact publication, registry mutation, secret use, or untrusted code execution is performed.","scanned_pipeline_files":native.get("summary",{}).get("files",0),"normalized_findings":findings+imported,"file_provenance":native.get("files",[]),"supported_safe_tools":["actionlint","zizmor","Trivy config","Checkov","OSV-Scanner","Syft","Grype","SLSA verifier","cosign verification imports"]}
    (out/"ci_cd_supply_chain_summary.json").write_text(json.dumps(payload,indent=2),encoding="utf-8")
    RT.write_md(out/"CI_CD_SUPPLY_CHAIN_SUMMARY.md","CI/CD and Software Supply Chain Security",[("Result",json.dumps(payload,indent=2)),("Tool honesty","Adapters are marked executed, installed-not-auto-executed, or unavailable. Their registration never implies that verification ran."),("Boundary",payload["boundary"])])
    ctx.phase_state["ci_cd_supply_chain_security"]={"native":native.get("summary",{}),"imported":imported}
    ctx.log("OK","ci_cd_supply_chain_security",f"{native.get('summary',{}).get('files',0)} files, {findings+imported} observations")
