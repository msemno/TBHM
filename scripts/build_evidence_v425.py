#!/usr/bin/env python3
"""Regenerate release evidence metadata from measured local records."""
import argparse,csv,hashlib,json,platform,re,sys,uuid
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from core.version import VERSION
D=ROOT/'docs/research-v4.2.5'
def read(p):return json.loads(p.read_text())
def write(name,value):(D/name).write_text(json.dumps(value,indent=2)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def table(name,headers,rows):
 with (D/name).open('w',newline='') as f:w=csv.writer(f);w.writerow(headers);w.writerows(rows)
def stats(rows):return {'groups':len(rows),'passed':sum(r['returncode']==0 for r in rows),'unittest_cases':sum(int(n) for r in rows for n in re.findall(r'Ran (\d+) tests?',r['stdout']+r['stderr'])),'skipped':sum(int(n) for r in rows for n in re.findall(r'skipped=(\d+)',r['stdout']+r['stderr']))}
def main():
 p=argparse.ArgumentParser();p.add_argument('--baseline-tests',type=Path,required=True);p.add_argument('--baseline-zip',type=Path,required=True);a=p.parse_args()
 base=read(a.baseline_tests);write('BASELINE_TEST_RESULTS.json',base)
 tests=read(D/'TEST_RESULTS.json');proof=read(D/'benchmarks/proof_evaluation.json');learning=read(D/'benchmarks/learning_evaluation.json');compat=read(D/'COMPATIBILITY.json')
 classes=['access_control','sensitive_data_exposure','open_redirect','path_traversal','bfla','bola']
 class_evidence={}
 for kind in classes:
  class_evidence[kind]={'fixtures':'tests/fixtures_v425.py' if kind=='bola' else 'tests/fixtures_v424.py' if kind in {'path_traversal','bfla'} else 'scripts/evaluate_proof_fixtures_v421.py',
   'vectors':'knowledge/proof_behavior_v425.json' if kind=='bola' else 'knowledge/proof_behavior_v423.json',
   'matrix':'docs/research-v4.2.5/benchmarks/proof_evaluation.json' if kind=='bola' else 'docs/research-v4.2.4/benchmarks/paired_evaluation.json' if kind in {'bfla','path_traversal'} else 'docs/research-v4.2.2/benchmarks/proof_evaluation.json',
   'behavioral_guard':'tests/test_bola_v425.py' if kind=='bola' else 'tests/test_strict_classes_v424.py' if kind in {'path_traversal','bfla'} else 'tests/test_proof_behavior_v424.py'}
 verification={'schema':'tbhm.release-verification/1','release':VERSION,'baseline':stats(base),'candidate':stats(tests),'compatibility':compat,
  'strict_class_evidence':class_evidence,'proof_comparison':{'record':'benchmarks/proof_evaluation.json','legacy_vectors':proof['legacy_behavior'],'new_bola_vectors':len(proof['new_vectors'])},
  'learning_comparison':{'record':'benchmarks/learning_evaluation.json','retrieval_top_1':learning['retrieval_top_1'],'real_model_effectiveness':'UNVERIFIED'},
  'representative_held_out':{'status':'DEFERRED','reason':'No licensed/authorized independently labeled representative real projects supplied; synthetic fixtures are not field calibration.'},
  'resource_measurement':learning['resource_measurement'],'rights_independently_verified':False,'training_executed':False,
  'limits':['Global scanner/browser/wire metering not implemented','Full writer/opaque-format closure not established','No external attributable OAST or reversible API writes','Real model quality and actual Kali VM resource use unverified']}
 write('VERIFICATION.json',verification)
 metadata={'release':VERSION,'archive_root':'TBHM-'+VERSION,'previous_release':'4.2.4','release_date':'2026-10-19','baseline_sha256':sha(a.baseline_zip),
  'runtime':'runtime.json','dependency_lock':'requirements.lock','sbom':'SBOM.cdx.json','new_runtime_dependencies':[],
  'cli_actions':compat['candidate_cli_actions'],'dispatched_phases':145,'research_directory':'docs/research-v4.2.5',
  'release_status':'validated incremental release; high-level scanner gates remain open',
  'safety_model':{'llm_advisory_only':True,'strict_proof_v2_preserved':proof['legacy_behavior']['all_equal'],
   'persistent_reviewed_scenario_memory':True,'project_scoped_scenario_retrieval':True,'independent_label_evaluation':True,
   'approved_retrieval_config_promotion_and_rollback':True,'read_only_owned_account_replay':True,'public_object_privacy_control':True,
   'local_oast_approval_required':True,'oast_callback_is_not_confirmation':True,'legacy_internal_ssrf_probes_disabled':True,
   'external_scanner_traffic_globally_metered':False,'global_wire_enforcement':False,'offline_is_os_network_namespace':False,
   'offline_network_syscall_filter':'Linux x86-64 seccomp TSYNC inherited across fork/exec; existing tests retained; no namespace/packet-trace/global-wire claim',
   'all_sensitive_writers_reviewed':False,'all_vulnerability_classes_auto_confirmable':False,
   'optional_broker_driver_allowlist':['native','pipe-v1'],'broker_body_unit':'accepted decoded response-body bytes, not global wire bytes',
   'strict_replay_requires_destination_pins':True,'strict_classes':classes,
   'new_class_scope':'bola: exact controlled two-tenant JSON canary object read with owned valid sessions, anonymous/missing/own-object controls and two repeats',
   'llm_evaluation_import_is_confirmation':False,'training_executed':False,'real_model_effectiveness':'UNVERIFIED'},
  'flag_evidence':{'llm_advisory_only':'tests/test_self_evaluation_v425.py','strict_proof_v2_preserved':'docs/research-v4.2.5/benchmarks/proof_evaluation.json',
    'persistent_reviewed_scenario_memory':'tests/test_scenarios_v425.py','project_scoped_scenario_retrieval':'tests/test_scenarios_v425.py',
    'independent_label_evaluation':'tests/test_self_evaluation_v425.py','approved_retrieval_config_promotion_and_rollback':'docs/research-v4.2.5/benchmarks/learning_evaluation.json'}}
 (ROOT/f'RELEASE_INFO-v{VERSION}.json').write_text(json.dumps(metadata,indent=2)+'\n')
 validation={'release':VERSION,'date':'2026-10-19','implementation_baseline':'4.2.4','baseline':stats(base),'candidate':stats(tests),
  'baseline_record':'docs/research-v4.2.5/BASELINE_TEST_RESULTS.json','candidate_record':'docs/research-v4.2.5/TEST_RESULTS.json',
  'compatibility':compat,'legacy_behavior':proof['legacy_behavior'],'proof_class_total':6,'new_runtime_dependencies':[],
  'model_weights_added':False,'training_executed':False,'real_model_effectiveness':'UNVERIFIED',
  'environment':{'platform':platform.platform(),'python':platform.python_version(),'libc':platform.libc_ver()},
  'release_gate':'scripts/check_release_v425.py','high_level_scanner_done':False,'done_gate_expected_exit':1,
  'evidence_directory':'docs/research-v4.2.5','tested_code_record':'docs/research-v4.2.5/TESTED_CODE_HASHES.json'}
 for filename,key in [('STATIC_VALIDATION.json','static_validation'),('FRESH_INSTALL.json','fresh_offline_install'),('PATCH_VALIDATION.json','source_patch_validation')]:
  if (D/filename).exists():validation[key]=read(D/filename)
 (ROOT/'RELEASE_VALIDATION.json').write_text(json.dumps(validation,indent=2)+'\n')
 hashes={p.relative_to(ROOT).as_posix():sha(p) for p in ROOT.rglob('*.py') if not any(s in {'.git','.venv','__pycache__'} for s in p.relative_to(ROOT).parts)}
 write('TESTED_CODE_HASHES.json',hashes)
 rows=list(csv.reader((ROOT/'docs/research-v4.2.4/PROOF_CONTRACT_MATRIX.csv').open()))
 rows.append(['bola','IMPLEMENTED','core/strict_api_v425.py','Seven authenticated captures: owner/challenger/missing/own-object/anonymous/two repeats','Owned two-tenant exact JSON canary read only','tests/test_bola_v425.py; 42 measured vectors'])
 table('PROOF_CONTRACT_MATRIX.csv',rows[0],rows[1:])
 rows=list(csv.reader((ROOT/'docs/research-v4.2.4/TRANSPORT_COVERAGE.csv').open()))
 rows.append(['Scenario learning','LOCAL ONLY','core/ai_plane/learning_jobs.py','No target networking; optional existing loopback model; offline refuses inference','Not a scanner traffic broker; no wire-metering claim'])
 table('TRANSPORT_COVERAGE.csv',rows[0],rows[1:])
 gaps=[['P0','unscoped model context','FIXED','core/ai_plane/advisor.py','tests/test_security_v425.py','Project-scoped reviewed retrieval required for private case text'],
 ['P0','proposal path traversal','FIXED','core/ai_plane/proposals.py','tests/test_improvement_v425.py','Exact UID and non-link directory'],
 ['P0','installer missing manifest','FIXED','core/package_verifier.py; install.sh','tests/test_security_v425.py','Explicit release-only requirement preserves generic tree/ZIP contract'],
 ['P1','persistent reviewed scenarios','IMPLEMENTED','core/ai_plane/scenarios.py','tests/test_scenarios_v425.py','Additive schema with immutable versioned identities'],
 ['P1','reviewed RAG and mistake feedback','IMPLEMENTED','core/ai_plane/scenarios.py','benchmarks/learning_evaluation.json','Synthetic retrieval comparison only'],
 ['P1','independent evaluation','IMPLEMENTED INFRASTRUCTURE','core/ai_plane/self_evaluation.py','tests/test_self_evaluation_v425.py','Real model effectiveness UNVERIFIED'],
 ['P1','controlled improvement','IMPLEMENTED','core/ai_plane/improvement.py','tests/test_improvement_v425.py','Retrieval config only; source and weights excluded'],
 ['P1','owned two-tenant BOLA proof','IMPLEMENTED','core/strict_api_v425.py','benchmarks/proof_evaluation.json','Read-only controlled exact JSON canary representation'],
 ['P1','evidence correlation','IMPLEMENTED ADDITION','core/evidence_graph.py','tests/test_bola_v425.py','Origin/tenant/object declarations remain associations, not exploit paths'],
 ['P1','learning resource backpressure','IMPLEMENTED','core/ai_plane/learning_jobs.py','tests/test_improvement_v425.py','One active inference per DB; 32 pending per project; no hard RSS quota'],
 ['P2','training dataset preparation','IMPLEMENTED','core/ai_plane/scenarios.py; learning_cli.py','tests/test_scenarios_v425.py','Explicit permission and revocation validation; no training'],
 ['P2','real model evaluation/training','DEFERRED','docs/LEARNING-v4.2.5.md','benchmarks/learning_evaluation.json','Approved model/data/hardware and comparative held-out evidence required'],
 ['P2','global transport/wire closure','OPEN','core/request_guard.py; core/brokered_http.py','TRANSPORT_COVERAGE.csv','Enforced scanner/browser transport plus wire/packet evidence required'],
 ['P2','full sensitive writer closure','OPEN','scripts/inventory_source_v425.py','SOURCE_INVENTORY.json','Per-producer semantic review plus opaque format canaries still required'],
 ['P2','other strict injection/browser classes','DEFERRED','ROADMAP.md','PROOF_CONTRACT_MATRIX.csv','Complete semantic verifier and bounded fixture recipe required'],
 ['P2','external attributable OAST','DEFERRED','core/oast.py','ROADMAP.md','Approved reachable signed callback provider and false-correlation controls'],
 ['P2','representative held-out calibration','DEFERRED','ROADMAP.md','VERIFICATION.json','Licensed independently labeled real projects required'],
 ['P2','full requirement-level standards','OPEN','STANDARDS_EXECUTION.json','ROADMAP.md','Only the executed owned-object objective is linked; ASVS/MASVS coverage unclaimed'],
 ['P2','actual Kali VM model resource measurement','DEFERRED','docs/UPGRADE-v4.2.5.md','benchmarks/learning_evaluation.json','Actual Kali/VMware guest/model runtime required']]
 table('GAP_MATRIX.csv',['Priority','Requirement','State','Implementation','Evidence','Limit/prerequisite'],gaps)
 table('FEATURE_DECISIONS.csv',['Priority','Feature','Decision','Code','Evidence','Rationale'],gaps)
 standards={'schema':'tbhm.executed-standard-objectives/1','full_requirement_level_coverage':False,
  'rows':[{'standard':'WSTG','version':'4.2','requirement_id':'WSTG-ATHZ-04','objective':'Verify object authorization using two separately authenticated owned users',
   'executed_case_ids':['bola-vulnerable','bola-secure','bola-public','bola-expired','bola-echo','bola-wrong_tenant'],
   'execution_record':'docs/research-v4.2.5/benchmarks/proof_evaluation.json','scope':'Partial objective coverage: explicit owned two-tenant read-only JSON canary object',
   'source':'https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References'},
  {'standard':'OWASP API Security Top 10','version':'2023','requirement_id':'API1:2023','objective':'Enforce authorization for the particular object requested by an authenticated principal',
   'executed_case_ids':['bola-vulnerable','bola-secure'],'execution_record':'docs/research-v4.2.5/benchmarks/proof_evaluation.json',
   'scope':'Category/control objective link only; not complete API Top 10 requirement coverage',
   'source':'https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/'}],
  'deferred':['Complete WSTG objective coverage','API2–API10 executed requirement mapping','ASVS versioned verification requirements','MASVS/MASTG executed fixtures']}
 write('STANDARDS_EXECUTION.json',standards)
 sbom=read(ROOT/'SBOM.cdx.json');sbom['serialNumber']='urn:uuid:'+str(uuid.uuid4());sbom['metadata']['component']['version']=VERSION;sbom['metadata']['timestamp']=datetime.now(timezone.utc).isoformat();(ROOT/'SBOM.cdx.json').write_text(json.dumps(sbom,indent=2)+'\n')
 print(json.dumps({'baseline':stats(base),'candidate':stats(tests),'classes':classes,'release_status':metadata['release_status']}))
if __name__=='__main__':main()
