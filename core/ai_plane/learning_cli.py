"""Standalone bounded scenario operations; no scan target or model is required."""
import json
from html import escape
from pathlib import Path
from core.ai_plane.scenarios import ScenarioMemory,canonical,identity
from core.ai_plane.self_evaluation import Evaluator
from core.ai_plane.improvement import Improvements
from core.ai_plane.learning_jobs import LearningJobs
from core.research_input import load

READ_ONLY={'get','retrieve','prompt','overview','evaluate','dashboard','validate_training'}

def dashboard(memory,project):
    overview=memory.overview(project)
    rows=memory.store.query('SELECT scenario_id,vulnerability_class,split,state,content_sha256 FROM scenarios WHERE project_id=? ORDER BY updated_at DESC LIMIT 500',(identity(project),))
    e=lambda x:escape(str(x))
    body=''.join('<tr>'+''.join('<td>'+e(row[k])+'</td>' for k in ('scenario_id','vulnerability_class','split','state','content_sha256'))+'</tr>' for row in rows)
    return '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TBHM Learning Review</title>
<style>body{font:16px/1.6 system-ui;background:#f4f6fa;color:#172334;margin:0}main{max-width:1200px;margin:auto;padding:24px}section{background:white;border:1px solid #dce3ee;border-radius:12px;padding:20px;margin:18px 0}.scroll{overflow:auto}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:12px;border-bottom:1px solid #ddd}pre{white-space:pre-wrap;overflow-wrap:anywhere}input{font:inherit;padding:10px}</style><main><h1>Learning review · '''+e(project)+'''</h1><p>Reviewed history supports advice. Deterministic proof remains the confirmation authority. Unresolved does not mean clean.</p><section><h2>Overview and performance</h2><pre>'''+e(json.dumps(overview,indent=2))+'''</pre></section><section><h2>Scenario library</h2><input id="filter" type="search" aria-label="Search scenarios" placeholder="Search ID, class, state"><div class="scroll"><table><thead><tr><th>Scenario</th><th>Class</th><th>Split</th><th>Review state</th><th>Content hash</th></tr></thead><tbody>'''+body+'''</tbody></table></div></section><p>Review, propose, approve, promote and rollback through --ai-learning plans. This page has no execution privileges.</p></main><script>document.getElementById('filter').addEventListener('input',function(){const q=this.value.toLowerCase();document.querySelectorAll('tbody tr').forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(q))})</script></html>'''

def operate(memory,gate,plan,*,approved=False,client=None,model_version='unavailable',offline=False):
    if not isinstance(plan,dict) or plan.get('schema')!='tbhm.learning-operation/1':raise ValueError('expected tbhm.learning-operation/1')
    op=plan.get('operation');project=identity(plan.get('project_id'))
    if op not in READ_ONLY and approved is not True:raise PermissionError('mutation requires --approve-ai-learning; review/promotion are deliberate operator actions')
    ev=Evaluator(memory);imp=Improvements(memory,gate);jobs=LearningJobs(memory)
    if op=='ingest':
        record=plan['record']
        if record.get('project_id')!=project:raise ValueError('project mismatch')
        return memory.ingest(record)
    if op=='ingest_run':
        from core.ai_plane.scenario_import import ingest_run
        return ingest_run(memory,project,plan)
    if op=='get':return memory.get(plan['scenario_id'],project)
    if op=='review':return memory.review(plan['scenario_id'],project,approved=approved,**plan['review'])
    if op=='revoke':return memory.revoke(plan['scenario_id'],project,approved=approved)
    if op=='retrieve':return memory.retrieve(project,plan['query'],**plan.get('options',{}))
    if op=='prompt':return ev.prompt(plan['scenario_id'],project,**plan.get('options',{}))
    if op=='prediction':return ev.record_prediction(plan['scenario_id'],project,plan['response'],model_version=plan['model_version'],retrieval_version=plan.get('retrieval_version','operator-import'))
    if op=='freeze':return ev.freeze(plan['evaluation_id'],project,plan['scenario_ids'],approved=approved)
    if op=='evaluate':return ev.evaluate(plan['evaluation_id'],project,plan['prediction_ids'],scope=plan.get('scope','operator supplied independently reviewed cases'))
    if op=='export_training':return memory.export_training(project)
    if op=='validate_training':
        exported=load(plan['dataset'],8*1024*1024)
        current=memory.export_training(project)
        if exported.get('schema')!=current['schema'] or exported.get('project_id')!=project or exported.get('dataset_sha256')!=current['dataset_sha256'] or exported.get('examples')!=current['examples']:
            raise ValueError('training dataset is stale, revoked, modified or belongs to another project; regenerate it')
        return {'passed':True,'dataset_sha256':current['dataset_sha256'],'examples':len(current['examples']),'training_executed':False}
    if op=='overview':return memory.overview(project)
    if op=='dashboard':return {'html':dashboard(memory,project)}
    if op=='propose':return imp.propose(project,**plan['proposal'])
    if op=='promote':return imp.promote(project,plan['config_id'],approved=approved)
    if op=='rollback':return imp.rollback(project,approved=approved)
    if op=='enqueue':return jobs.enqueue(project,plan['scenario_id'],config=imp.active(project)['config'])
    if op in {'retry','cancel','recover'}:return jobs.change(project,plan['job_id'],op)
    if op=='run_job':
        if offline:raise PermissionError('offline learning commands cannot contact any model service')
        return jobs.run_one(project,plan['job_id'],client,model_version=model_version)
    raise ValueError('unknown learning operation')

def handle(args):
    from core.ai_plane.home import get
    from core.ai_plane.store import Store
    from core.ai_plane.proposals import Audit,ProposalGate
    home=get(getattr(args,'ai_home',None),create=True);store=Store(home.db_path)
    plan=load(args.ai_learning,1024*1024);audit=Audit(store,home);memory=ScenarioMemory(store,audit)
    try:
        client=None;model='unavailable'
        if plan.get('operation')=='run_job' and not getattr(args,'offline',False):
            from core.llm_local import runtime_from_args
            runtime=runtime_from_args(args);client=runtime.client;model=runtime.model
        result=operate(memory,ProposalGate(store,home,audit),plan,approved=getattr(args,'approve_ai_learning',False),
            client=client,model_version=model,offline=getattr(args,'offline',False))
        target=getattr(args,'ai_learning_output',None)
        if target:
            path=Path(target).absolute()
            if path.is_symlink() or any(p.is_symlink() for p in path.parents):raise ValueError('linked output path refused')
            path.parent.mkdir(parents=True,exist_ok=True)
            content=result['html'] if plan['operation']=='dashboard' else json.dumps(result,indent=2)+'\n'
            # Never clobber an evidence file or an existing export.
            with path.open('x',encoding='utf-8') as f:f.write(content)
            path.chmod(0o600)
            print(json.dumps({'output':str(path),'status':'written'}))
        else:print(json.dumps(result,indent=2))
        return 0 if result.get('status') not in {'failed','cancelled','interrupted'} else 2
    finally:store.close()
