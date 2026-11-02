"""Reviewed project-scoped scenario memory in the existing AI-plane SQLite store.

Records/reviewer labels are advisory data, never proof capabilities. No file,
network, shell, model or scanner execution is reachable from this module.
"""
from __future__ import annotations
import hashlib
import json
import re
import time
import uuid
from core.ai_plane.sanitizer import scrub, wrap_untrusted
from core.evidence_redaction import redact_text
from core.research_input import loads
from core.version import VERSION

DDL = [
'''CREATE TABLE IF NOT EXISTS scenarios(
 scenario_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, run_id TEXT NOT NULL,
 split TEXT NOT NULL, vulnerability_class TEXT NOT NULL, content_sha256 TEXT NOT NULL,
 record_json TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
 created_at REAL NOT NULL, updated_at REAL NOT NULL)''',
'CREATE INDEX IF NOT EXISTS ix_scenario_project ON scenarios(project_id,state,split)',
'''CREATE TABLE IF NOT EXISTS scenario_reviews(
 id INTEGER PRIMARY KEY, scenario_id TEXT NOT NULL REFERENCES scenarios(scenario_id),
 content_sha256 TEXT NOT NULL, reviewer TEXT NOT NULL, technical_validity TEXT NOT NULL,
 decision TEXT NOT NULL, review_json TEXT NOT NULL, created_at REAL NOT NULL)''',
'''CREATE TABLE IF NOT EXISTS learning_predictions(
 prediction_id TEXT PRIMARY KEY, scenario_id TEXT NOT NULL REFERENCES scenarios(scenario_id),
 content_sha256 TEXT NOT NULL, model_version TEXT NOT NULL, retrieval_version TEXT NOT NULL,
 response_json TEXT NOT NULL, created_at REAL NOT NULL)''',
'''CREATE TABLE IF NOT EXISTS learning_evaluations(
 evaluation_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, manifest_json TEXT NOT NULL,
 report_json TEXT, created_at REAL NOT NULL)''',
'''CREATE TABLE IF NOT EXISTS learning_configs(
 config_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, proposal_uid TEXT NOT NULL,
 config_json TEXT NOT NULL, state TEXT NOT NULL, evaluation_id TEXT NOT NULL,
 prior_config_id TEXT, created_at REAL NOT NULL)''',
'''CREATE TABLE IF NOT EXISTS learning_jobs(
 job_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, operation TEXT NOT NULL,
 status TEXT NOT NULL, detail_json TEXT NOT NULL, attempts INTEGER NOT NULL,
 created_at REAL NOT NULL, updated_at REAL NOT NULL)''',
"CREATE UNIQUE INDEX IF NOT EXISTS ux_single_learning_worker ON learning_jobs(status) WHERE status='running'",
]
SPLITS = {'train','validation','test','regression','adversarial'}
VALIDITY = {'confirmed','refuted','inconclusive'}
OUTCOMES = {'accepted','duplicate','informative','rejected','not-applicable','out-of-scope','pending','unsubmitted'}
ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}')
POISON = re.compile(r'ignore (?:all |the |any )?(?:previous|prior|system) instructions|reveal (?:the )?system prompt|<\|(?:system|im_start)\|>|override (?:the )?(?:scope|proof|safety)|execute (?:this )?(?:shell|command)', re.I)
REQUIRED = {'scenario_id','run_id','project_id','scope_reference','vulnerability_class','observation_summary',
            'test_objective','evidence','root_cause_id','source_license','permission_reference','reuse_approved','split'}
TEXT_FIELDS = {'target_category','test_environment','affected_component','entry_point','prerequisites',
 'observation_summary','test_objective','verification_method','proof_status','false_positive_reason',
 'missed_detection_reason','root_cause_category','safe_reproduction_reference','remediation_summary',
 'model_recommendation','uncertainty','technology','input_type','sink_type','auth_context','dataflow_pattern',
 'control_failure','limitations','timestamp','model_version','retrieval_version'}
OPTIONAL = TEXT_FIELDS | {'cwe','owasp','negative_control_ids','data_sensitivity','training_allowed',
 'shared','expires_at','fixture_id','version_family','source_fingerprints'}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',',':'), ensure_ascii=False, allow_nan=False)

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def identity(value):
    if not isinstance(value,str) or not ID_RE.fullmatch(value) or redact_text(value) != value:
        raise ValueError('bounded non-sensitive identity required')
    return value

def text(value, maximum=4000):
    if not isinstance(value,str) or len(value.encode()) > maximum or '\x00' in value:
        raise ValueError('bounded UTF-8 text required')
    return scrub(redact_text(value), limit=maximum)

def _items(value, maximum=30):
    if not isinstance(value,list) or len(value)>maximum or any(not isinstance(v,str) for v in value):
        raise ValueError('bounded text list required')
    return [text(v,300) for v in value]

def normalize(record):
    if not isinstance(record,dict) or len(canonical(record).encode())>64000:
        raise ValueError('bounded scenario object required')
    if REQUIRED-record.keys() or record.keys()-(REQUIRED|OPTIONAL):
        raise ValueError('scenario fields missing or unknown; imported review/authority flags forbidden')
    result={k:identity(record[k]) for k in ('scenario_id','run_id','project_id','vulnerability_class','root_cause_id')}
    if record['split'] not in SPLITS:raise ValueError('explicit dataset split required')
    result['split']=record['split']
    for name in ('scope_reference','source_license','permission_reference'):
        result[name]=text(record[name],500)
        if not result[name].strip() or result[name].upper() in {'UNKNOWN','TODO','NOASSERTION'}:
            raise ValueError('explicit scope, license and processing-permission references required')
    for name in TEXT_FIELDS:
        result[name]=text(record.get(name,''))
    for name in ('reuse_approved','training_allowed','shared'):
        value=record.get(name,False)
        if type(value) is not bool:raise ValueError('explicit permission boolean required')
        result[name]=value
    sensitivity=record.get('data_sensitivity','sanitized')
    if sensitivity not in {'sanitized','public'}:raise ValueError('raw/private sensitive scenario ingestion refused')
    result['data_sensitivity']=sensitivity
    if result['shared'] and sensitivity!='public':raise ValueError('only explicitly public cases may be shared')
    expires=record.get('expires_at',0)
    if type(expires) not in (int,float) or not 0<=expires<=32503680000:raise ValueError('invalid retention deadline')
    result['expires_at']=expires
    for name in ('cwe','owasp','negative_control_ids','source_fingerprints'):
        result[name]=_items(record.get(name,[]))
    for name in ('fixture_id','version_family'):
        result[name]=identity(record[name]) if record.get(name) else ''
    refs=record['evidence']
    if not isinstance(refs,list) or not 1<=len(refs)<=30:raise ValueError('1–30 sanitized evidence references required')
    result['evidence']=[];seen=set()
    for ref in refs:
        if not isinstance(ref,dict) or set(ref)!={'id','sha256','summary','kind'}:raise ValueError('evidence metadata only; paths/raw bodies forbidden')
        eid=identity(ref['id'])
        if eid in seen or not isinstance(ref['sha256'],str) or not re.fullmatch('[a-f0-9]{64}',ref['sha256']):
            raise ValueError('unique evidence id and SHA-256 required')
        seen.add(eid)
        result['evidence'].append({'id':eid,'sha256':ref['sha256'],'summary':text(ref['summary'],3000),'kind':identity(ref['kind'])})
    if not set(result['negative_control_ids'])<=seen:raise ValueError('unknown negative control evidence reference')
    result['schema']='tbhm.scenario/1';result['tool_version']=VERSION
    return result

class ScenarioMemory:
    def __init__(self, store, audit=None):self.store,self.audit=store,audit

    def _audit(self,action,subject,detail):
        if self.audit:self.audit.record('scenario.'+action,subject,detail)

    def ingest(self,record):
        clean=normalize(record);sid=clean['scenario_id'];sha=digest(clean)
        old=self.store.one('SELECT content_sha256,state FROM scenarios WHERE scenario_id=?',(sid,))
        if old:
            if old['content_sha256']!=sha:raise ValueError('scenario identity conflict; use a new versioned identity')
            return {'scenario_id':sid,'content_sha256':sha,'state':old['state'],'duplicate':True}
        # The detector is a quarantine heuristic; structural boundaries do not
        # depend on recognizing every possible malicious instruction.
        state='quarantined' if POISON.search(canonical(clean)) else 'pending'
        now=time.time()
        self.store.conn.execute('INSERT INTO scenarios VALUES(?,?,?,?,?,?,?,?,?,?)',
         (sid,clean['project_id'],clean['run_id'],clean['split'],clean['vulnerability_class'],sha,canonical(clean),state,now,now))
        self.store.conn.commit();self._audit('ingest',sid,{'sha256':sha,'state':state})
        return {'scenario_id':sid,'content_sha256':sha,'state':state,'duplicate':False}

    def get(self,sid,project):
        row=self.store.one('SELECT * FROM scenarios WHERE scenario_id=? AND project_id=?',(identity(sid),identity(project)))
        if not row:raise ValueError('scenario unavailable in this project')
        out=dict(row);out['record']=loads(out.pop('record_json'))
        if digest(out['record'])!=out['content_sha256']:raise ValueError('scenario integrity mismatch')
        reviews=self.store.query('SELECT review_json FROM scenario_reviews WHERE scenario_id=? ORDER BY id DESC LIMIT 1',(sid,))
        out['review']=loads(reviews[0]['review_json']) if reviews else None
        return out

    def review(self,sid,project,*,expected_sha256,reviewer,technical_validity,decision,note,evidence_ids,
               program_outcome='pending',approved=False):
        if approved is not True:raise PermissionError('explicit operator review approval required')
        row=self.get(sid,project);r=row['record']
        if row['state'] in {'revoked','quarantined'}:raise ValueError('revoked/quarantined records cannot be promoted')
        if expected_sha256!=row['content_sha256']:raise ValueError('review must bind to current sanitized scenario hash')
        if technical_validity not in VALIDITY or decision not in {'accepted','rejected'} or program_outcome not in OUTCOMES:
            raise ValueError('independent technical label, reviewer decision and program outcome required')
        reviewer=identity(reviewer);note=text(note,2000)
        if not note.strip():raise ValueError('review explanation required')
        ids=[identity(i) for i in _items(evidence_ids)]
        if not ids or not set(ids)<={e['id'] for e in r['evidence']}:raise ValueError('review needs supplied evidence IDs')
        previous=self.store.query("SELECT technical_validity FROM scenario_reviews WHERE scenario_id=? AND decision='accepted'",(sid,))
        conflict=any(v['technical_validity']!=technical_validity for v in previous) and decision=='accepted'
        review={'reviewer':reviewer,'technical_validity':technical_validity,'decision':decision,'note':note,
                'evidence_ids':ids,'program_outcome':program_outcome,'content_sha256':expected_sha256}
        state='quarantined' if conflict else 'reviewed' if decision=='accepted' else 'rejected'
        with self.store.conn:
            self.store.conn.execute('INSERT INTO scenario_reviews(scenario_id,content_sha256,reviewer,technical_validity,decision,review_json,created_at) VALUES(?,?,?,?,?,?,?)',
             (sid,expected_sha256,reviewer,technical_validity,decision,canonical(review),time.time()))
            self.store.conn.execute('UPDATE scenarios SET state=?,updated_at=? WHERE scenario_id=?',(state,time.time(),sid))
        self._audit('review',sid,{'state':state,'review_sha256':digest(review)})
        return {'scenario_id':sid,'state':state,'review':review,'proof_authority':False}

    def revoke(self,sid,project,*,approved=False):
        if approved is not True:raise PermissionError('operator approval required')
        self.get(sid,project)
        with self.store.conn:self.store.conn.execute("UPDATE scenarios SET state='revoked',updated_at=? WHERE scenario_id=?",(time.time(),sid))
        self._audit('revoke',sid,{})
        return {'scenario_id':sid,'state':'revoked','derived_manifests_invalidated':True,
                'note':'Regeneration rechecks every source. Previously exported operator copies must be withdrawn separately.'}

    @staticmethod
    def eligible(row,*,training=False):
        r=row['record']
        return (row['state']=='reviewed' and r['reuse_approved'] and
         (not r['expires_at'] or r['expires_at']>time.time()) and row['review'] and row['review']['decision']=='accepted' and
         (not training or (r['training_allowed'] and row['split']=='train' and row['review']['technical_validity'] in {'confirmed','refuted'})))

    def retrieve(self,project,query,*,vulnerability_class='',k=5,max_chars=10000,feedback=True):
        identity(project);query=text(query,2000)
        if type(k) is not int or not 1<=k<=10 or type(max_chars) is not int or not 500<=max_chars<=16000:raise ValueError('retrieval budget exceeded')
        if vulnerability_class:identity(vulnerability_class)
        rows=self.store.query("SELECT scenario_id,project_id FROM scenarios WHERE state='reviewed' AND split='train' AND (project_id=? OR json_extract(record_json,'$.shared')=1) ORDER BY scenario_id LIMIT 2001",(project,))
        if len(rows)>2000:raise ValueError('retrieval candidate budget exceeded; narrow the project corpus')
        tokens=set(re.findall(r'[a-z0-9_]+',query.lower()));ranked=[]
        for item in rows:
            row=self.get(item['scenario_id'],item['project_id']);r=row['record']
            if not self.eligible(row) or (item['project_id']!=project and not (r['shared'] and r['data_sensitivity']=='public')):continue
            if vulnerability_class and r['vulnerability_class']!=vulnerability_class:continue
            hay=' '.join(r.get(f,'') for f in ('observation_summary','test_objective','technology','input_type','sink_type','control_failure','root_cause_category'))
            overlap=len(tokens & set(re.findall(r'[a-z0-9_]+',hay.lower())))
            if not overlap:continue
            score=overlap
            if feedback and (r['false_positive_reason'] or r['missed_detection_reason']):score+=2
            ranked.append((score,row))
        hits=[];used=0
        for score,row in sorted(ranked,key=lambda v:(-v[0],v[1]['scenario_id']))[:k]:
            r=row['record']
            hit={'scenario_id':row['scenario_id'],'project_id':row['project_id'],'content_sha256':row['content_sha256'],
                 'technical_validity':row['review']['technical_validity'],'program_outcome':row['review']['program_outcome'],
                 'evidence_ids':[e['id'] for e in r['evidence']],'observation':r['observation_summary'],
                 'previous_mistake':r['false_positive_reason'] or r['missed_detection_reason'],
                 'missing_controls':r['control_failure'],'verification_method':r['verification_method'],
                 'limitations':r['limitations'],'permission_reference':r['permission_reference'],'score':score}
            n=len(canonical(hit))
            if used+n>max_chars:continue
            used+=n;hits.append(hit)
        return {'schema':'tbhm.scenario-retrieval/1','retrieval_version':'scenario-lexical-feedback-v1' if feedback else 'scenario-lexical-v1',
                'project_id':project,'hits':hits,'chars':used,'non_authoritative':True,'unresolved_is_clean':False}

    def context(self,*args,**kwargs):return wrap_untrusted(canonical(self.retrieve(*args,**kwargs)),'T3')

    def export_training(self,project):
        rows=self.store.query('SELECT scenario_id FROM scenarios WHERE project_id=? ORDER BY scenario_id LIMIT 2001',(identity(project),))
        if len(rows)>2000:raise ValueError('dataset budget exceeded')
        selected=[self.get(row['scenario_id'],project) for row in rows]
        from core.ai_plane.self_evaluation import check_leakage
        allrows=self.store.query('SELECT scenario_id,project_id FROM scenarios LIMIT 2001')
        check_leakage([self.get(r['scenario_id'],r['project_id']) for r in allrows])
        examples=[]
        for row in selected:
            if not self.eligible(row,training=True):continue
            r=row['record']
            examples.append({'scenario_id':row['scenario_id'],'source_sha256':row['content_sha256'],
             'review_sha256':digest(row['review']),'source_license':r['source_license'],'permission_reference':r['permission_reference'],
             'input':{'observation':r['observation_summary'],'evidence':r['evidence'],'objective':r['test_objective']},
             'output':{'technical_validity':row['review']['technical_validity'],'explanation':row['review']['note'],
                       'evidence_ids':row['review']['evidence_ids'],'remediation':r['remediation_summary']}})
        return {'schema':'tbhm.reviewed-training-data/1','project_id':project,'examples':examples,'dataset_sha256':digest(examples),
                'training_executed':False,'rights_independently_verified':False,'revalidate_before_use':True}

    def overview(self,project):
        identity(project)
        counts={r['state']:r['n'] for r in self.store.query('SELECT state,COUNT(*) AS n FROM scenarios WHERE project_id=? GROUP BY state',(project,))}
        outcomes={r['technical_validity']:r['n'] for r in self.store.query("SELECT r.technical_validity,COUNT(*) AS n FROM scenario_reviews r JOIN scenarios s ON s.scenario_id=r.scenario_id WHERE s.project_id=? AND s.state='reviewed' AND r.id=(SELECT MAX(id) FROM scenario_reviews WHERE scenario_id=s.scenario_id) GROUP BY r.technical_validity",(project,))}
        last=self.store.one('SELECT evaluation_id,report_json FROM learning_evaluations WHERE project_id=? AND report_json IS NOT NULL ORDER BY created_at DESC LIMIT 1',(project,))
        configs=[dict(r) for r in self.store.query('SELECT config_id,state,prior_config_id FROM learning_configs WHERE project_id=? ORDER BY created_at DESC LIMIT 20',(project,))]
        jobs=[dict(r) for r in self.store.query("SELECT job_id,operation,status,attempts FROM learning_jobs WHERE project_id=? ORDER BY created_at DESC LIMIT 20",(project,))]
        return {'schema':'tbhm.learning-overview/1','project_id':project,'states':counts,'reviewed_outcomes':outcomes,
          'last_evaluation':loads(last['report_json']) if last else None,'configs':configs,'jobs':jobs,
          'model_effectiveness':'UNVERIFIED unless a report explicitly identifies a real model run','non_authoritative':True}
