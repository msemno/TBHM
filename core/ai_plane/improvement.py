"""Comparative, operator-approved retrieval configuration promotion and rollback.

The only deployable objects here are bounded retrieval settings. Source, proof,
scanner policy and model weights have no mutation interface in this module.
"""
import time
import uuid
from core.ai_plane.scenarios import canonical,digest,identity,text
from core.research_input import loads

DEFAULT={'feedback':False,'k':5,'max_chars':10000}

def configuration(value):
    if not isinstance(value,dict) or set(value)!=set(DEFAULT) or type(value['feedback']) is not bool or type(value['k']) is not int or not 1<=value['k']<=10 or type(value['max_chars']) is not int or not 500<=value['max_chars']<=10000:raise ValueError('only bounded retrieval configuration may be promoted')
    return dict(value)

class Improvements:
    def __init__(self,memory,gate):self.memory=memory;self.store=memory.store;self.gate=gate

    def active(self,project):
        row=self.store.one("SELECT config_id,config_json FROM learning_configs WHERE project_id=? AND state='active'",(identity(project),))
        return {'config_id':row['config_id'] if row else 'baseline','config':loads(row['config_json']) if row else dict(DEFAULT)}

    def _report(self,eid,project):
        row=self.store.one('SELECT manifest_json,report_json FROM learning_evaluations WHERE evaluation_id=? AND project_id=?',(identity(eid),identity(project)))
        if not row or not row['report_json']:raise ValueError('completed independent evaluation required')
        manifest=loads(row['manifest_json'])
        for case in manifest['cases']:
            current=self.memory.get(case['scenario_id'],project)
            if not self.memory.eligible(current) or current['content_sha256']!=case['content_sha256'] or digest(current['review'])!=case['review_sha256']:raise ValueError('evaluation invalidated by source revocation or review change')
        return loads(row['report_json'])

    def compare(self,project,baseline,candidate):
        b,c=(self._report(i,project) for i in (baseline,candidate))
        reasons=[]
        if baseline==candidate or b['dataset_sha256']!=c['dataset_sha256']:reasons.append('same frozen dataset and distinct experiments required')
        if c['invalid_citations'] or c['failure_examples']:reasons.append('candidate fabricated evidence or invalid response')
        if c['missing_predictions']>b['missing_predictions']:reasons.append('missing prediction regression')
        if c['abstention_rate']>b['abstention_rate']:reasons.append('abstention regression')
        old={(r['stage'],r['class']):r for r in b['metrics']['by_stage_class']};new={(r['stage'],r['class']):r for r in c['metrics']['by_stage_class']}
        improved=False
        if not old or set(old)!=set(new):reasons.append('matching nonempty labeled tasks required')
        for key,r in old.items():
            n=new.get(key)
            if not n:continue
            if n['FP']>r['FP'] or n['FN']+n['inconclusive_positive']>r['FN']+r['inconclusive_positive'] or n['prediction_coverage']<r['prediction_coverage']:reasons.append('classification or coverage regression: '+key[1])
            improved |= n['TP']>r['TP'] or n['TN']>r['TN'] or n['FP']<r['FP'] or n['FN']<r['FN']
        if c['evidence_citation_validity'] is None or c['evidence_citation_validity']<1:reasons.append('candidate evidence citation validation incomplete')
        if not improved:reasons.append('no measured predictive improvement on this dataset')
        if c['peak_ram_bytes'] is not None and c['peak_ram_bytes']>512*1024*1024:reasons.append('learning worker RAM budget exceeded')
        return {'passed':not reasons,'reasons':reasons,'baseline':baseline,'candidate':candidate,
         'dataset_sha256':c['dataset_sha256'],'scope':c['scope'],'security_policy_changed':False}

    def propose(self,project,*,config,baseline,candidate,scenario_ids,problem):
        problem=text(problem,4000)
        config=configuration(config);comparison=self.compare(project,baseline,candidate)
        if not comparison['passed']:raise ValueError('improvement rejected: '+canonical(comparison['reasons']))
        if self._report(baseline,project).get('configuration_sha256')!=digest(self.active(project)['config']):
            raise ValueError('comparison baseline must match the currently active retrieval configuration')
        support=[]
        for sid in scenario_ids:
            row=self.memory.get(sid,project)
            if not self.memory.eligible(row):raise ValueError('reviewed supporting scenarios required')
            support.append({'scenario_id':sid,'content_sha256':row['content_sha256'],'evidence_ids':[e['id'] for e in row['record']['evidence']]})
        if not support:raise ValueError('supporting scenarios required')
        # A measured experiment must identify the exact candidate config. The
        # CLI evaluation attaches config_sha256 from its prediction job lineage.
        report=self._report(candidate,project)
        if report.get('configuration_sha256')!=digest(config):raise ValueError('candidate configuration is not bound to evaluated predictions')
        proposal=self.gate.create(problem=problem,evidence=[{'comparison':comparison,'support':support,'config':config,
          'root_cause_hypothesis':'Reviewed mistake-aware ranking improves relevant prior-case selection.',
          'regression_tests':['split isolation','fabricated citations','proof authority unchanged'],
          'success_criteria':'same denominator; no FP/FN/coverage regressions; valid citations; measured improvement',
          'rollback_plan':'restore previous validated retrieval configuration'}],
          affected_files=['AI-plane retrieval configuration'],expected_benefit='Measured advisory improvement on the frozen labeled scope.',
          risks=['Dataset-limited evidence; real-model and field effectiveness require their own evaluations.'])
        cid='config-'+uuid.uuid4().hex
        self.store.conn.execute('INSERT INTO learning_configs VALUES(?,?,?,?,?,?,?,?)',
          (cid,project,proposal['proposal_id'],canonical(config),'candidate',candidate,self.active(project)['config_id'],time.time()))
        self.store.conn.commit();return {'config_id':cid,'proposal_id':proposal['proposal_id'],'comparison':comparison}

    def promote(self,project,cid,*,approved=False):
        if approved is not True:raise PermissionError('explicit operator approval required')
        row=self.store.one("SELECT * FROM learning_configs WHERE config_id=? AND project_id=? AND state='candidate'",(identity(cid),identity(project)))
        if not row:raise ValueError('candidate unavailable')
        proposal=self.store.one("SELECT status,evidence_json FROM change_proposals WHERE proposal_uid=?",(row['proposal_uid'],))
        if not proposal or proposal['status']!='accepted':raise PermissionError('existing proposal approval required before promotion')
        evidence=loads(proposal['evidence_json'])[0];cmp=evidence['comparison']
        if loads(row['config_json'])!=evidence['config'] or not self.compare(project,cmp['baseline'],cmp['candidate'])['passed']:raise ValueError('stale or tampered candidate')
        active=self.active(project)['config_id']
        if active!=row['prior_config_id']:raise ValueError('active baseline changed; evaluate again')
        with self.store.conn:
            self.store.conn.execute("UPDATE learning_configs SET state='retired' WHERE project_id=? AND state='active'",(project,))
            self.store.conn.execute("UPDATE learning_configs SET state='active' WHERE config_id=?",(cid,))
        self.memory._audit('promote',cid,{'previous':active});return self.active(project)

    def rollback(self,project,*,approved=False):
        if approved is not True:raise PermissionError('explicit operator approval required')
        current=self.active(project)
        if current['config_id']=='baseline':raise ValueError('already at baseline')
        row=self.store.one('SELECT prior_config_id FROM learning_configs WHERE config_id=?',(current['config_id'],))
        previous=row['prior_config_id']
        with self.store.conn:
            self.store.conn.execute("UPDATE learning_configs SET state='rolled_back' WHERE config_id=?",(current['config_id'],))
            if previous!='baseline':self.store.conn.execute("UPDATE learning_configs SET state='active' WHERE config_id=? AND project_id=?",(previous,project))
        self.memory._audit('rollback',current['config_id'],{'restored':previous});return self.active(project)
