"""Small durable bounded queue; optional model failures never change a scan."""
import os
import shutil
import time
import uuid
from core.ai_plane.scenarios import canonical,identity,digest
from core.ai_plane.self_evaluation import Evaluator,SYSTEM
from core.ai_plane.improvement import configuration,DEFAULT
from core.research_input import loads

class LearningJobs:
    def __init__(self,memory):self.memory=memory;self.store=memory.store

    def enqueue(self,project,sid,*,config=None):
        identity(project);self.memory.get(sid,project);config=configuration(config or DEFAULT)
        n=self.store.one("SELECT COUNT(*) AS n FROM learning_jobs WHERE project_id=? AND status IN ('pending','running')",(project,))['n']
        if n>=32:raise ValueError('learning queue full; finish or cancel existing jobs')
        job='job-'+uuid.uuid4().hex;now=time.time()
        self.store.conn.execute('INSERT INTO learning_jobs VALUES(?,?,?,?,?,?,?,?)',
          (job,project,'analyze','pending',canonical({'scenario_id':sid,'config':config}),0,now,now))
        self.store.conn.commit();return {'job_id':job,'status':'pending'}

    def change(self,project,job,action):
        row=self.store.one('SELECT * FROM learning_jobs WHERE job_id=? AND project_id=?',(identity(job),identity(project)))
        if not row:raise ValueError('job unavailable')
        status=row['status']
        if action=='retry':
            if status not in {'failed','cancelled','interrupted'} or row['attempts']>=3:raise ValueError('job not retryable')
            n=self.store.one("SELECT COUNT(*) AS n FROM learning_jobs WHERE project_id=? AND status IN ('pending','running')",(project,))['n']
            if n>=32:raise ValueError('learning queue full')
            status='pending'
        elif action=='cancel':
            if status=='running':raise ValueError('running worker cancellation requires its cancellation event')
            if status!='pending':raise ValueError('only pending jobs can be cancelled')
            status='cancelled'
        elif action=='recover':
            if status!='running':raise ValueError('only an abandoned running job can be marked interrupted')
            status='interrupted'
        else:raise ValueError('unknown job action')
        self.store.conn.execute('UPDATE learning_jobs SET status=?,updated_at=? WHERE job_id=?',(status,time.time(),job));self.store.conn.commit()
        return {'job_id':job,'status':status}

    def run_one(self,project,job,client,*,model_version,cancel=None):
        row=self.store.one('SELECT * FROM learning_jobs WHERE job_id=? AND project_id=?',(identity(job),identity(project)))
        if not row or row['status']!='pending':raise ValueError('pending project job required')
        start=time.perf_counter();detail=loads(row['detail_json']);status='failed';prediction=None
        cur=self.store.conn.execute("UPDATE learning_jobs SET status='running',attempts=attempts+1,updated_at=? WHERE job_id=? AND status='pending'",(time.time(),job));self.store.conn.commit()
        if cur.rowcount!=1:raise ValueError('job already claimed')
        try:
            if cancel is not None and cancel.is_set():status='cancelled';raise RuntimeError('cancelled before inference')
            import psutil
            if psutil.virtual_memory().available<256*1024*1024 or shutil.disk_usage(self.store.path.parent).free<64*1024*1024 or len(psutil.pids())>2048:raise RuntimeError('resource budget unavailable; retry deliberately')
            if not client or not client.available()[0]:raise RuntimeError('optional model unavailable; scanner operation unaffected')
            config=configuration(detail['config']);evaluator=Evaluator(self.memory)
            context_size=getattr(getattr(client,'config',None),'context',8192)
            context_budget=max(1500,min(16000,(int(context_size)-700)*3))
            context=evaluator.prompt(detail['scenario_id'],project,retrieval=True,feedback=config['feedback'],
                k=config['k'],history_chars=config['max_chars'],max_context_chars=context_budget)
            context['configuration_sha256']=digest(config)
            response=client.chat_json(SYSTEM,canonical(context))
            if cancel is not None and cancel.is_set():status='cancelled';raise RuntimeError('cancelled; model result discarded')
            prediction=evaluator.record_prediction(detail['scenario_id'],project,response,model_version=model_version,
                retrieval_version=context['history']['retrieval_version'],context=context,latency_ms=(time.perf_counter()-start)*1000,
                peak_ram_bytes=__import__('resource').getrusage(__import__('resource').RUSAGE_SELF).ru_maxrss*1024)
            # Link exact configuration to the stored prediction (not model data).
            prow=self.store.one('SELECT response_json FROM learning_predictions WHERE prediction_id=?',(prediction['prediction_id'],))
            payload=loads(prow['response_json']);payload['configuration_sha256']=digest(config)
            self.store.conn.execute('UPDATE learning_predictions SET response_json=? WHERE prediction_id=?',(canonical(payload),prediction['prediction_id']))
            detail.update(prediction_id=prediction['prediction_id'],configuration_sha256=digest(config));status='completed'
        except Exception as exc:
            from core.ai_plane.scenarios import text
            detail['error']=text(str(exc),2000)
        finally:
            detail['elapsed_ms']=(time.perf_counter()-start)*1000
            self.store.conn.execute('UPDATE learning_jobs SET status=?,detail_json=?,updated_at=? WHERE job_id=?',
              (status,canonical(detail),time.time(),job));self.store.conn.commit()
        return {'job_id':job,'status':status,**detail}
