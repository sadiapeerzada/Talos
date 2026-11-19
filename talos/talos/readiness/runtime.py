"""Hard process cancellation for offline controls, sealed Stage A recording."""
from pathlib import Path
import json,os,signal,subprocess,sys,tempfile,time
from talos.corpus.models import content_hash
from talos.readiness.contracts import EngineeringPlan
from talos.readiness.gates import report
from talos.research.recorder import Recorder


def worker_environment():
    return {'LANG':'C.UTF-8','PYTHONHASHSEED':'0','LANGSMITH_TRACING':'false','OTEL_SDK_DISABLED':'true',
        'HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1'}


def run_control(plan:EngineeringPlan):
    plan=EngineeringPlan.model_validate(plan.model_dump())
    if plan.limits.amounts['attempts']==0 or plan.limits.amounts['elapsed_ms']==0:
        return {'state':'BUDGET_STOP','reason':'No attempt/wall-time budget; no child started.','worker_pid':None,'worker_reaped':True,
            'elapsed_ms':0,'control':None,'usage_complete':True,'unified_outcome':'UNKNOWN','primary_eligible':False}
    worker=Path(__file__).with_name('worker.py').resolve();start=time.monotonic_ns()
    with tempfile.TemporaryDirectory(prefix='talos-agent-offline-') as directory:
        environment=worker_environment();environment['TMPDIR']=directory
        process=subprocess.Popen([sys.executable,'-I',str(worker)],cwd=directory,env=environment,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        try:
            stdout,stderr=process.communicate(plan.model_dump_json(),timeout=max(0,min(plan.hard_timeout_ms,plan.limits.amounts['elapsed_ms'])/1000-(time.monotonic_ns()-start)/1e9))
            elapsed=(time.monotonic_ns()-start+999999)//1000000
            if process.returncode or len(stdout)>2000000:raise ValueError('worker incomplete/oversized')
            result=json.loads(stdout)
            if 'worker_failure' in result:
                return {'state':'FAILED','reason':'Offline child failed; no retry or success inference.',
                    'worker_failure':result['worker_failure'],'worker_pid':process.pid,'worker_reaped':process.poll() is not None,
                    'elapsed_ms':elapsed,'control':None,'usage_complete':False,'unified_outcome':'UNKNOWN','primary_eligible':False}
            result['budget']['used']['elapsed_ms']=int(elapsed)
            result['budget']['known_usage_lower_bound']['elapsed_ms']=int(elapsed)
            if elapsed>plan.limits.amounts['elapsed_ms']:
                result['budget']['stop_reason']='Whole-worker elapsed exceeded ceiling; no further calls'
            return {'state':'RECORDED','reason':'Offline engineering only.','worker_pid':process.pid,'worker_reaped':process.poll() is not None,
                'elapsed_ms':elapsed,'control':result,'usage_complete':True,'unified_outcome':'UNKNOWN','primary_eligible':False}
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL);process.communicate()
            return {'state':'HARD_TIMEOUT','reason':'Isolated process group killed and reaped; partial state/evidence unavailable.',
                'worker_pid':process.pid,'worker_reaped':process.poll() is not None,
                'elapsed_ms':(time.monotonic_ns()-start+999999)//1000000,'control':None,'usage_complete':False,
                'unified_outcome':'UNKNOWN','primary_eligible':False}
        except BaseException:
            if process.poll() is None:os.killpg(process.pid,signal.SIGKILL)
            process.communicate();raise


def execute(plan:EngineeringPlan,archive:Path):
    plan=EngineeringPlan.model_validate(plan.model_dump())
    with Recorder(Path(archive),create=True) as recorder:
        recorder.append('readiness_manifest',{'plan':plan.model_dump(mode='json'),'plan_sha256':plan.digest(),'readiness':report()})
        recorder.append('agent_intent',{'identity':plan.identity.model_dump(mode='json'),'execution':'offline_scripted_control'})
        result=run_control(plan)
        recorder.append('agent_result',result)
        summary={'planned':1,'recorded':1,'unknown':1,'independent_primary_findings':None,
            'state':result['state'],'empirical_execution':'NO-GO','pr09_experimental_complete':False}
        recorder.append('readiness_summary',summary)
        return recorder.seal()
