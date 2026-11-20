"""Explicit B1 API; no inference CLI, startup or automatically enabled provider."""
from pathlib import Path
import time
from talos.readiness.agent import control
from talos.pilot.contracts import ModelPlan
from talos.pilot.backend import LocalModelBackend,ProtocolReplayBackend
from talos.pilot.mlx_backend import MLXModelBackend,MLXReplayBackend
from talos.research.recorder import Recorder


def execute(plan:ModelPlan,backend,archive:Path):
    plan=ModelPlan.model_validate(plan.model_dump())
    if type(backend) not in (LocalModelBackend,ProtocolReplayBackend,MLXModelBackend,MLXReplayBackend):raise TypeError('explicit known backend required')
    before=backend.budget_for(plan.limits).snapshot()
    with Recorder(archive,create=True) as recorder:
        recorder.append('model_manifest',{'plan':plan.model_dump(mode='json'),'plan_sha256':plan.digest(),
            'execution_basis':'local_model_DEV' if backend.is_live else 'software_protocol_fixture_not_empirical',
            'primary_eligible':False,'approval_scope':backend.scope.model_dump(mode='json') if backend.is_live else None,'budget_before':before})
        recorder.append('model_intent',{'plan_sha256':plan.digest(),'model_calls_authorized_by_manifest':False})
        start=time.monotonic_ns();result=None;error=None
        try:result=control(plan,backend=backend)
        except Exception as failure:error=type(failure).__name__
        finally:
            cancellation=backend.close()
        elapsed=(time.monotonic_ns()-start+999999)//1000000
        if backend.budget is not None:backend.budget.used['elapsed_ms']=before['used']['elapsed_ms']+elapsed
        if backend.budget is not None and backend.budget.used['elapsed_ms']>plan.limits.amounts['elapsed_ms']:
            backend.budget.stop_reason='whole conversation elapsed ceiling exceeded; no further calls'
        if result:
            if backend.budget is not None and backend.budget.stop_reason:result['budget']=backend.budget.snapshot()
            result['budget']['used']['elapsed_ms']=before['used']['elapsed_ms']+elapsed;result['budget']['known_usage_lower_bound']['elapsed_ms']=before['used']['elapsed_ms']+elapsed
            if backend.budget is not None:backend.budget.used['elapsed_ms']=before['used']['elapsed_ms']+elapsed
        value={'control':result,'failure_class':error,'elapsed_ms':elapsed,'protocol_receipts':backend.receipts,
            'budget':result['budget'] if result else (backend.budget.snapshot() if backend.budget else None),
            'cancellation':cancellation,'MLX_batch':backend.batch.snapshot() if isinstance(backend,MLXReplayBackend) else None,'independent_primary_findings':None,'unified_outcome':'UNKNOWN',
            'actual_cost_microunits':None,'actual_provider_usage':backend.receipts if backend.is_live else None}
        recorder.append('model_result',value)
        recorder.append('model_summary',{'planned':1,'recorded':1,'unknown':1,'primary_findings':None,
            'state':'FAILED' if error else result['state'],'pr09_experimental_complete':False})
        return recorder.seal()
