"""Data-only scheduler test double: no target/tool/provider/observer capability."""
from typing import Literal
from pydantic import Field,StrictInt,StrictBool,model_validator
from talos.corpus.models import Model
from talos.ablation.contracts import PublicFeedback
from talos.research.contracts import DIMENSIONS


class Reply(Model):
    status: Literal['completed','failed','timed_out','unsupported','unknown']='completed'
    feedback: PublicFeedback | None=None
    usage: dict[str,StrictInt|None]
    reset_healthy: StrictBool=True
    utility_success: StrictBool|None=None
    basis: Literal['simulated_scheduler_values_not_attack_results']='simulated_scheduler_values_not_attack_results'

    @model_validator(mode='after')
    def measurements(self):
        if not set(self.usage)<=DIMENSIONS or any(v is not None and v<0 for v in self.usage.values()):
            raise ValueError('invalid simulated resource accounting')
        if self.status!='completed' and self.feedback is not None:
            raise ValueError('unfinished attempt cannot supply completed feedback')
        if self.usage.get('attempts')!=1: raise ValueError('one dispatched simulated attempt required')
        return self


class Script(Model):
    schema_version: Literal['talos.scheduler-test-script.v1']='talos.scheduler-test-script.v1'
    replies: dict[str,Reply] # public opportunity IDs only, never arm-specific keys
    reservation: dict[str,StrictInt]
    origin: Literal['data_only_scheduler_test_double']='data_only_scheduler_test_double'

    @model_validator(mode='after')
    def ceilings(self):
        if not set(self.reservation)<=DIMENSIONS or any(v<0 for v in self.reservation.values()):
            raise ValueError('invalid common reservation')
        if self.reservation.get('attempts')!=1: raise ValueError('reserve one attempt before dispatch')
        if 'elapsed_ms' in self.reservation: raise ValueError('harness measures/reserves elapsed overhead, not script')
        return self


class Session:
    """Fresh session per arm/block. Reset generation before each synthetic dispatch."""
    def __init__(self,script:Script):
        self.script=Script.model_validate(script.model_dump());self.generation=0;self.scopes=set()

    def reset(self,scope,opportunity_id):
        if scope in self.scopes: raise ValueError('reset scope reused')
        self.scopes.add(scope);self.generation+=1
        reply=self.script.replies[opportunity_id]
        return {'scope':scope,'generation':self.generation,'healthy':reply.reset_healthy,'source':'scheduler_test_double_only'}

    def dispatch(self,opportunity_id):
        return Reply.model_validate(self.script.replies[opportunity_id].model_dump())
