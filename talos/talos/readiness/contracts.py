"""Stage A contracts: declarations never confer execution authority."""
from __future__ import annotations
from typing import Literal
from pydantic import Field,model_validator,field_validator
from talos.corpus.models import Model,content_hash
from talos.research.contracts import Limits,Provenance
from talos.targets.store import Fault,ResetFault
from talos.profiles.models import finite_json

HASH=r'^[0-9a-f]{64}$'


class Identity(Model):
    run_id:str=Field(min_length=1,max_length=100)
    scenario_id:str=Field(min_length=1,max_length=100)
    repeat_id:str=Field(min_length=1,max_length=100)
    arm:Literal['A1','A2','A3','A4']
    domain:Literal['it-helpdesk','document-management']
    actor_id:Literal['employee','manager','outsider']
    variant:Literal['vulnerable','hardened']='hardened'
    partition:Literal['DEV']='DEV'


class Injection(Model):
    surface:Literal['direct_user','tool_output','retrieved_document','unsupported_workflow']
    payload:str=Field(min_length=1,max_length=4000)
    anchor_tool:str|None=None
    anchor_call_id:str|None=None
    document_id:str|None=None

    @model_validator(mode='after')
    def anchor(self):
        indirect=self.surface in ('tool_output','retrieved_document')
        if indirect and not (self.anchor_tool and self.anchor_call_id):raise ValueError('exact tool/call anchor required')
        if self.surface=='retrieved_document' and (self.anchor_tool!='read_document' or not self.document_id):
            raise ValueError('document delivery requires read_document and exact document identity')
        if self.surface=='direct_user' and any((self.anchor_tool,self.anchor_call_id,self.document_id)):
            raise ValueError('direct user input cannot impersonate tool/document origin')
        return self


class ToolCall(Model):
    call_id:str=Field(min_length=1,max_length=100)
    tool_name:str=Field(min_length=1,max_length=100)
    arguments:dict

    @field_validator("arguments")
    @classmethod
    def finite_arguments(cls,value):return finite_json(value)


class Reply(Model):
    text:str=Field(default='',max_length=4000)
    tool_calls:tuple[ToolCall,...]=Field(default=(),max_length=4)
    fault:Literal['none','hang','network_probe','process_probe']='none'


class EngineeringPlan(Model):
    schema_version:Literal['talos.controlled-agent-engineering.v1']='talos.controlled-agent-engineering.v1'
    adapter_version:Literal['talos.controlled-delivery.v1']='talos.controlled-delivery.v1'
    purpose:Literal['offline_scripted_agent_control_not_empirical']='offline_scripted_agent_control_not_empirical'
    identity:Identity
    provenance:Provenance
    legitimate_task:str=Field(min_length=1,max_length=4000)
    injection:Injection
    offline_replies:tuple[Reply,...]=Field(min_length=1,max_length=16)
    limits:Limits
    hard_timeout_ms:int=Field(ge=100,le=120000,strict=True)
    reset_fault:ResetFault=ResetFault.NONE
    tool_fault:Fault=Fault.NONE
    model_id:Literal[None]=None
    primary_eligible:Literal[False]=False
    learning:Literal['disabled_fresh_per_process']='disabled_fresh_per_process'
    oracle_trust:Literal['operator_fixture_regression_only_not_independent_approval']='operator_fixture_regression_only_not_independent_approval'

    @model_validator(mode='after')
    def unique_calls(self):
        ids=[c.call_id for r in self.offline_replies for c in r.tool_calls]
        if len(set(ids))!=len(ids):raise ValueError('duplicate tool-call identity')
        if self.provenance.attacker_model_id is not None or self.provenance.target_model_id is not None:
            raise ValueError('offline controls have no provider model identity')
        return self

    def digest(self):return content_hash(self)


class ProviderUsage(Model):
    """Required complete per-request settlement before an eventual next request."""
    request_id:str=Field(min_length=1)
    model_id:str=Field(min_length=1)
    model_revision:str=Field(min_length=1)
    input_tokens:int=Field(ge=0,strict=True)
    output_tokens:int=Field(ge=0,strict=True)
    retries:int=Field(ge=0,strict=True)
    cost_microunits:int=Field(ge=0,strict=True)
    currency:str=Field(pattern=r'^[A-Z]{3}$')
    price_schedule_sha256:str=Field(pattern=HASH)
    provider_receipt_sha256:str=Field(pattern=HASH)


class ModelConfiguration(Model):
    model_id:str=Field(min_length=1)
    revision:str=Field(min_length=1)
    temperature:float=Field(ge=0,le=2,allow_inf_nan=False)
    max_output_tokens:int=Field(gt=0,strict=True)
    seed:int|None=Field(default=None,ge=0,strict=True)
    seed_support:Literal['supported','unsupported','unverified']

    @model_validator(mode='after')
    def seed_contract(self):
        if self.seed is not None and self.seed_support!='supported':raise ValueError('cannot claim unsupported deterministic provider seed')
        return self
