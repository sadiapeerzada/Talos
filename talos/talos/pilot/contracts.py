"""Versioned DEV-only prospective model and approval scope; no supplied approvals."""
from typing import Literal
from urllib.parse import urlsplit
from pydantic import Field,model_validator
from talos.corpus.models import Model,content_hash
from talos.readiness.contracts import Identity,Injection,ModelConfiguration
from talos.research.contracts import Limits,Provenance
from talos.targets.store import Fault,ResetFault
from talos.pilot.mlx_spec import MLXModel
H=r'^[0-9a-f]{64}$'


class LocalModel(Model):
    configuration:ModelConfiguration
    weights_sha256:str=Field(pattern=H)
    server_sha256:str=Field(pattern=H)
    chat_template_sha256:str=Field(pattern=H)
    endpoint:str
    max_input_tokens:int=Field(gt=0,strict=True)
    request_timeout_ms:int=Field(ge=100,le=120000,strict=True)
    input_microunits_per_million:int=Field(ge=0,strict=True)
    output_microunits_per_million:int=Field(ge=0,strict=True)
    currency:str=Field(pattern=r'^[A-Z]{3}$')
    price_schedule_sha256:str=Field(pattern=H)
    cost_basis:Literal['proposed_token_debit_not_actual_hardware_spend']='proposed_token_debit_not_actual_hardware_spend'

    @model_validator(mode='after')
    def local_only(self):
        p=urlsplit(self.endpoint)
        if (p.scheme!='http' or p.hostname!='127.0.0.1' or p.username or p.password or p.path not in ('','/')
            or p.query or p.fragment or not p.port or self.endpoint!=f'http://127.0.0.1:{p.port}'):
            raise ValueError('only exact numeric loopback HTTP origin with explicit port; no external targets')
        return self

    def debit(self,input_tokens,output_tokens):
        return (input_tokens*self.input_microunits_per_million+output_tokens*self.output_microunits_per_million+999999)//1000000


class ModelInjection(Model):
    surface:Literal['direct_user','tool_output','retrieved_document']
    payload:str=Field(min_length=1,max_length=4000)
    anchor_tool:str|None=None
    anchor_call_id:Literal[None]=None
    matching_call_ordinal:int|None=Field(default=None,ge=1,strict=True)
    document_id:str|None=None

    @model_validator(mode='after')
    def anchor(self):
        if self.surface=='direct_user':
            if any((self.anchor_tool,self.matching_call_ordinal,self.document_id)):raise ValueError('direct origin cannot be spoofed')
        elif not self.anchor_tool or self.matching_call_ordinal is None:raise ValueError('approved semantic tool/ordinal anchor required')
        if self.surface=='retrieved_document' and (self.anchor_tool!='read_document' or not self.document_id):
            raise ValueError('exact controlled document reader and document required')
        return self


class ModelPlan(Model):
    schema_version:Literal['talos.dev-model-conversation.v1']='talos.dev-model-conversation.v1'
    adapter_version:Literal['talos.local-chat-adapter.v1','talos.qwen-mlx-native-adapter.v1']='talos.local-chat-adapter.v1'
    purpose:Literal['prospective_DEV_only_not_authorized']='prospective_DEV_only_not_authorized'
    identity:Identity
    provenance:Provenance
    legitimate_task:str=Field(min_length=1,max_length=4000)
    injection:ModelInjection
    model:LocalModel|MLXModel
    limits:Limits
    case_identity:str|None=None
    opportunity_id:str|None=None
    common_pool_sha256:str|None=Field(default=None,pattern=H)
    max_turns:int=Field(ge=1,le=16,strict=True)
    hard_timeout_ms:int=Field(ge=100,le=120000,strict=True)
    reset_fault:Literal[ResetFault.NONE]=ResetFault.NONE
    tool_fault:Literal[Fault.NONE]=Fault.NONE
    primary_eligible:Literal[False]=False
    learning:Literal['disabled_fresh_per_process']='disabled_fresh_per_process'
    oracle_trust:Literal['operator_fixture_regression_only_not_independent_approval']='operator_fixture_regression_only_not_independent_approval'

    @model_validator(mode='after')
    def mlx_bounds(self):
        if isinstance(self.model,MLXModel):
            if self.max_turns>4:raise ValueError('proposed MLX request ceiling is four per episode')
            if self.adapter_version!='talos.qwen-mlx-native-adapter.v1':raise ValueError('explicit native MLX adapter version required')
        return self

    def digest(self):return content_hash(self)


class Scope(Model):
    schema_version:Literal['talos.DEV-pilot-approval-scope.v1']='talos.DEV-pilot-approval-scope.v1'
    run_nonce:str=Field(min_length=20)
    plan_sha256:str=Field(pattern=H)
    common_pool_sha256:str=Field(pattern=H)
    corpus_sha256:str=Field(pattern=H)
    graph_sha256:str=Field(pattern=H)
    target_policy_source_sha256:str=Field(pattern=H)
    adapter_source_sha256:str=Field(pattern=H)
    protocol_sha256:str=Field(pattern=H)
    cancellation_sha256:str=Field(pattern=H)
    model_custody_sha256:str=Field(pattern=H)
    dev_family_ids:tuple[str,...]=Field(min_length=1)
    permitted_surfaces:tuple[Literal['direct_user','tool_output','retrieved_document'],...]=Field(min_length=1)
    phase:Literal['DEV']='DEV'
    primary_eligible:Literal[False]=False

    def digest(self):return content_hash(self)
