"""Pinned external comparison contracts, separate from Talos selection strategies."""
from __future__ import annotations
from typing import Literal
import json
from pydantic import Field,StrictInt,model_validator
from talos.corpus.models import Model,Surface,content_hash
from talos.corpus.planning import CommonPool,PublicTool
from talos.profiles import TargetProfile
from talos.research.contracts import Limits,Provenance

VERSION='talos.pyrit-comparator-adapter.v1'
PYRIT_VERSION='1.2.1'
PYRIT_COMMIT='c7b5789d74433da9e66569f27ee569f8622a22f6'


class Config(Model):
    adapter_version: Literal['talos.pyrit-comparator-adapter.v1']=VERSION
    framework: Literal['PyRIT']='PyRIT'
    framework_version: Literal['1.2.1']=PYRIT_VERSION
    framework_commit: Literal['c7b5789d74433da9e66569f27ee569f8622a22f6']=PYRIT_COMMIT
    strategy: Literal['native_RedTeamingAttack']='native_RedTeamingAttack'
    mode: Literal['native_adaptive_orchestration_offline_stubs']='native_adaptive_orchestration_offline_stubs'
    max_turns: int=Field(ge=1,le=10,strict=True)
    seed: int=Field(ge=0,le=4294967295,strict=True)
    score_as_adversarial_feedback: Literal[False]=False
    native_scorer: Literal['SubStringScorer_offline_diagnostic_only']='SubStringScorer_offline_diagnostic_only'
    provider_execution: Literal['DISABLED']='DISABLED'
    plugins: tuple[()]=()
    seed_scope: Literal['framework_local_randomness_not_provider_determinism']='framework_local_randomness_not_provider_determinism'


class Mapping(Model):
    opportunity_id: str
    target_id: str
    profile_sha256: str=Field(pattern=r'^[0-9a-f]{64}$')
    actor_id: str
    authorization_context_reference: str
    policy_id: str
    policy_version: str
    reset_contract: str
    surface: Surface
    shared_objective: str=Field(min_length=1)
    objective_review_reference: str | None=None
    delivery_status: Literal['UNAVAILABLE']='UNAVAILABLE'
    equivalence: Literal['candidate_mapping_not_approved_equivalence']='candidate_mapping_not_approved_equivalence'


class Contrast(Model):
    existing_primary: Literal['A2-A1']='A2-A1'
    proposed_full_system: Literal['A4-A1_pending_researcher_approval']='A4-A1_pending_researcher_approval'
    external_contrast: Literal['UNDECIDED_requires_researcher_approval']='UNDECIDED_requires_researcher_approval'
    comparator_validity_reference: str | None=None
    information_budget_reference: str | None=None
    denominator_clustering_reference: str | None=None
    cohort: Literal['UNASSIGNED']='UNASSIGNED'
    inference: Literal['NOT_PERFORMED']='NOT_PERFORMED'


class Plan(Model):
    schema_version: Literal['talos.external-comparison-plan.v1']='talos.external-comparison-plan.v1'
    comparison_id: str=Field(pattern=r'^[A-Za-z0-9_-]+$')
    provenance: Provenance
    config: Config
    dependency_lock_sha256: str=Field(pattern=r'^[0-9a-f]{64}$')
    framework_identity_sha256: str=Field(pattern=r'^[0-9a-f]{64}$')
    target_profile: TargetProfile
    pool: CommonPool
    mappings: tuple[Mapping,...]
    common_limits: Limits
    initialization_reserve_ms: int=Field(gt=0,strict=True)
    attempt_timeout_ms: int=Field(gt=0,strict=True)
    contrast: Contrast=Field(default_factory=Contrast)

    @model_validator(mode='after')
    def complete_shared_scope(self):
        ids=[m.opportunity_id for m in self.mappings]
        if len(set(ids))!=len(ids) or set(ids)!={o.opportunity_id for o in self.pool.opportunities}:
            raise ValueError('all common opportunities, including unsupported, require exact one-to-one mappings')
        expected_tools=tuple(PublicTool(name=t.name,description=t.description,input_schema=t.input_schema,output_schema=t.output_schema)
            for t in sorted(self.target_profile.tools,key=lambda t:t.name))
        if any(o.tools!=expected_tools for o in self.pool.opportunities):
            raise ValueError('common opportunity tool inventory differs from target profile')
        opportunities={o.opportunity_id:o for o in self.pool.opportunities}
        for m in self.mappings:
            surfaces={s.surface for s in opportunities[m.opportunity_id].stimuli}
            if m.surface==Surface.USER and surfaces-{Surface.USER}:
                raise ValueError('cannot hide unsupported surfaces in a mixed workflow')
            if m.surface not in {s.surface for s in opportunities[m.opportunity_id].stimuli}:
                raise ValueError('surface absent from matched public opportunity')
            if not all((m.actor_id,m.authorization_context_reference,m.reset_contract)):
                raise ValueError('explicit custody and reset references required')
            if m.target_id!=self.target_profile.target_id or m.profile_sha256!=self.target_profile.digest():
                raise ValueError('comparator mapping targets a different identity/profile')
            boundaries={(b.policy_id,b.policy_version) for b in self.target_profile.authorization_boundaries}
            if (m.policy_id,m.policy_version) not in boundaries: raise ValueError('unmatched policy/version')
        if self.provenance.attacker_model_id is not None or self.provenance.target_model_id is not None:
            raise ValueError('no actual provider models are configured in this engineering integration')
        return self

    def digest(self): return content_hash(self)


class NativeEvent(Model):
    sequence: int=Field(ge=0,strict=True)
    role: Literal['adversarial_stub','objective_stub']
    request_text: str
    response_text: str
    basis: Literal['native_framework_scripted_target_callback_not_provider_inference']='native_framework_scripted_target_callback_not_provider_inference'


class NativeReceipt(Model):
    schema_version: Literal['talos.pyrit-native-receipt.v1']='talos.pyrit-native-receipt.v1'
    framework_version: Literal['1.2.1']='1.2.1'
    phase_elapsed_ms: dict[str,StrictInt]
    environment: dict
    source_files: dict[str,str]
    config_sha256: str
    objective_sha256: str
    events: tuple[NativeEvent,...]
    native_outcome: str
    native_scores: tuple[dict,...]
    raw_result: dict
    counts: dict[str,StrictInt]
    provider_model_ids: Literal[None]=None
    tokens: Literal[None]=None
    cost: Literal[None]=None
    actual_agent_delivery: Literal['UNAVAILABLE']='UNAVAILABLE'

    @model_validator(mode='after')
    def callback_counts(self):
        if set(self.phase_elapsed_ms)!={'framework_initialization','native_execution'} or any(v<0 for v in self.phase_elapsed_ms.values()):
            raise ValueError('complete nonnegative framework timing required')
        if [e.sequence for e in self.events]!=list(range(len(self.events))): raise ValueError('native event gaps/order mismatch')
        if len(self.events)%2: raise ValueError('incomplete native generation/delivery pair')
        for index in range(0,len(self.events),2):
            attacker,objective=self.events[index:index+2]
            if (attacker.role,objective.role)!=('adversarial_stub','objective_stub'):
                raise ValueError('native callback roles out of order')
            if json.loads(attacker.response_text).get('next_message')!=objective.request_text:
                raise ValueError('native generated text was not forwarded unchanged')
            if index and attacker.request_text!=self.events[index-1].response_text:
                raise ValueError('native response feedback mismatch')
        expected={role:sum(e.role==role for e in self.events) for role in ('adversarial_stub','objective_stub')}
        if self.counts!=expected: raise ValueError('native request-role counts inconsistent')
        return self


class NormalizedResult(Model):
    schema_version: Literal['talos.external-normalized-result.v1']='talos.external-normalized-result.v1'
    opportunity_id: str
    state: Literal['DELIVERY_UNAVAILABLE','SURFACE_UNSUPPORTED','OFFLINE_NATIVE_CONTROL','BUDGET_STOP','ERROR']
    reason: str
    native_receipt: NativeReceipt | None=None
    unified_outcome: Literal['UNKNOWN']='UNKNOWN'
    independently_confirmed_primary_count: Literal[None]=None
    actual_target_model_calls: Literal[None]=None
    actual_target_tool_calls: Literal[None]=None
    actual_provider_cost: Literal[None]=None
