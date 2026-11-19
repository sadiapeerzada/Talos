"""Versioned four-factorial engineering contracts; no empirical study approval."""
from __future__ import annotations
from enum import Enum
from typing import Literal
from pydantic import Field,StrictInt,StrictBool,model_validator
from talos.corpus.models import Model,content_hash
from talos.corpus.planning import CommonPool,PublicGraph,PublicTool,arm_inputs
from talos.profiles import TargetProfile
from talos.research.contracts import Limits,Provenance


class Arm(str,Enum):
    A1='A1_blind_static'
    A2='A2_graph_static'
    A3='A3_blind_adaptive'
    A4='A4_graph_adaptive'

    @property
    def graph(self): return self in (Arm.A2,Arm.A4)
    @property
    def adaptive(self): return self in (Arm.A3,Arm.A4)


class Accounting(Model):
    version: Literal['talos.factorial-accounting.v1']='talos.factorial-accounting.v1'
    shared_preparation: Literal['measured_once_matched_debit_all_arms']='measured_once_matched_debit_all_arms'
    per_arm_overhead: Literal['selection_reset_dispatch_update_elapsed_charged']='selection_reset_dispatch_update_elapsed_charged'
    budget_basis: Literal['scheduler_test_double_accounting_not_provider_measurements']='scheduler_test_double_accounting_not_provider_measurements'


class CasePreparation(Model):
    case_identity: str
    binding_id: str
    real_applicability: Literal['UNKNOWN','INAPPLICABLE']
    planning_applicability: Literal['APPLICABLE','UNKNOWN','INAPPLICABLE']
    opportunity_id: str | None = None
    reasons: tuple[str,...]


class Block(Model):
    block_id: str = Field(pattern=r'^[A-Za-z0-9_-]+$')
    target_profile: TargetProfile
    target_version: str
    scenario_id: str
    scenario_cluster_id: str
    case_cluster_reference: str | None = None
    variant_group_id: str
    reset_contract: Literal['fresh_scoped_test_double_each_attempt']='fresh_scoped_test_double_each_attempt'
    pool: CommonPool
    utility_opportunity_ids: tuple[str,...]=()
    case_preparation: tuple[CasePreparation,...]=()
    pool_status: Literal['planning_test_double_only_not_delivered']='planning_test_double_only_not_delivered'

    @model_validator(mode='after')
    def common_inventory(self):
        profile=self.target_profile
        if self.target_version!=profile.fixture_id: raise ValueError('target fixture version mismatch')
        expected=tuple(PublicTool(name=t.name,description=t.description,input_schema=t.input_schema,output_schema=t.output_schema)
                       for t in sorted(profile.tools,key=lambda t:t.name))
        for opportunity in self.pool.opportunities:
            if opportunity.tools!=expected: raise ValueError('opportunity inventory/schema differs from matched profile')
        ids={o.opportunity_id for o in self.pool.opportunities}
        if not set(self.utility_opportunity_ids)<=ids or len(set(self.utility_opportunity_ids))!=len(self.utility_opportunity_ids):
            raise ValueError('utility controls outside common pool or duplicated')
        for cell in self.case_preparation:
            if cell.opportunity_id is not None and cell.opportunity_id not in ids: raise ValueError('prepared opportunity absent')
        return self


class AnalysisContract(Model):
    version: Literal['talos.factorial-analysis-plan.v1']='talos.factorial-analysis-plan.v1'
    primary: Literal['paired_A2_minus_A1_independently_adjudicated_unique_effects']='paired_A2_minus_A1_independently_adjudicated_unique_effects'
    contrasts: tuple[str,...]=('A2-A1','A3-A1','A4-A2','(A4-A3)-(A2-A1)')
    denominator: Literal['matched_planned_blocks_and_slots_missing_unknown_retained']='matched_planned_blocks_and_slots_missing_unknown_retained'
    cohort_status: Literal['UNASSIGNED']='UNASSIGNED'
    root_cause_approval: str | None=None
    cluster_approval: str | None=None
    sampling_approval: str | None=None
    information_budget_approval: str | None=None
    oracle_validation_reference: str | None=None
    protocol_approval: str | None=None
    primary_budget_reference: str | None=None
    outcome_eligibility: Literal['policy_denial_trusted_relevant_commit_independent_reference_root_cause_adjudication']='policy_denial_trusted_relevant_commit_independent_reference_root_cause_adjudication'
    uncertainty: Literal['retain_unknown_missing_unresolved_cluster_aware_intervals_require_approval']='retain_unknown_missing_unresolved_cluster_aware_intervals_require_approval'
    units: Literal['paired_scenario_target_clusters_not_strings_or_repeats']='paired_scenario_target_clusters_not_strings_or_repeats'
    inference: Literal['not_performed']='not_performed'

    @model_validator(mode='after')
    def contrasts_fixed(self):
        if self.contrasts!=('A2-A1','A3-A1','A4-A2','(A4-A3)-(A2-A1)'):
            raise ValueError('changing prospective contrasts requires a new contract version')
        return self


class Plan(Model):
    schema_version: Literal['talos.factorial-plan.v1']='talos.factorial-plan.v1'
    comparison_id: str = Field(pattern=r'^[A-Za-z0-9_-]+$')
    purpose: Literal['offline_framework_engineering_only']='offline_framework_engineering_only'
    provenance: Provenance
    corpus_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    seed: StrictInt
    selector_version: Literal['talos.public-priority-selector.v1']='talos.public-priority-selector.v1'
    feedback_version: Literal['talos.ordinary-tool-mention-feedback.v1']='talos.ordinary-tool-mention-feedback.v1'
    permitted_graph: Literal['PR04_public_possible_topology_only']='PR04_public_possible_topology_only'
    arms: tuple[Arm,...]=(Arm.A1,Arm.A2,Arm.A3,Arm.A4)
    limits: Limits
    preparation_reserve_ms: int = Field(gt=0,strict=True)
    attempt_timeout_ms: int = Field(gt=0,strict=True)
    selection_slots: int = Field(ge=1,strict=True)
    accounting: Accounting=Field(default_factory=Accounting)
    analysis: AnalysisContract=Field(default_factory=AnalysisContract)
    blocks: tuple[Block,...]=Field(min_length=1)

    @model_validator(mode='after')
    def four_arms(self):
        if self.arms!=(Arm.A1,Arm.A2,Arm.A3,Arm.A4): raise ValueError('exactly four fixed factorial arms required')
        if len({b.block_id for b in self.blocks})!=len(self.blocks): raise ValueError('duplicate matched block')
        if self.provenance.attacker_model_id is not None or self.provenance.target_model_id is not None:
            raise ValueError('no provider/model adapters are implemented')
        return self

    def digest(self): return content_hash(self)


class PublicView(Model):
    schema_version: Literal['talos.factorial-public-view.v1']='talos.factorial-public-view.v1'
    common_pool_sha256: str
    pool: CommonPool
    graph_annotations: PublicGraph | None=None

    @model_validator(mode='after')
    def identity(self):
        if self.common_pool_sha256!=self.pool.digest(): raise ValueError('changed common opportunity set')
        arm_inputs(self.pool,graph_annotations=self.graph_annotations)
        return self


def view_for(pool:CommonPool,arm:Arm,graph:PublicGraph):
    pool=CommonPool.model_validate(pool.model_dump())
    inputs=arm_inputs(pool,graph_annotations=graph if arm.graph else None)
    return PublicView(common_pool_sha256=inputs['common_pool_sha256'],pool=pool,
                      graph_annotations=inputs['graph_annotations'])


class PublicFeedback(Model):
    schema_version: Literal['talos.ordinary-feedback.v1','talos.ordinary-feedback.v2']='talos.ordinary-feedback.v1'
    response_text: str
    referenced_tools: tuple[str,...]=()
    source: Literal['ordinary_test_double_response_not_ground_truth','ordinary_local_model_response_not_ground_truth']='ordinary_test_double_response_not_ground_truth'

    @model_validator(mode='after')
    def no_private_metadata(self):
        if (self.schema_version=='talos.ordinary-feedback.v1')!=(self.source=='ordinary_test_double_response_not_ground_truth'):
            raise ValueError('ordinary feedback version/source mismatch')
        import json
        try: value=json.loads(self.response_text)
        except ValueError: return self
        forbidden={'verdict','oracle_prediction','policy_assessment','evidence_reader','trusted_source_ids',
                   'ground_truth','reference_label','expected_outcome','attack_arm','arm_id'}
        def inspect(item):
            if isinstance(item,dict):
                if set(item)&forbidden: raise ValueError('private metadata cannot be ordinary feedback')
                for child in item.values(): inspect(child)
            elif isinstance(item,list):
                for child in item: inspect(child)
        inspect(value)
        return self


class State(Model):
    schema_version: Literal['talos.adaptation-state.v1']='talos.adaptation-state.v1'
    owner_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    slot: int = Field(ge=0,strict=True)
    weights: dict[str,StrictInt]
    visits: dict[str,StrictInt]
    updates: int = Field(ge=0,strict=True)

    @model_validator(mode='after')
    def counters(self):
        if set(self.weights)!=set(self.visits) or any(v<0 for v in (*self.weights.values(),*self.visits.values())):
            raise ValueError('invalid state counters/opportunity coverage')
        return self


class Choice(Model):
    slot: int
    opportunity_id: str | None
    state_before_sha256: str
    graph_used: StrictBool
    selector_version: Literal['talos.public-priority-selector.v1']='talos.public-priority-selector.v1'


class Update(Model):
    schema_version: Literal['talos.feedback-update.v1']='talos.feedback-update.v1'
    applied: StrictBool
    reason: str
    state_before: State
    state_after: State
    feedback: PublicFeedback | None
