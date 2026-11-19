"""Prospective matched scope; compatibility is never silently equated to validity."""
from talos.corpus.models import Surface,content_hash
from talos.comparator.contracts import Plan
from talos.comparator.isolation import bundle_identity,lock_hash


def validate_plan(plan:Plan):
    plan=Plan.model_validate(plan.model_dump())
    if plan.framework_identity_sha256!=content_hash(bundle_identity()) or plan.dependency_lock_sha256!=lock_hash():
        raise ValueError('framework identity/dependency lock mismatch')
    return plan


def matched_ceilings(talos_limits,external_limits):
    if talos_limits!=external_limits: raise ValueError('unequal Talos/external budget ceilings')
    return content_hash(talos_limits)


def mapping_status(mapping):
    if mapping.surface!=Surface.USER:
        return 'SURFACE_UNSUPPORTED','Native text-loop bridge has no reviewed indirect/tool/document/workflow delivery adapter.'
    return 'DELIVERY_UNAVAILABLE','Controlled agent prompt delivery and operational permission remain unavailable.'


def gates():
    return {'execution':'BLOCKED','provider_inference':'DISABLED','agent_delivery':'UNAVAILABLE','independent_validation':'PENDING',
        'opportunity_equivalence':'NOT_APPROVED','cohort':'UNASSIGNED','primary_findings':None,
        'analysis_primary':'A2-A1_unchanged','proposed_A4_minus_A1':'REQUIRES_RESEARCHER_APPROVAL'}


def dry_run(plan:Plan):
    plan=validate_plan(plan)
    return {'schema_version':'talos.external-comparison-dry-run.v1','plan_sha256':plan.digest(),
        'pool_sha256':plan.pool.digest(),'framework_version':plan.config.framework_version,
        'cells':[{'opportunity_id':m.opportunity_id,'status':mapping_status(m)[0],'reason':mapping_status(m)[1]} for m in plan.mappings],
        'gates':gates()}


def match_block(plan:Plan,block,limits, *, actor_id:str,authorization_context_reference:str):
    """Check prospective counterpart identity; no declaration grants authorization."""
    validate_plan(plan)
    matched_ceilings(plan.common_limits,limits)
    if plan.target_profile!=block.target_profile or plan.pool!=block.pool:
        raise ValueError('counterpart target/schema/opportunity mismatch')
    if any(m.reset_contract!=block.reset_contract or m.actor_id!=actor_id or
           m.authorization_context_reference!=authorization_context_reference for m in plan.mappings):
        raise ValueError('counterpart reset/actor/authorization mismatch')
    return {'matched_contract':True,'equivalence_approved':False,'execution':'BLOCKED'}
