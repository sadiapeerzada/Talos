"""Prospective matched controls; no generated-fix or efficacy claim."""
from talos.corpus.models import content_hash
from talos.ablation.contracts import Block


def matched_hardening(baseline:Block,hardened:Block):
    if baseline.target_version==hardened.target_version: raise ValueError('distinct target variants required')
    if (baseline.variant_group_id!=hardened.variant_group_id or baseline.scenario_id!=hardened.scenario_id
        or baseline.target_profile.domain!=hardened.target_profile.domain):
        raise ValueError('unmatched hardening scenario/domain/variant group')
    def public_signature(block):
        return content_hash([{'tools':[t.model_dump(mode='json') for t in o.tools],
                              'stimuli':[s.model_dump(mode='json') for s in o.stimuli]} for o in block.pool.opportunities])
    if public_signature(baseline)!=public_signature(hardened): raise ValueError('hardening changed underlying opportunities/inventory')
    def utility_signature(block):
        index={o.opportunity_id:o for o in block.pool.opportunities}
        return content_hash([{'tools':[t.model_dump(mode='json') for t in index[i].tools],
                              'stimuli':[s.model_dump(mode='json') for s in index[i].stimuli]} for i in block.utility_opportunity_ids])
    if not baseline.utility_opportunity_ids or utility_signature(baseline)!=utility_signature(hardened):
        raise ValueError('benign-task controls missing or changed across variants')
    if (baseline.reset_contract!=hardened.reset_contract or len(baseline.utility_opportunity_ids)!=len(hardened.utility_opportunity_ids)):
        raise ValueError('hardening reset/utility mismatch')
    return {'schema_version':'talos.hardening-comparison.v1','status':'PLANNING_ONLY',
        'baseline':baseline.target_version,'hardened':hardened.target_version,'shared_public_content_sha256':public_signature(baseline),
        'effectiveness':None,'independently_generated_fix':False}


def legacy_wrapper_control():
    import hashlib
    from importlib.resources import files
    source_hash=hashlib.sha256(files('talos.sample_agents').joinpath('policy.py').read_bytes()).hexdigest()
    return {'schema_version':'talos.prewritten-wrapper-control.v1',
        'source':'talos/talos/sample_agents/policy.py:PolicyEnforcingBrain',
        'origin':'existing_prewritten_customer_service_policy_wrapper','source_sha256':source_hash,
        'portable_domain_adapter':'UNAVAILABLE','matched_portable_comparison':'BLOCKED',
        'required_controls':['same underlying brain/model','same task/opportunity inventory','same budgets/reset',
                             'authorized task success/failure and evidence-grounded effects'],
        'independently_generated_fix':False,'general_remediation_effectiveness':None}
