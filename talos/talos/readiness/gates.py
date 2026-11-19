"""Machine-readable actual readiness; no approval verifier/provider installed."""
from pathlib import Path
from typing import Literal,Protocol
from pydantic import Field
from talos.corpus.models import Model,content_hash
from talos.readiness.contracts import ModelConfiguration
from talos.research.contracts import Limits
from talos.research.safety import NetworkPolicy

REQUIREMENTS={
 'target_ownership':('Signed ownership and scope for exact target/version/synthetic stores','target owner and principal researcher'),
 'authorization_policy':('Independent review of exact actor/policy/version boundaries','policy owner and independent reviewer'),
 'trusted_state':('Reviewed reader custody, action binding, completeness and finality evidence','independent evidence custodian'),
 'prompt_delivery':('Reviewed adapter/consumption proof for exact target and surface','target custodian and principal researcher'),
 'model_provider':('Explicit provider/model revision/endpoint opt-in and terms/scope authorization','account owner and principal researcher'),
 'isolation':('Reviewed process/network/tool sink/credential containment for operational adapter','target custodian'),
 'hard_timeout':('Operational process/provider cancellation, finality and containment verification','target custodian and evidence reviewer'),
 'resource_budget':('Signed per-run monetary/request/token/time caps, currency and complete usage contract','budget owner'),
 'validated_corpus':('Source-reviewed case validity/applicability and leakage checks','corpus custodian and independent reviewer'),
 'held_out_cohort':('Independently selected TEST family/target identity manifest and separation review','independent cohort selector'),
 'reviewer_independence':('Two raters, adjudicator, conflict declarations and blind custody protocol','independent review coordinator'),
 'statistical_protocol':('Approved primary budget, clusters, missingness, intervals and stopping rules','principal researcher and independent statistical reviewer'),
 'protocol_freeze':('Explicit signed protocol/configuration freeze and amendment process','principal researcher'),
 'dev_pilot':('Separate exact DEV model/target/delivery/budget pilot authorization','principal researcher and budget owner'),
}


class ApprovalClaim(Model):
    gate:str
    authority_id:str=Field(min_length=1)
    evidence_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    scope_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    expires_at:str
    approval_reference:str=Field(min_length=1)
    signature:str=Field(min_length=1,repr=False)


class ApprovalVerifier(Protocol):
    """External trust root must verify signer authority, signature, scope, expiry/revocation.

    No concrete operational verifier is shipped or trusted by Stage A.
    """
    def verify(self,claim:ApprovalClaim, *, scope_sha256:str)->bool:...


def report(claims:tuple[ApprovalClaim,...]=()):
    # Even plausible signature/config strings are unverified without an actual trust root.
    unknown=set(c.gate for c in claims)-set(REQUIREMENTS)
    if unknown:raise ValueError('unknown approval gate')
    if len({c.gate for c in claims})!=len(claims):raise ValueError('duplicate approval claim')
    by_gate={c.gate:c for c in claims}
    gates=[]
    for key,(evidence,authority) in REQUIREMENTS.items():
        gates.append({'gate_id':key,'necessary_evidence':evidence,'approval_authority':authority,
            'status':'UNVERIFIED' if key in by_gate else 'MISSING',
            'evidence_sha256':by_gate[key].evidence_sha256 if key in by_gate else None,
            'reason':'No operational approval verifier, trusted authority registry or independently checked approval evidence is installed.'
                if key in by_gate else 'Required authorization/independent evidence was not supplied.',
            'engineering_control_is_approval':False})
    return {'schema_version':'talos.experimental-readiness.v1','stage':'PR09_STAGE_A',
        'source_baseline':'700d6acf9c06e98c82cd623abf17c65c301ef24d',
        'engineering_scope':'offline_scripted_agent_tool_workflow',
        'operational_approval_verifier':'UNAVAILABLE','empirical_execution':'NO-GO','pr09_experimental_complete':False,'dev_pilot':'NOT_AUTHORIZED',
        'live_provider_transport':'UNAVAILABLE','cohort':'UNASSIGNED','gates':gates,
        'primary':'A2-A1','proposed_secondary':'A4-A1_PENDING_APPROVAL','pyrit':'EXPLORATORY_EQUIVALENCE_UNAPPROVED'}


class CapabilityRequest(Model):
    schema_version:Literal['talos.agent-capability-request.v1']='talos.agent-capability-request.v1'
    opt_in:bool=Field(default=False,strict=True)
    phase:Literal['DEV']='DEV'
    target_id:str=Field(min_length=1)
    target_profile_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    actor_id:str=Field(min_length=1)
    policy_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    reset_contract_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    protocol_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    delivery_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    surface:Literal['direct_user','tool_output','retrieved_document']
    model:ModelConfiguration
    network:NetworkPolicy
    limits:Limits
    credential_handle:str=Field(min_length=1,repr=False,exclude=True)

    def invoke(self,*args,**kwargs):
        # Neither config metadata nor possession of API credentials activates inference.
        raise PermissionError('PR-09 EMPIRICAL EXECUTION: NO-GO; operational verifier/transport, approved target and budget are absent')


def write_report(path:Path):
    # Exclusive create prevents accidental replacement of an approved future artifact.
    import json
    with Path(path).open('x') as stream:json.dump(report(),stream,sort_keys=True,indent=2);stream.write('\n')
    return content_hash(report())
