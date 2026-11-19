"""Approval strings, merges, keys and synthetic controls never approve a study."""
import json,subprocess,sys
from pathlib import Path
import pytest
from talos.readiness import CapabilityRequest,ApprovalClaim,report,ModelConfiguration,ProviderUsage
from talos.readiness.gates import REQUIREMENTS,write_report
from .readiness_helpers import plan


def request(**changes):
    raw=dict(opt_in=False,target_id='synthetic-prospective-target',target_profile_sha256='0'*64,actor_id='employee',
        policy_sha256='1'*64,reset_contract_sha256='2'*64,protocol_sha256='3'*64,delivery_sha256='4'*64,surface='direct_user',
        model=ModelConfiguration(model_id='not-approved-model',revision='explicit-unapproved-revision',temperature=0,
            max_output_tokens=100,seed_support='unverified'),network={'allowed_origins':()},limits=plan().limits,
        credential_handle='SECRET_PRIVATE_HANDLE')
    raw.update(changes);return CapabilityRequest(**raw)


@pytest.mark.parametrize('gate',sorted(REQUIREMENTS))
def test_each_gate_has_evidence_authority_and_reason(gate):
    r=report();g=next(g for g in r['gates'] if g['gate_id']==gate)
    assert g['necessary_evidence'] and g['approval_authority'] and g['reason']
    assert g['status']=='MISSING' and g['engineering_control_is_approval'] is False
    assert r['empirical_execution']=='NO-GO' and r['pr09_experimental_complete'] is False


@pytest.mark.parametrize('gate',sorted(REQUIREMENTS))
def test_invented_approval_and_merge_reference_cannot_enable(gate):
    claim=ApprovalClaim(gate=gate,authority_id='claimed-researcher',evidence_sha256='a'*64,scope_sha256='b'*64,
        expires_at='2099-01-01T00:00:00Z',approval_reference='merged-PR-is-not-consent',signature='unverified-claimed-signature')
    r=report((claim,));g=next(g for g in r['gates'] if g['gate_id']==gate)
    assert g['status']=='UNVERIFIED' and r['empirical_execution']=='NO-GO'


@pytest.mark.parametrize('opt_in',[False,True])
def test_key_and_opt_in_never_activate_transport(monkeypatch,opt_in):
    monkeypatch.setenv('OPENAI_API_KEY','SECRET_API_KEY')
    r=request(opt_in=opt_in)
    assert 'SECRET_PRIVATE_HANDLE' not in r.model_dump_json() and 'SECRET_PRIVATE_HANDLE' not in repr(r)
    with pytest.raises(PermissionError,match='NO-GO'):r.invoke()


def test_unknown_duplicate_approval_and_claim_validation():
    raw=dict(gate='unknown',authority_id='x',evidence_sha256='a'*64,scope_sha256='b'*64,expires_at='expired',approval_reference='x',signature='x')
    with pytest.raises(ValueError):report((ApprovalClaim(**raw),))
    c=ApprovalClaim(**{**raw,'gate':'target_ownership'})
    with pytest.raises(ValueError):report((c,c))
    with pytest.raises(ValueError):ApprovalClaim(**{**raw,'evidence_sha256':'not-a-hash'})


@pytest.mark.parametrize('field',['input_tokens','output_tokens','retries','cost_microunits'])
def test_missing_provider_usage_is_not_zero(field):
    raw=dict(request_id='r',model_id='unapproved',model_revision='v',input_tokens=1,output_tokens=1,retries=0,
        cost_microunits=0,currency='USD',price_schedule_sha256='a'*64,provider_receipt_sha256='b'*64)
    ProviderUsage(**raw)
    with pytest.raises(ValueError):ProviderUsage(**{**raw,field:None})
    with pytest.raises(ValueError):ProviderUsage(**{**raw,field:-1})


@pytest.mark.parametrize('support',['unverified','unsupported'])
def test_seed_support_not_fabricated(support):
    with pytest.raises(ValueError):ModelConfiguration(model_id='m',revision='v',temperature=0,max_output_tokens=1,seed=4,seed_support=support)


def test_no_test_cohort_or_empirical_fields_can_be_injected():
    p=plan();raw=p.model_dump();raw['identity']['partition']='TEST'
    from talos.readiness import EngineeringPlan
    with pytest.raises(ValueError):EngineeringPlan.model_validate(raw)
    raw=p.model_dump();raw['primary_eligible']=True
    with pytest.raises(ValueError):EngineeringPlan.model_validate(raw)
    with pytest.raises(ValueError):request(phase='TEST')


def test_checked_in_machine_report_and_exclusive_write(tmp_path):
    root=Path(__file__).parents[2]
    assert json.loads((root/'docs/experimental/pr09_readiness.json').read_text())==report()
    path=tmp_path/'readiness.json';write_report(path)
    with pytest.raises(FileExistsError):write_report(path)


def test_cli_has_only_readiness_schema_and_replay():
    from talos.readiness.__main__ import main
    root=Path(__file__).parents[2]
    result=subprocess.run([sys.executable,'-m','talos.readiness','report'],cwd=root,capture_output=True,text=True)
    assert result.returncode==0 and json.loads(result.stdout)['empirical_execution']=='NO-GO'
    result=subprocess.run([sys.executable,'-m','talos.readiness','--help'],cwd=root,capture_output=True,text=True)
    assert 'pilot' not in result.stdout and 'live' not in result.stdout


@pytest.mark.parametrize('field,value',[('frozen',True),('approval','invented'),('test_cohort',[]),('primary_budget',80),
    ('sample_size',120),('primary','A4-A1'),('empirical_execution','GO'),('pr09_experimental_complete',True)])
def test_freeze_preparation_rejects_invented_decisions(field,value):
    from talos.readiness.protocol import ProtocolDraft
    p=ProtocolDraft(protocol_sha256='0'*64,governing_final_plan_sha256='1'*64,governing_original_plan_sha256='2'*64)
    with pytest.raises(ValueError):ProtocolDraft.model_validate({**p.model_dump(),field:value})


def test_protocol_content_identity():
    import hashlib
    from talos.readiness.protocol import ProtocolDraft
    root=Path(__file__).parents[2]
    p=ProtocolDraft.model_validate_json((root/'docs/experimental/pr09_freeze_preparation.json').read_text())
    assert p.protocol_sha256==hashlib.sha256((root/'docs/experimental/pr09_protocol_draft.md').read_bytes()).hexdigest()
