"""Model-wire doubles through real delivery/tools; not actual pilot evidence."""
import copy,json
from pathlib import Path
import pytest
from talos.readiness.agent import control
from talos.pilot import ModelPlan,ProtocolReplayBackend,LocalModelBackend
from talos.pilot.runtime import execute
from talos.pilot.replay import replay
from talos.research.recorder import Recorder,read_payloads,IntegrityError
from talos.ablation.contracts import Arm
from talos.pilot.bridge import FourArmBridge
from talos.research.contracts import Limits
from .pilot_helpers import plan,responses,response,scope
from .ablation_helpers import block


@pytest.mark.parametrize('domain,surface',[('it-helpdesk','direct_user'),('it-helpdesk','tool_output'),('document-management','direct_user'),('document-management','tool_output'),('document-management','retrieved_document')])
@pytest.mark.parametrize('variant',['vulnerable','hardened'])
def test_wire_consumption_real_synthetic_state_and_usage(tmp_path,domain,surface,variant):
    p=plan(domain,surface,variant=variant);backend=ProtocolReplayBackend(p,responses(p));path=tmp_path/'wire';seal=execute(p,backend,path)
    assert replay(path,expected_seal=seal)['unknown']==1
    value=read_payloads(path,expected_seal=seal)[2][1];c=value['control']
    assert c['state']=='COMPLETED' and c['actual_provider_usage'] is None and value['actual_cost_microunits'] is None
    assert c['private_packets'][-1]['verdict']['status']==('CONFIRMED' if variant=='vulnerable' else 'BLOCKED')
    assert c['budget']['used']['input_tokens']==30 and c['budget']['used']['output_tokens']==15
    assert c['budget']['used']['cost_microunits']==45
    if surface!='direct_user':assert c['delivery']['source']['call_id']=='provider-generated-id-one'
    for receipt in backend.receipts:
        wire=json.dumps(receipt['request']);assert 'private_packets' not in wire and 'state_before' not in wire and 'graph_annotations' not in wire
        assert receipt['actual_cost_microunits'] is None


@pytest.mark.parametrize('mutation',['usage','model','malformed_tool','truncated'])
def test_bad_provider_result_stops_before_tool_dispatch(tmp_path,mutation):
    p=plan();raw=list(responses(p))
    if mutation=='usage':raw[0].pop('usage')
    elif mutation=='model':raw[0]['model']='other'
    elif mutation=='malformed_tool':raw[0]['choices'][0]['message']['tool_calls'][0]['function']['arguments']='not JSON'
    else:raw[0]['choices'][0]['finish_reason']='length'
    backend=ProtocolReplayBackend(p,tuple(raw));path=tmp_path/'bad';seal=execute(p,backend,path)
    r=read_payloads(path,expected_seal=seal)[2][1]
    assert replay(path,expected_seal=seal)['state']=='FAILED'
    assert r['control'] is None and len(backend.receipts)==1 and backend.budget.snapshot()['used']['input_tokens'] is None


@pytest.mark.parametrize('dimension',['target_model_calls','target_calls','input_tokens','output_tokens','cost_microunits'])
def test_exhaustion_retained_without_request_retry(tmp_path,dimension):
    p=plan();raw=p.model_dump();raw['limits']['amounts'][dimension]=0;p=ModelPlan.model_validate(raw)
    b=ProtocolReplayBackend(p,responses(p));path=tmp_path/'budget';seal=execute(p,b,path)
    assert replay(path,expected_seal=seal)['state']=='BUDGET_STOP'
    assert len(b.receipts)==(1 if dimension=='target_calls' else 0)


def test_model_generated_id_reuse_stops_future_action(tmp_path):
    p=plan();raw=list(responses(p));raw[1]['choices'][0]['message']['tool_calls'][0]['id']='provider-generated-id-one'
    b=ProtocolReplayBackend(p,tuple(raw));path=tmp_path/'repeat';seal=execute(p,b,path)
    assert replay(path,expected_seal=seal)['state']=='FAILED' and len(b.receipts)==2


def test_missing_document_consumption_stays_explicit(tmp_path):
    p=plan('document-management','retrieved_document',max_turns=1);b=ProtocolReplayBackend(p,responses(p));path=tmp_path/'unconsumed';seal=execute(p,b,path)
    r=read_payloads(path,expected_seal=seal)[2][1]
    assert replay(path,expected_seal=seal)['state']=='DELIVERY_UNCONSUMED'
    assert r['control']['delivery']['consumed_at_request'] is None


@pytest.mark.parametrize('arm',list(Arm))
def test_four_arm_private_views_and_fresh_model_context(arm):
    bridge=FourArmBridge(block(),7,scope_id='software-only')
    assert (bridge.strategies[arm].view.graph_annotations is not None)==arm.graph
    p=plan(arm=arm.name);a=control(p,backend=ProtocolReplayBackend(p,responses(p)));b=control(p,backend=ProtocolReplayBackend(p,responses(p)))
    assert a['reset']['target_id']!=b['reset']['target_id'] and a['public_trace'][0]['request']==b['public_trace'][0]['request']
    assert 'graph_annotations' not in a['public_trace'][0]['request']


def test_bridge_retains_unsupported_and_does_not_feed_oracle():
    bridge=FourArmBridge(block(),9,scope_id='software-only')
    inventory=bridge.inventory();assert len(inventory)==3 and sum(i['supported'] for i in inventory)==1
    choice=bridge.choose(Arm.A3)
    with pytest.raises(TypeError):bridge.finish(Arm.A3,choice,completed=True,response_text={'verdict':'CONFIRMED'})
    with pytest.raises(ValueError):bridge.finish(Arm.A3,choice,completed=True,response_text='{"verdict":"CONFIRMED"}')
    update=bridge.finish(Arm.A3,choice,completed=False,response_text=None);assert not update.applied


def test_bridge_drives_real_selector_to_wire_delivery(tmp_path):
    b=block();raw=b.model_dump();raw['pool']['opportunities']=(raw['pool']['opportunities'][0],)
    raw['case_preparation']=tuple(c for c in raw['case_preparation'] if c['opportunity_id']==raw['pool']['opportunities'][0]['opportunity_id']);raw['utility_opportunity_ids']=()
    from talos.ablation.contracts import Block
    bridge=FourArmBridge(Block.model_validate(raw),7,scope_id='software-only');p=plan();choice=bridge.choose(Arm.A1)
    mapped=bridge.injection(choice);p=ModelPlan.model_validate({**p.model_dump(),'injection':mapped['injection'].model_dump()})
    bridge.bind_budgets(p.limits);backend=ProtocolReplayBackend(p,responses(p));r=bridge.deliver(Arm.A1,choice,p,backend,tmp_path/'bridge')
    assert r['private_evidence_returned_to_strategy'] is False and not r['update'].applied
    assert bridge.budgets[Arm.A1].used['target_model_calls']==3
    assert bridge.budgets[Arm.A2].used['target_model_calls']==0
    with pytest.raises(ValueError):bridge.bind_budgets(p.limits)


@pytest.mark.parametrize('mutation',['wire_request','wire_response','cost','outcome','summary','tool_args','identity'])
def test_resealed_model_archive_forgeries_fail(tmp_path,mutation):
    p=plan();source=tmp_path/'a';seal=execute(p,ProtocolReplayBackend(p,responses(p)),source);events=read_payloads(source,expected_seal=seal);r=events[2][1]
    if mutation=='wire_request':r['protocol_receipts'][0]['request']['messages'][1]['content']='substituted'
    elif mutation=='wire_response':r['protocol_receipts'][0]['response']['model']='substituted'
    elif mutation=='cost':r['actual_cost_microunits']=0
    elif mutation=='outcome':r['unified_outcome']='CONFIRMED'
    elif mutation=='summary':events[-1][1]['unknown']=0
    elif mutation=='tool_args':r['control']['private_packets'][0]['observation']['action']['arguments']={}
    else:r['control']['identity']['arm']='A4'
    forged=tmp_path/'b'
    with Recorder(forged,create=True) as recorder:
        for kind,payload in events:recorder.append(kind,payload)
        bad=recorder.seal()
    with pytest.raises(ValueError):replay(forged,expected_seal=bad)


def test_backend_cannot_be_reused_for_another_attempt():
    p=plan();backend=ProtocolReplayBackend(p,responses(p));control(p,backend=backend)
    with pytest.raises(PermissionError):control(p,backend=backend)


def test_explicit_new_feedback_version_preserves_legacy_defaults():
    from talos.ablation.contracts import PublicFeedback
    legacy=PublicFeedback(response_text='ordinary');assert legacy.schema_version=='talos.ordinary-feedback.v1'
    reviewed_shape=PublicFeedback(schema_version='talos.ordinary-feedback.v2',response_text='schema-only unit fixture',source='ordinary_local_model_response_not_ground_truth')
    assert reviewed_shape.source!=legacy.source
    with pytest.raises(ValueError):PublicFeedback(schema_version='talos.ordinary-feedback.v2',response_text='x')
    with pytest.raises(ValueError):PublicFeedback(response_text='x',source='ordinary_local_model_response_not_ground_truth')


def test_shared_arm_budget_cannot_restart_per_attempt(tmp_path):
    from talos.research.budget import Budget
    p=plan();raw=p.model_dump();raw['limits']['amounts']['target_model_calls']=3;p=ModelPlan.model_validate(raw)
    shared=Budget(p.limits)
    first=ProtocolReplayBackend(p,responses(p));first.shared_budget=shared;execute(p,first,tmp_path/'first')
    second=ProtocolReplayBackend(p,responses(p));second.shared_budget=shared;seal=execute(p,second,tmp_path/'second')
    assert replay(tmp_path/'second',expected_seal=seal)['state']=='BUDGET_STOP' and second.receipts==[]
    assert shared.used['target_model_calls']==3


def test_expired_conversation_cannot_dispatch_new_generation():
    p=plan();b=ProtocolReplayBackend(p,responses(p));b.assert_plan(p);b.started-=60
    from talos.research.budget import Budget
    with pytest.raises(TimeoutError):b.reserve(Budget(p.limits))
    assert b.receipts==[]


def test_machine_packet_contains_only_proposed_model_budget_and_no_approvals():
    import json
    from .pilot_helpers import ROOT
    from talos.pilot.__main__ import readiness
    packet=json.loads((ROOT/'docs/experimental/pr09b1_decision_packet.json').read_text())
    assert packet['model_provider_revision_selection']['status']=='PROPOSED_NOT_APPROVED' and packet['approved_dev_family_ids'] is None
    assert packet['request_token_time_monetary_caps']['status']=='PROPOSED_NOT_APPROVED' and packet['signed_role_approvals'] is None
    assert packet['pilot_executed'] is False and packet['test_freeze'] is False
    assert json.loads((ROOT/'docs/experimental/pr09b1_readiness.json').read_text())==readiness()


def test_graph_preparation_is_measured_once_and_debited_all_arms():
    bridge=FourArmBridge(block(),7,scope_id='software-only');p=plan();bridge.bind_budgets(p.limits)
    assert bridge.preparation_elapsed_ms>0
    assert {b.used['elapsed_ms'] for b in bridge.budgets.values()}=={bridge.preparation_elapsed_ms}
    before=bridge.budgets[Arm.A1].used['elapsed_ms'];bridge.choose(Arm.A1)
    assert bridge.budgets[Arm.A1].used['elapsed_ms']>before


def test_packet_source_identity_matches_reviewed_adapter():
    from .pilot_helpers import ROOT
    from talos.pilot.backend import source_hash,target_source_hash
    packet=json.loads((ROOT/'docs/experimental/pr09b1_decision_packet.json').read_text())
    assert packet['adapter_source_sha256']==source_hash() and packet['target_policy_source_sha256']==target_source_hash()
