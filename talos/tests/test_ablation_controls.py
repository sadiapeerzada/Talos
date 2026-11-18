"""Offline isolation, utility and matched-hardening engineering controls."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from talos.ablation import Arm,Plan,execute,replay
from talos.ablation.contracts import PublicFeedback,view_for
from talos.ablation.planning import corpus_block,public_topology
from talos.ablation.strategy import Strategy
from talos.ablation.remediation import matched_hardening,legacy_wrapper_control
from talos.ablation.observer import recorded_outcome,utility_control
from talos.ablation.doubles import Reply,Script
from talos.corpus.models import content_hash
from talos.profiles import TargetProfile
from talos.research import execute as execute_fixture
from talos.research.contracts import Packet
from talos.research.recorder import read_payloads,IntegrityError
from talos.targets import ControlledEnvironment
from .research_helpers import control_plan
from .ablation_helpers import Clock,block,plan,script


@pytest.mark.parametrize('domain',['it-helpdesk','document-management'])
@pytest.mark.parametrize('variant',['vulnerable','hardened'])
@pytest.mark.parametrize('fault',['none','failed_tool','missing_audit'])
def test_benign_utility_success_failure_unknown_without_attack_delivery(tmp_path,domain,variant,fault):
    with ControlledEnvironment(domain,variant=variant) as env:
        p=control_plan(env,trust=True,suffix='AUTHORIZED');raw=p.model_dump();raw['cells'][0]['tool_fault']=fault;p=type(p).model_validate(raw)
        archive=tmp_path/'fixture-control';seal=execute_fixture(p,env,archive)
        packets=[Packet.model_validate(v['packet']) for k,v in read_payloads(archive,expected_seal=seal) if k=='action']
        assert len(packets)==1
        goal={'resources':['wiki']} if domain=='it-helpdesk' else {'editors':['employee','manager']}
        result=utility_control(packets[0],expected_response=goal)
        assert result['success']==({'none':True,'failed_tool':False,'missing_audit':None}[fault])
        assert result['scope']=='synthetic_control_only_not_general_utility'


@pytest.mark.parametrize('variant,expected',[('vulnerable','CONFIRMED'),('hardened','BLOCKED')])
def test_observer_replays_unmodified_oracle_but_cannot_count_independent_findings(tmp_path,variant,expected):
    with ControlledEnvironment('it-helpdesk',variant=variant) as env:
        p=control_plan(env,trust=True);archive=tmp_path/'fixture-control';seal=execute_fixture(p,env,archive)
    note=recorded_outcome(archive,expected_seal=seal,action_id='synthetic-unit-test:cell-0:action_tool')
    assert note['verdict']['status']==expected
    assert not note['primary_finding_eligible'] and note['primary_count'] is None
    assert note['independent_reference_status']=='PENDING'
    with pytest.raises((ValueError,IntegrityError)):
        recorded_outcome(archive,expected_seal='0'*64,action_id='synthetic-unit-test:cell-0:action_tool')


@pytest.mark.parametrize('domain',['it-helpdesk','document-management'])
def test_hardening_pairs_preserve_public_opportunities_and_benign_controls(domain):
    baseline=block(domain,'vulnerable','baseline');hard=block(domain,'hardened','hard')
    result=matched_hardening(baseline,hard)
    assert result['status']=='PLANNING_ONLY' and result['effectiveness'] is None
    assert not result['independently_generated_fix']
    with pytest.raises(ValueError): matched_hardening(baseline,baseline)
    raw=hard.model_dump();raw['utility_opportunity_ids']=tuple(o.opportunity_id for o in hard.pool.opportunities[:1])
    altered=type(hard).model_validate(raw)
    with pytest.raises(ValueError): matched_hardening(baseline,altered)


def test_legacy_prewritten_wrapper_is_not_a_portable_generated_fix():
    result=legacy_wrapper_control()
    assert result['matched_portable_comparison']=='BLOCKED'
    assert len(result['source_sha256'])==64 and not result['independently_generated_fix']
    assert result['general_remediation_effectiveness'] is None


def test_no_global_learning_model_activation_or_network_with_keys_present(tmp_path,monkeypatch):
    import talos.learning
    def forbidden(*args,**kwargs): raise AssertionError('hidden influence')
    monkeypatch.setattr(talos.learning.LearningStore,'__init__',forbidden)
    monkeypatch.setattr(socket.socket,'connect',forbidden);monkeypatch.setattr(socket,'getaddrinfo',forbidden)
    for name in ('OPENAI_API_KEY','ANTHROPIC_API_KEY','GROQ_API_KEY'): monkeypatch.setenv(name,'never-activate')
    p=plan();seal=execute(p,tmp_path/'run',script=script(p),clock_ns=Clock())
    report=replay(tmp_path/'run',expected_seal=seal)
    assert report['summary']['actual_provider_measurements']=={'attacker_model':None,'target_model':None,'tokens':None,'cost':None}


def test_unknown_permissions_keep_all_candidates_and_slots_in_accounting(tmp_path):
    source=block();raw=source.target_profile.model_dump()
    for tool in raw['tools']: tool['permissions']=[]
    profile=TargetProfile.model_validate(raw)
    b=corpus_block(profile,block_id='unknown',scenario_id=source.scenario_id,scenario_cluster_id='cluster',
        variant_group_id=source.variant_group_id,binding_ids=[x.binding_id for x in source.case_preparation])
    assert not b.pool.opportunities and len(b.case_preparation)==3
    assert all(c.planning_applicability=='UNKNOWN' for c in b.case_preparation)
    p=plan([b]);seal=execute(p,tmp_path/'run',script=script(p),clock_ns=Clock())
    report=replay(tmp_path/'run',expected_seal=seal)
    assert report['summary']['planned_cells']==16
    assert all(r['state']=='unsupported' for r in report['rows'])
    assert report['summary']['case_preparation_counts']['unknown']['requested_cases']==3


def test_cooperative_timeout_and_shared_preparation_overrun_stop_calls(tmp_path):
    p=plan(attempt_timeout_ms=1);s=script(p)
    seal=execute(p,tmp_path/'timeout',script=s,clock_ns=Clock(step_ns=10_000_000))
    report=replay(tmp_path/'timeout',expected_seal=seal)
    assert all(r['reply'] is None for r in report['rows'])
    assert all(b['stop_reason'] for b in report['budgets'].values())
    p=plan(preparation_reserve_ms=1)
    seal=execute(p,tmp_path/'prep',script=script(p),clock_ns=Clock(step_ns=10_000_000))
    report=replay(tmp_path/'prep',expected_seal=seal)
    assert all(r['state']=='budget_exhausted' for r in report['rows'])


def test_overhead_charge_is_equal_and_graph_build_is_not_claimed_four_times(tmp_path):
    p=plan();path=tmp_path/'run';execute(p,path,script=script(p),clock_ns=Clock())
    prep=[v for k,v in read_payloads(path) if k=='common_preparation']
    assert len(prep)==1 and prep[0]['physical_builds']==1
    assert prep[0]['actual_shared_elapsed_ms']==prep[0]['matched_debit_each_arm_ms']
    assert prep[0]['accounting']['shared_preparation']=='measured_once_matched_debit_all_arms'


@pytest.mark.parametrize('private',['policy_assessment','evidence_reader','ground_truth','reference_label','expected_outcome','attack_arm','arm_id'])
def test_private_feedback_metadata_rejected_even_nested_json(private):
    with pytest.raises(ValueError): PublicFeedback(response_text=json.dumps({'data':[{private:'secret'}]}))


@pytest.mark.parametrize('bad',['extra_reply','missing_reply','per_arm_script','unknown_usage_dimension','negative_reservation','unfinished_feedback'])
def test_script_cannot_change_opportunities_by_arm_or_conceal_accounting(tmp_path,bad):
    p=plan();s=script(p);raw=s.model_dump()
    if bad=='extra_reply': raw['replies']['private-extra']=next(iter(raw['replies'].values()))
    if bad=='missing_reply': raw['replies'].pop(next(iter(raw['replies'])))
    if bad=='per_arm_script': raw['arms']={'A4':'special privilege'}
    if bad=='unknown_usage_dimension': next(iter(raw['replies'].values()))['usage']['hidden_calls']=1
    if bad=='negative_reservation': raw['reservation']['target_calls']=-1
    if bad=='unfinished_feedback': next(iter(raw['replies'].values()))['status']='timed_out'
    with pytest.raises(ValueError): execute(p,tmp_path/'run',script=Script.model_validate(raw),clock_ns=Clock())


def test_schema_inventory_and_utility_set_cannot_differ_between_arms():
    b=block();raw=b.model_dump()
    raw['pool']['opportunities'][0]['tools'][0]['input_schema']={'type':'object','properties':{'leaked_label':{}}}
    with pytest.raises(ValueError): type(b).model_validate(raw)
    raw=b.model_dump();raw['utility_opportunity_ids']=('private-not-eligible',)
    with pytest.raises(ValueError): type(b).model_validate(raw)


def test_static_and_adaptive_without_feedback_have_same_choices():
    b=block();g=public_topology(b)
    for static,adaptive in ((Arm.A1,Arm.A3),(Arm.A2,Arm.A4)):
        a=Strategy(static,view_for(b.pool,static,g),12);c=Strategy(adaptive,view_for(b.pool,adaptive,g),12)
        for i in range(8):
            assert a.choose().opportunity_id==c.choose().opportunity_id
            a.finish(a.choose(),status='failed',feedback=None);c.finish(c.choose(),status='failed',feedback=None)


def test_arm_and_block_state_cannot_be_imported_between_strategies():
    b=block();g=public_topology(b)
    a=Strategy(Arm.A3,view_for(b.pool,Arm.A3,g),12);c=Strategy(Arm.A4,view_for(b.pool,Arm.A4,g),12)
    a.state=c.state
    with pytest.raises(ValueError): a.choose()


def test_cli_offline_plan_and_replay(tmp_path):
    p=plan();manifest=tmp_path/'plan.json';manifest.write_text(p.model_dump_json())
    path=tmp_path/'run';seal=execute(p,path,clock_ns=Clock())
    for args in (['plan',str(manifest)],['replay',str(path),'--expected-seal',seal]):
        child=subprocess.run([sys.executable,'-m','talos.ablation',*args],capture_output=True,text=True)
        assert child.returncode==0,child.stderr
        result=json.loads(child.stdout)
        assert result['gates']['operational_status']=='BLOCKED'


def test_selector_operates_on_unfamiliar_renamed_public_tools_without_legacy_names():
    from talos.corpus.planning import CommonPool,PublicGraph,PublicGraphEdge,PublicOpportunity,PublicTool,RenderedStimulus
    from talos.ablation.contracts import PublicView
    tools=(PublicTool(name='opaque_alpha',description='Unfamiliar capability',input_schema={'type':'object','properties':{'k':{'type':'string'}}},output_schema={'type':'string'}),
           PublicTool(name='opaque_beta',description='Another capability',input_schema={'type':'object','properties':{'v':{'type':'string'}}},output_schema={'type':'string'}))
    pool=CommonPool(opportunities=(PublicOpportunity(opportunity_id='one',tools=tools,stimuli=(RenderedStimulus(surface='user_message',text='opaque_beta'),)),
        PublicOpportunity(opportunity_id='two',tools=tools,stimuli=(RenderedStimulus(surface='user_message',text='opaque_alpha then opaque_beta'),))))
    graph=PublicGraph(nodes=('tool:opaque_alpha','tool:opaque_beta'),edges=(PublicGraphEdge(source='tool:opaque_alpha',target='tool:opaque_beta',relation='possible_data_flow'),))
    view=PublicView(common_pool_sha256=pool.digest(),pool=pool,graph_annotations=graph)
    selector=Strategy(Arm.A2,view,7)
    assert selector.choose().opportunity_id=='two'
