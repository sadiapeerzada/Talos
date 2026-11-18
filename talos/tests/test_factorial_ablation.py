"""Deterministic scheduler controls, never empirical four-arm evaluations."""
from copy import deepcopy
import json
import random
from pathlib import Path
import subprocess
import sys

import pytest

from talos.ablation import Arm,Plan,PublicFeedback,dry_run,execute,replay,schedule
from talos.ablation.contracts import PublicView,view_for
from talos.ablation.planning import public_topology
from talos.ablation.strategy import Strategy
from talos.ablation.doubles import Reply,Script
from talos.corpus.models import content_hash
from talos.research.recorder import Recorder,IntegrityError,read_payloads
from .ablation_helpers import Clock,block,plan,script


@pytest.mark.parametrize('arm',list(Arm))
def test_four_arms_same_pool_inventory_only_permitted_topology(arm):
    b=block();graph=public_topology(b);view=view_for(b.pool,arm,graph)
    strategy=Strategy(arm,view,5)
    assert view.pool==b.pool and view.common_pool_sha256==b.pool.digest()
    assert (view.graph_annotations is not None)==arm.graph
    assert strategy.choose().graph_used==arm.graph
    assert strategy.state.updates==0
    for private in ('policy_assessment','expected_outcome','trusted_source_ids','authorization_boundaries','case_preparation'):
        assert private not in view.model_dump_json()


def test_deterministic_balanced_schedule_and_manifest_roundtrip_no_global_rng():
    blocks=[block(ident=f'b-{i}') for i in range(4)]
    p=plan(blocks);before=random.getstate();first=schedule(p)
    assert random.getstate()==before and first==schedule(Plan.model_validate_json(p.model_dump_json()))
    positions={arm:[] for arm in Arm}
    for entry in first: positions[Arm(entry['arm'])].append(entry['position'])
    assert all(sorted(v)==[0,1,2,3] for v in positions.values())
    assert dry_run(p)['gates']['operational_status']=='BLOCKED'
    assert all(x.real_applicability=='UNKNOWN' for b in p.blocks for x in b.case_preparation)


@pytest.mark.parametrize('arm',[Arm.A1,Arm.A2])
def test_static_policy_is_frozen_despite_completed_or_failed_feedback(arm):
    b=block();view=view_for(b.pool,arm,public_topology(b));left=Strategy(arm,view,2);right=Strategy(arm,view,2)
    for _ in range(6):
        a,c=left.choose(),right.choose();assert a==c
        u=left.finish(a,status='completed',feedback=PublicFeedback(response_text='grant_access'))
        right.finish(c,status='failed',feedback=None)
        assert not u.applied and left.state.weights==right.state.weights
    assert left.state.updates==0


def test_adaptation_only_completed_public_feedback_and_isolated_state():
    b=block();v=view_for(b.pool,Arm.A3,public_topology(b))
    adaptive=Strategy(Arm.A3,v,2);peer=Strategy(Arm.A3,v,2,scope_id='separate-block')
    baseline=Strategy(Arm.A1,view_for(b.pool,Arm.A1,public_topology(b)),2)
    before=peer.state.model_dump();choice=adaptive.choose()
    skipped=adaptive.finish(choice,status='timed_out',feedback=PublicFeedback(response_text='grant_access'))
    assert not skipped.applied and adaptive.state.updates==0
    baseline.finish(baseline.choose(),status='timed_out',feedback=None)
    assert adaptive.choose().opportunity_id==baseline.choose().opportunity_id
    update=adaptive.finish(adaptive.choose(),status='completed',feedback=PublicFeedback(response_text='lookup_employee'))
    assert update.applied and adaptive.state.updates==1 and peer.state.model_dump()==before
    assert any(update.state_after.weights[i]!=update.state_before.weights[i] for i in adaptive.ids)
    adaptive.state=peer.state
    with pytest.raises(ValueError): adaptive.choose()


@pytest.mark.parametrize('mutation',['private_field','structured_label','unknown_tool','blind_graph','unequal_pool'])
def test_deliberate_leakage_and_opportunity_changes_fail(mutation):
    b=block();graph=public_topology(b);view=view_for(b.pool,Arm.A3,graph)
    if mutation=='private_field':
        with pytest.raises(ValueError): PublicFeedback.model_validate({'response_text':'x','verdict':'CONFIRMED'})
    elif mutation=='structured_label':
        with pytest.raises(ValueError): PublicFeedback(response_text='{"nested":{"oracle_prediction":"CONFIRMED"}}')
    elif mutation=='unknown_tool':
        strategy=Strategy(Arm.A3,view,0)
        with pytest.raises(ValueError): strategy.finish(strategy.choose(),status='completed',feedback=PublicFeedback(response_text='x',referenced_tools=('private_reader',)))
    elif mutation=='blind_graph':
        with pytest.raises(ValueError): Strategy(Arm.A3,view_for(b.pool,Arm.A4,graph),0)
    else:
        raw=view.model_dump(mode='json');raw['pool']['opportunities'].pop()
        with pytest.raises(ValueError): PublicView.model_validate(raw)


def test_data_only_scheduler_replay_equal_budgets_and_actual_outcomes_unknown(tmp_path):
    p=plan();s=script(p);path=tmp_path/'run'
    seal=execute(p,path,script=s,clock_ns=Clock());report=replay(path,expected_seal=seal)
    assert report['summary']['planned_cells']==20 and report['summary']['recorded_cells']==20
    assert report['summary']['independently_confirmed_primary_findings'] is None
    assert all(r['security_outcome']=='UNKNOWN' and not r['primary_finding_eligible'] for r in report['rows'])
    assert len({content_hash(b['limits']) for b in report['budgets'].values()})==1
    assert all(b['used']['attempts']==5 and b['used']['target_calls']==5 for b in report['budgets'].values())
    scopes=[r['reset']['scope'] for r in report['rows'] if r['reset']]
    assert len(scopes)==len(set(scopes))
    for arm in Arm:
        rows=[r for r in report['rows'] if r['arm']==arm.value and r['kind']=='selection']
        assert all(r['update']['applied']==arm.adaptive for r in rows)


def test_repeated_synthetic_clock_runs_have_identical_seals(tmp_path):
    p=plan();s=script(p)
    left=execute(p,tmp_path/'one',script=s,clock_ns=Clock())
    right=execute(p,tmp_path/'two',script=s,clock_ns=Clock())
    assert left==right
    assert read_payloads(tmp_path/'one')==read_payloads(tmp_path/'two')


def test_missing_prompt_delivery_is_retained_for_every_arm_without_dispatch(tmp_path):
    p=plan();path=tmp_path/'run';seal=execute(p,path,clock_ns=Clock())
    report=replay(path,expected_seal=seal)
    assert all(r['state']=='delivery_unavailable' for r in report['rows'])
    assert all(b['used']['target_calls']==0 and b['used']['attempts']==0 for b in report['budgets'].values())
    assert report['summary']['actual_legitimate_task_success'] is None


@pytest.mark.parametrize('change',[{'arms':['A1_blind_static']},{'arm_limits':{}},{'seed':True},
                                   {'selector_version':'other'},{'feedback_version':'other'},
                                   {'analysis':{'cohort_status':'TEST'}},{'selection_slots':0}])
def test_unequal_or_unversioned_design_rejected(change):
    p=plan();raw=p.model_dump()
    if 'analysis' in change: raw['analysis'].update(change['analysis'])
    else: raw.update(change)
    with pytest.raises(ValueError): Plan.model_validate(raw)


@pytest.mark.parametrize('failure',['failed','timed_out','unsupported','unknown','reset','missing_usage','exhaustion'])
def test_failure_cells_no_hidden_retry_and_no_feedback_from_unfinished(tmp_path,failure):
    p=plan();s=script(p)
    if failure in ('failed','timed_out','unsupported','unknown'): s=script(p,status=failure,feedback=None,utility_success=False)
    elif failure=='reset': s=script(p,reset_healthy=False)
    elif failure=='missing_usage': s=script(p,usage={'attempts':1,'target_calls':None})
    else:
        raw=p.model_dump();raw['limits']['amounts']['target_calls']=0;p=Plan.model_validate(raw)
    seal=execute(p,tmp_path/'run',script=s,clock_ns=Clock());report=replay(tmp_path/'run',expected_seal=seal)
    assert report['summary']['recorded_cells']==20
    assert all(r['security_outcome']=='UNKNOWN' for r in report['rows'])
    if failure in ('failed','timed_out','unsupported','unknown','reset'):
        assert all(not r['update']['applied'] for r in report['rows'] if r['update'])
    if failure=='missing_usage':
        assert all(b['used']['target_calls'] is None for b in report['budgets'].values())
        assert sum(r['reply'] is not None for r in report['rows'])==4
    if failure=='exhaustion': assert all(r['reply'] is None for r in report['rows'])


def repack(source,destination,change):
    with Recorder(destination,create=True) as recorder:
        for kind,data in read_payloads(source):
            recorder.append(kind,change(kind,deepcopy(data)))
        return recorder.seal()


@pytest.mark.parametrize('attack',['pool','graph','limits','state','update','reset','outcome','denominator'])
def test_rehashed_leakage_inequality_and_fabricated_results_fail_replay(tmp_path,attack):
    p=plan();source=tmp_path/'source';execute(p,source,script=script(p),clock_ns=Clock())
    changed=[]
    def corrupt(kind,d):
        if kind=='arm_start' and not changed:
            if attack=='pool' and d['view']: d['view']['pool']['opportunities'].pop();changed.append(True)
            if attack=='graph' and not Arm(d['arm']).graph: d['view']['graph_annotations']=public_topology(p.blocks[0]).model_dump(mode='json');changed.append(True)
            if attack=='limits': d['limits_sha256']='0'*64;changed.append(True)
            if attack=='state': d['initial_state']['updates']=999;changed.append(True)
        if kind=='factorial_cell' and not changed:
            if attack=='update' and d['update']: d['update']['state_after']['updates']=999;changed.append(True)
            if attack=='reset' and d['reset']: d['reset']['scope']='another-arm';changed.append(True)
            if attack=='outcome': d['security_outcome']='CONFIRMED';changed.append(True)
        if kind=='factorial_summary' and attack=='denominator': d['recorded_cells']=1;changed.append(True)
        return d
    target=tmp_path/'altered';seal=repack(source,target,corrupt)
    assert changed
    with pytest.raises((ValueError,IntegrityError)): replay(target,expected_seal=seal)


def test_graph_priority_uses_only_public_possible_path_and_feedback_can_change_next_choice():
    b=block();g=public_topology(b)
    graph=Strategy(Arm.A2,view_for(b.pool,Arm.A2,g),0)
    adaptive=Strategy(Arm.A4,view_for(b.pool,Arm.A4,g),0)
    first=graph.choose();assert first.opportunity_id==adaptive.choose().opportunity_id
    assert graph.graph_scores[first.opportunity_id]>0
    graph.finish(first,status='completed',feedback=None)
    update=adaptive.finish(adaptive.choose(),status='completed',feedback=PublicFeedback(response_text='lookup_employee'))
    assert update.applied
    assert graph.choose().opportunity_id!=adaptive.choose().opportunity_id
    blind_first={Strategy(Arm.A1,view_for(b.pool,Arm.A1,g),seed).choose().opportunity_id for seed in range(8)}
    assert len(blind_first)>1 and all(Strategy(Arm.A2,view_for(b.pool,Arm.A2,g),seed).choose().opportunity_id==first.opportunity_id for seed in range(8))


def test_ordinary_success_words_are_not_oracle_rewards():
    b=block();g=public_topology(b)
    a=Strategy(Arm.A3,view_for(b.pool,Arm.A3,g),0);static=Strategy(Arm.A1,view_for(b.pool,Arm.A1,g),0)
    update=a.finish(a.choose(),status='completed',feedback=PublicFeedback(response_text='CONFIRMED BLOCKED success denied'))
    static.finish(static.choose(),status='completed',feedback=None)
    assert all(v==0 for v in update.state_after.weights.values())
    assert a.choose().opportunity_id==static.choose().opportunity_id


def test_invalid_tool_feedback_preserves_known_usage_and_no_cross_arm_influence(tmp_path):
    p=plan();s=script(p,feedback=PublicFeedback(response_text='x',referenced_tools=('private_unknown_tool',)))
    seal=execute(p,tmp_path/'run',script=s,clock_ns=Clock());report=replay(tmp_path/'run',expected_seal=seal)
    adaptive=[b for key,b in report['budgets'].items() if 'adaptive' in key]
    static=[b for key,b in report['budgets'].items() if 'static' in key]
    assert all(b['used']['target_calls']==1 and b['stop_reason'] for b in adaptive)
    assert all(b['used']['target_calls']==5 for b in static)
    assert all(not r['primary_finding_eligible'] for r in report['rows'])
