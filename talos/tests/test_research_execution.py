"""Offline research engineering tests, not empirical attack evaluations."""
from copy import deepcopy
import json
import os
from pathlib import Path
import random
import socket
import subprocess
import sys

import pytest

from talos.corpus import content_hash
from talos.judging import Outcome
from talos.research import RunPlan, dry_run, execute, finalize_interrupted, replay
from talos.research.budget import Budget, BudgetStop
from talos.research.contracts import CellResult, DIMENSIONS, LearningSnapshot, Limits
from talos.research.recorder import IntegrityError, Recorder, canonical, read_payloads, verify
from talos.research.replay import replay_packet
from talos.research.safety import InferenceGate, NetworkPolicy
from talos.targets import ControlledEnvironment
from .research_helpers import control_plan


def amend_cell(plan,**changes):
    raw=plan.model_dump();raw['cells'][0].update(changes)
    return RunPlan.model_validate(raw)


def result_from(path,plan,environment):
    seal=execute(plan,environment,path)
    result=replay(path,expected_seal=seal)
    return result['results']['cell-0'],result,seal


@pytest.mark.parametrize('domain',['it-helpdesk','document-management'])
@pytest.mark.parametrize('variant,trust,suffix,expected',[
    ('vulnerable',True,'DIRECT',Outcome.CONFIRMED),
    ('hardened',True,'DIRECT',Outcome.BLOCKED),
    ('vulnerable',True,'AUTHORIZED',Outcome.NO_VIOLATION),
    ('hardened',True,'AUTHORIZED',Outcome.NO_VIOLATION),
    ('vulnerable',False,'DIRECT',Outcome.UNKNOWN),
])
def test_fixture_verdicts_and_full_offline_replay(tmp_path,domain,variant,trust,suffix,expected):
    path=tmp_path/'run'
    with ControlledEnvironment(domain,variant=variant) as env:
        plan=control_plan(env,trust=trust,suffix=suffix)
        r,report,seal=result_from(path,plan,env)
        assert r.outcome==expected
        assert r.packet.observation.action.run_id==plan.run_id
        assert r.packet.reset_receipt['generation']==1
        assert r.packet.raw_store_records['snapshots']
        assert report['accounting']['recorded_actions']==1
        assert report['summary']['budget']['used']['target_calls']==1
        assert r.input_tokens is None and r.output_tokens is None and r.cost_microunits is None
    # Environment/store gone: replay uses captured policy/evidence only.
    again=replay(path,expected_seal=seal)
    assert again['results']==report['results']
    assert replay_packet(r.packet)==r.packet.verdict


@pytest.mark.parametrize('fault,expected',[
    ('failed_tool',Outcome.ATTEMPTED),('rollback_before_commit',Outcome.ATTEMPTED),
    ('missing_audit',Outcome.UNKNOWN),('delayed_audit',Outcome.UNKNOWN),
    ('contradictory_audit',Outcome.UNKNOWN),('partial_commit',Outcome.UNKNOWN),
    ('unrelated_state_change',Outcome.UNKNOWN),('timeout',Outcome.UNKNOWN),
])
def test_faults_preserve_nonconfirmations(tmp_path,fault,expected):
    with ControlledEnvironment('it-helpdesk',variant='vulnerable') as env:
        plan=amend_cell(control_plan(env,trust=True),tool_fault=fault)
        r,report,_=result_from(tmp_path/'run',plan,env)
        assert r.outcome==expected
        if expected==Outcome.UNKNOWN: assert r.abstention_reason
        assert report['accounting']['outcome_counts']['CONFIRMED']==0


@pytest.mark.parametrize('fault',['failed_reset','incomplete_reset'])
def test_reset_failures_no_call(tmp_path,fault):
    with ControlledEnvironment('document-management',variant='vulnerable') as env:
        plan=amend_cell(control_plan(env,trust=True),reset_fault=fault)
        r,report,_=result_from(tmp_path/'run',plan,env)
        assert r.outcome==Outcome.UNKNOWN and r.state=='reset_failed'
        assert report['summary']['budget']['used']['target_calls']==0
        assert report['accounting']['recorded_actions']==0


def test_new_run_always_resets_no_cross_repeat_contamination(tmp_path):
    with ControlledEnvironment('it-helpdesk',variant='vulnerable') as env:
        plan=control_plan(env,trust=True,count=2)
        _,report,_=result_from(tmp_path/'one',plan,env)
        assert [r.packet.reset_receipt['generation'] for r in report['results'].values()]==[1,2]
        assert all(r.outcome==Outcome.CONFIRMED for r in report['results'].values())
        plan=RunPlan.model_validate({**plan.model_dump(),'run_id':'another-run'})
        _,second,_=result_from(tmp_path/'two',plan,env)
        assert all(r.packet.observation.action.run_id=='another-run' for r in second['results'].values())
        assert [r.packet.reset_receipt['generation'] for r in second['results'].values()]==[3,4]


def test_workflow_records_every_action_and_outcome(tmp_path):
    with ControlledEnvironment('document-management',variant='vulnerable') as env:
        plan=control_plan(env,trust=True,suffix='WORKFLOW')
        _,report,_=result_from(tmp_path/'run',plan,env)
        assert report['accounting']['recorded_actions']==2
        assert report['accounting']['action_outcome_counts']['NO_VIOLATION']==1
        assert report['accounting']['action_outcome_counts']['CONFIRMED']==1
        assert report['summary']['budget']['used']['target_calls']==2


def test_default_corpus_delivery_abstains_without_reset_or_budget(tmp_path,monkeypatch):
    with ControlledEnvironment('it-helpdesk') as env:
        plan=amend_cell(control_plan(env,trust=True),mode='corpus_delivery')
        def forbidden(**kwargs): raise AssertionError('no reset permitted for unavailable delivery')
        monkeypatch.setattr(env,'reset',forbidden)
        assert dry_run(plan)['cells']['cell-0']['status']=='UNKNOWN'
        r,report,_=result_from(tmp_path/'run',plan,env)
        assert r.state=='delivery_unavailable' and r.outcome==Outcome.UNKNOWN
        assert not r.packet
        assert report['summary']['budget']['used']['target_calls']==0


@pytest.mark.parametrize('dimension',sorted(DIMENSIONS))
def test_budget_exact_reservation_and_exhaustion(dimension):
    amounts={d:0 for d in DIMENSIONS};amounts[dimension]=1
    b=Budget(Limits(amounts=amounts))
    b.reserve({dimension:1});b.settle({dimension:1})
    assert b.used[dimension]==1
    with pytest.raises(BudgetStop): b.reserve({dimension:1})


def test_budget_no_pending_oversubscription_missing_usage_or_silent_overrun():
    limits={d:2 for d in DIMENSIONS}
    b=Budget(Limits(amounts=limits));b.reserve({'input_tokens':1})
    with pytest.raises(BudgetStop): b.reserve({'input_tokens':1})
    with pytest.raises(BudgetStop): b.settle({'input_tokens':None})
    assert b.stop_reason and b.used['input_tokens']==0
    with pytest.raises(BudgetStop): b.reserve({})
    b=Budget(Limits(amounts=limits));b.reserve({'target_calls':1})
    with pytest.raises(BudgetStop): b.settle({'target_calls':2})
    assert b.used['target_calls']==2
    with pytest.raises(ValueError): Budget(Limits(amounts=limits)).reserve({'target_calls':True})


def test_exhausted_cells_not_silently_omitted_or_retried(tmp_path):
    with ControlledEnvironment('it-helpdesk',variant='vulnerable') as env:
        plan=control_plan(env,trust=True,count=3)
        raw=plan.model_dump();raw['limits']['amounts']['target_calls']=0
        plan=RunPlan.model_validate(raw)
        _,report,_=result_from(tmp_path/'run',plan,env)
        assert report['accounting']['planned_cells']==3
        assert report['accounting']['recorded_cells']==3
        assert report['accounting']['outcome_counts']['UNKNOWN']==3
        assert not report['accounting']['missing_cell_ids']
        assert report['summary']['budget']['used']['target_calls']==0


def test_timeout_abstains_and_stops_future_calls(tmp_path):
    ticks=iter(range(0,1_000_000_000,100_000_000))
    with ControlledEnvironment('it-helpdesk',variant='vulnerable') as env:
        plan=control_plan(env,trust=True,count=2,timeout_ms=1)
        execute(plan,env,tmp_path/'run',clock_ns=lambda:next(ticks))
        report=replay(tmp_path/'run')
        assert all(r.outcome==Outcome.UNKNOWN for r in report['results'].values())
        assert report['results']['cell-0'].state=='timed_out'
        assert report['accounting']['execution_intents']==1


@pytest.mark.parametrize('which',['case','corpus','policy','target','version','source'])
def test_exact_input_identity_rejects_mismatches_before_archive(tmp_path,which):
    with ControlledEnvironment('it-helpdesk') as env:
        plan=control_plan(env,trust=True);raw=plan.model_dump()
        if which=='case': raw['cells'][0]['case_identity']='unknown'
        if which=='corpus': raw['corpus_sha256']='0'*64
        if which=='policy':
            raw['policy_version']='bad';raw['trust']['policy_version']='bad'
        if which=='target': raw['profile']['target_id']='another-target'
        if which=='version': raw['target_version']='unrecognized'
        if which=='source': raw['trust']['trusted_source_ids']=['unapproved-other-source']
        with pytest.raises(ValueError): execute(RunPlan.model_validate(raw),env,tmp_path/'run')
        assert not (tmp_path/'run').exists()


def test_order_local_random_and_frozen_learning_no_global_effect(tmp_path,monkeypatch):
    import talos.learning
    def forbidden(*args,**kwargs): raise AssertionError('hidden global learning/network access')
    monkeypatch.setattr(talos.learning.LearningStore,'__init__',forbidden)
    monkeypatch.setattr(talos.learning,'default_db_path',forbidden)
    monkeypatch.setattr(socket.socket,'connect',forbidden)
    monkeypatch.setattr(socket,'getaddrinfo',forbidden)
    for name in ('ANTHROPIC_API_KEY','OPENAI_API_KEY','GROQ_API_KEY'):
        monkeypatch.setenv(name,'present-but-forbidden')
    with ControlledEnvironment('it-helpdesk') as env:
        plan=control_plan(env,count=4,order='seeded_shuffle',learning={'mode':'supplied_frozen','data':{'hints':['fixed']}})
        before=random.getstate();one=dry_run(plan);two=dry_run(plan)
        assert before==random.getstate() and one==two
        execute(plan,env,tmp_path/'run')
        assert replay(tmp_path/'run')['plan'].learning.data=={'hints':['fixed']}
        assert one['learning_sha256']==content_hash(plan.learning)


@pytest.mark.parametrize('optin',[False,True])
def test_api_keys_never_enable_provider_transport(monkeypatch,optin):
    monkeypatch.setenv('OPENAI_API_KEY','never-used')
    with pytest.raises(PermissionError):
        InferenceGate(opt_in=optin,model_id='explicit-test-model',approval_reference='test-not-approval').invoke()


@pytest.mark.parametrize('url',[
    'https://example.com','http://169.254.169.254/latest','http://10.0.0.1',
    'http://127.0.0.1:1234','file:///etc/passwd','https://user:pass@example.com',
    'https://example.com#private','https://example.com\\evil','https://%65xample.com',
    'http://[::ffff:127.0.0.1]:80',
])
def test_network_default_deny(url):
    with pytest.raises((PermissionError,ValueError)): NetworkPolicy().validate_destination(url)


def test_network_allowlist_dns_pinning_redirect_and_private_guards():
    policy=NetworkPolicy(allowed_origins=('https://example.com:443',),pinned_addresses=('8.8.8.8',))
    assert policy.validate_destination('https://example.com/path',resolved_addresses=('8.8.8.8',))=='https://example.com:443'
    for options in ({},{'resolved_addresses':('127.0.0.1',)},{'resolved_addresses':('8.8.8.8',),'redirected':True}):
        with pytest.raises(PermissionError): policy.validate_destination('https://example.com',**options)
    with pytest.raises(PermissionError): policy.request('https://example.com')
    for address in ('169.254.169.254','10.0.0.1','0.0.0.0','224.0.0.1','127.0.0.1'):
        policy=NetworkPolicy(allowed_origins=(f'http://{address}:80',),pinned_addresses=(address,))
        with pytest.raises(PermissionError): policy.validate_destination(f'http://{address}')
    policy=NetworkPolicy(allowed_origins=('http://127.0.0.1:99',),pinned_addresses=('127.0.0.1',),allow_loopback_fixture=True)
    assert policy.validate_destination('http://127.0.0.1:99')


@pytest.mark.parametrize('damage',['payload','event','delete_tail','seal','wrong_pin','noncanonical','symlink'])
def test_archive_integrity_failures(tmp_path,damage):
    path=tmp_path/'journal'
    with Recorder(path,create=True) as r:
        r.append('a',{'value':1});r.append('b',{'value':2});seal=r.seal()
    if damage=='payload': next((path/'objects').glob('*.json')).write_text('{}')
    if damage=='event': (path/'events/00000000.json').write_text('{}')
    if damage=='delete_tail': (path/'events/00000001.json').unlink()
    if damage=='seal': (path/'seal.json').write_text('{}')
    if damage=='wrong_pin': seal='0'*64
    if damage=='noncanonical':
        p=path/'events/00000000.json';p.write_text(json.dumps(json.loads(p.read_text()),indent=2))
    if damage=='symlink': (path/'injected').symlink_to(path/'seal.json')
    with pytest.raises(IntegrityError): verify(path,expected_seal=seal)


def test_recorder_exclusive_sealed_no_overwrite_and_deterministic_bytes(tmp_path):
    left,right=tmp_path/'one',tmp_path/'two'
    for path in (left,right):
        with Recorder(path,create=True) as r:
            with pytest.raises(IntegrityError): Recorder(path)
            r.append('same',{'b':2,'a':1});seal=r.seal()
            with pytest.raises(IntegrityError): r.append('later',{})
        with pytest.raises(IntegrityError): Recorder(path)
        with pytest.raises(FileExistsError): Recorder(path,create=True)
    assert (left/'seal.json').read_bytes()==(right/'seal.json').read_bytes()
    assert read_payloads(left)==read_payloads(right)


def test_interrupt_after_effect_recovery_never_reissues_call(tmp_path,monkeypatch):
    path=tmp_path/'run'
    with ControlledEnvironment('it-helpdesk',variant='vulnerable') as env:
        plan=control_plan(env,trust=True,count=2)
        original=env.execute
        count=[]
        def interrupted(action):
            count.append(action);original(action);raise KeyboardInterrupt('test interrupted after commit')
        monkeypatch.setattr(env,'execute',interrupted)
        with pytest.raises(KeyboardInterrupt): execute(plan,env,path)
        assert len(count)==1
        pending=replay(path,allow_incomplete=True)
        assert len(pending['accounting']['missing_cell_ids'])==2
        with pytest.raises(IntegrityError): replay(path)
        seal=finalize_interrupted(path)
        assert len(count)==1
    report=replay(path,expected_seal=seal)
    assert report['accounting']['outcome_counts']['UNKNOWN']==2
    assert report['summary']['budget'] is None
    with pytest.raises(IntegrityError): finalize_interrupted(path)


def test_cli_passive_replay(tmp_path):
    with ControlledEnvironment('it-helpdesk') as env:
        plan=amend_cell(control_plan(env),mode='corpus_delivery')
        execute(plan,env,tmp_path/'run')
        manifest=tmp_path/'plan.json';manifest.write_text(plan.model_dump_json())
    for args in (['plan',str(manifest)],['replay',str(tmp_path/'run')]):
        result=subprocess.run([sys.executable,'-m','talos.research',*args],capture_output=True,text=True)
        assert result.returncode==0,result.stderr
        assert json.loads(result.stdout)


@pytest.mark.parametrize('change', [
    {'schema_version':'legacy'}, {'oracle_version':'new-unknown'}, {'timeout_ms':0},
    {'timeout_ms':True}, {'seed':True}, {'run_id':'../old-results'},
    {'purpose':'frozen-held-out-study'}, {'order':'hidden-learning'},
    {'provenance':{'attacker_model_id':'inferred-from-key'}},
    {'provenance':{'target_model_id':'invented'}},
])
def test_run_contract_rejects_versions_hidden_modes_and_invented_models(change):
    with ControlledEnvironment('it-helpdesk') as env:
        raw=control_plan(env).model_dump()
        for key,value in change.items():
            if key=='provenance': raw[key].update(value)
            else: raw[key]=value
        with pytest.raises(ValueError): RunPlan.model_validate(raw)


@pytest.mark.parametrize('kind',['duplicate_cell','duplicate_context','extra_field','missing_limit','negative_limit',
                                 'bool_limit','trust_mismatch','learning_disabled_nonempty'])
def test_run_strict_identity_and_configuration(kind):
    with ControlledEnvironment('it-helpdesk') as env:
        raw=control_plan(env,trust=True,count=2).model_dump()
        if kind=='duplicate_cell': raw['cells'][1]['cell_id']=raw['cells'][0]['cell_id']
        if kind=='duplicate_context': raw['cells'][1]['repeat_id']=raw['cells'][0]['repeat_id']
        if kind=='extra_field': raw['approved_heldout']=True
        if kind=='missing_limit': raw['limits']['amounts'].pop('attacker_calls')
        if kind=='negative_limit': raw['limits']['amounts']['attempts']=-1
        if kind=='bool_limit': raw['limits']['amounts']['attempts']=True
        if kind=='trust_mismatch': raw['trust']['policy_version']='mismatch'
        if kind=='learning_disabled_nonempty': raw['learning']['data']={'hidden':'hints'}
        with pytest.raises(ValueError): RunPlan.model_validate(raw)


def repack(original,destination,transform):
    payloads=read_payloads(original)
    with Recorder(destination,create=True) as r:
        for kind,payload in payloads:
            kind,payload=transform(kind,deepcopy(payload))
            r.append(kind,payload)
        return r.seal()


@pytest.mark.parametrize('damage',['config','learning','order','corpus','reset_context','raw_state','policy_gate',
                                  'duplicate_result','denominator'])
def test_semantic_replay_rejects_even_rehashed_inconsistent_records(tmp_path,damage):
    path=tmp_path/'original'
    with ControlledEnvironment('it-helpdesk',variant='vulnerable') as env:
        execute(control_plan(env,trust=True),env,path)
    def transform(kind,p):
        if kind=='manifest':
            if damage=='config': p['configuration_sha256']='0'*64
            if damage=='learning': p['learning_sha256']='0'*64
            if damage=='order': p['execution_order']=[]
            if damage=='corpus': p['corpus']['records'][0]['case']['objective']='tampered'
        if kind=='action':
            if damage=='reset_context': p['packet']['reset_receipt']['run_id']='different-run'
            if damage=='raw_state': p['packet']['raw_store_records']['snapshots'][0]['state_hash']='0'*64
            if damage=='policy_gate': p['packet']['policy_enabled']=False
        if kind=='summary':
            if damage=='denominator': p['accounting']['planned_cells']=999
            if damage=='duplicate_result':
                kind='result';p=next(v for k,v in read_payloads(path) if k=='result')
        return kind,p
    target=tmp_path/'tampered';repack(path,target,transform)
    with pytest.raises((IntegrityError,ValueError)): replay(target)


def test_exception_counts_requested_call_and_keeps_all_cells(tmp_path,monkeypatch):
    with ControlledEnvironment('it-helpdesk') as env:
        plan=control_plan(env,count=2)
        def failed(action): raise RuntimeError('sensitive text must not enter recorder')
        monkeypatch.setattr(env,'execute',failed)
        execute(plan,env,tmp_path/'run')
    report=replay(tmp_path/'run')
    assert report['accounting']['outcome_counts']['UNKNOWN']==2
    assert report['summary']['budget']['used']['target_calls']==2
    errors=[p for k,p in read_payloads(tmp_path/'run') if k=='interruption']
    assert errors and errors[0]['exception_type']=='RuntimeError' and errors[0]['stack']
    # Exception values are deliberately omitted; structured type/phase/stack remain.
    assert 'sensitive text must not enter recorder' not in json.dumps(errors)


def test_run_provenance_has_actual_versions_source_and_no_secrets(monkeypatch):
    monkeypatch.setenv('ANTHROPIC_API_KEY','secret-value-never-recorded')
    with ControlledEnvironment('it-helpdesk') as env:
        provenance=control_plan(env).provenance
    assert provenance.python
    assert provenance.dependency_versions['pydantic']
    assert len(provenance.source_commit)==40 and len(provenance.source_tree_sha256)==64
    assert provenance.attacker_model_id is None and provenance.target_model_id is None
    assert 'secret-value-never-recorded' not in provenance.model_dump_json()


def test_missing_usage_is_explicit_null_not_zero():
    b=Budget(Limits(amounts={d:10 for d in DIMENSIONS}))
    b.reserve({'input_tokens':2})
    with pytest.raises(BudgetStop): b.settle({'input_tokens':None})
    assert b.snapshot()['used']['input_tokens'] is None
    assert b.snapshot()['missing_dimensions']==['input_tokens']


def test_missing_archive_and_unsealed_tail_are_never_complete(tmp_path):
    with pytest.raises(IntegrityError): verify(tmp_path/'absent',allow_incomplete=True)
    path=tmp_path/'journal'
    with Recorder(path,create=True) as recorder: recorder.append('not-a-run',{})
    with pytest.raises(IntegrityError): verify(path)
    assert verify(path,allow_incomplete=True)


def test_delivery_protocol_has_no_working_adapter():
    from talos.research.delivery import UnavailableDelivery
    adapter=UnavailableDelivery()
    assert not adapter.supported_surfaces
    with pytest.raises(NotImplementedError): adapter.deliver(None,deadline_ns=0)


def test_delivery_receipt_does_not_accept_cross_actor_observations():
    from talos.judging import Action,Observation
    from talos.research.delivery import DeliveryContext,DeliveryReceipt
    context=DeliveryContext(run_id='run',cell_id='cell',target_id='synthetic-target',actor_id='employee',
        authorization_context_id='context',scenario_id='scenario',repeat_id='repeat',case_identity='fixture-identity')
    action=Action(target_id=context.target_id,scenario_id=context.scenario_id,run_id=context.run_id,
        repeat_id=context.repeat_id,action_id='action',actor_id='outsider',
        authorization_context_id=context.authorization_context_id,tool_name='opaque',arguments={})
    with pytest.raises(ValueError):
        DeliveryReceipt(adapter_id='test-not-implemented',adapter_version='1',context=context,status='unknown',
                        reason='synthetic scope validation',observations=(Observation(action=action),))


def test_closed_writer_cannot_seal(tmp_path):
    writer=Recorder(tmp_path/'journal',create=True);writer.close()
    with pytest.raises(IntegrityError): writer.seal()
