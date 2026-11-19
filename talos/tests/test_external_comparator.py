"""Synthetic contract tests; receipts below are declared doubles, never findings."""
import json
from pathlib import Path
import pytest
from pydantic import ValidationError
from .ablation_helpers import block,plan as ablation_plan
from talos.comparator.contracts import Config,Mapping,Plan,NativeReceipt,NormalizedResult
from talos.comparator.isolation import bundle_identity,lock_hash,worker_environment,native_control,deterministic_projection
from talos.comparator.matching import dry_run,match_block,matched_ceilings
from talos.comparator.measurement import normalize_control
from talos.comparator.runtime import execute
from talos.comparator.replay import replay
from talos.corpus.models import content_hash,Surface
from talos.research.contracts import Limits,DIMENSIONS
from talos.research.recorder import Recorder,read_payloads,IntegrityError


def proposal(domain='it-helpdesk',**changes):
    b=block(domain);p=ablation_plan((b,));policy=b.target_profile.authorization_boundaries[0]
    mappings=tuple(Mapping(opportunity_id=o.opportunity_id,target_id=b.target_profile.target_id,profile_sha256=b.target_profile.digest(),
        actor_id='explicit-test-actor',authorization_context_reference='synthetic-declaration-not-approval',policy_id=policy.policy_id,
        policy_version=policy.policy_version,reset_contract=b.reset_contract,surface=o.stimuli[0].surface,
        shared_objective='Synthetic test objective; no approved opportunity equivalence.') for o in b.pool.opportunities)
    amounts={d:0 for d in DIMENSIONS};amounts.update(attempts=20,attacker_calls=20,target_calls=20,elapsed_ms=1000000)
    raw=dict(comparison_id='offline-test-only',provenance=p.provenance,config=Config(max_turns=2,seed=7),
        dependency_lock_sha256=lock_hash(),framework_identity_sha256=content_hash(bundle_identity()),target_profile=b.target_profile,
        pool=b.pool,mappings=mappings,common_limits=Limits(amounts=amounts),initialization_reserve_ms=1000,attempt_timeout_ms=1000)
    raw.update(changes);return Plan(**raw)


def receipt(p):
    return NativeReceipt(source_files=bundle_identity()['source_files'],config_sha256=content_hash(p.config),
        objective_sha256=content_hash(p.mappings[0].shared_objective),events=(),native_outcome='synthetic-success-diagnostic',
        native_scores=({'score_value':'true'},),raw_result={'declared_test_double':True},counts={'adversarial_stub':0,'objective_stub':0},
        environment={'test_double':True},phase_elapsed_ms={'framework_initialization':0,'native_execution':0})


@pytest.mark.parametrize('field,value',[('framework_version','latest'),('provider_execution','ENABLED'),('plugins',('remote',)),
    ('seed',True),('max_turns',0),('max_turns',11),('max_turns',True),('score_as_adversarial_feedback',True),('strategy','talos_selector')])
def test_configuration_rejects_unsafe_or_unpinned(field,value):
    with pytest.raises(ValidationError):Config(**{**dict(max_turns=2,seed=7),field:value})


@pytest.mark.parametrize('secret',['OPENAI_API_KEY','ANTHROPIC_API_KEY','PYTHONPATH','HTTP_PROXY','HOME','PYRIT_CONFIG','LANGSMITH_API_KEY'])
def test_environment_does_not_inherit_credentials(monkeypatch,secret):
    monkeypatch.setenv(secret,'do-not-inherit');assert secret not in worker_environment(7)


@pytest.mark.parametrize('domain',['it-helpdesk','document-management'])
def test_portable_complete_mapping(domain):
    p=proposal(domain);report=dry_run(p)
    assert len(report['cells'])==len(p.pool.opportunities)
    assert {c['status'] for c in report['cells']}=={'DELIVERY_UNAVAILABLE','SURFACE_UNSUPPORTED'}
    assert report['gates']['analysis_primary']=='A2-A1_unchanged'
    assert match_block(p,block(domain),p.common_limits,actor_id='explicit-test-actor',authorization_context_reference='synthetic-declaration-not-approval')['execution']=='BLOCKED'


@pytest.mark.parametrize('field,value',[('mappings',()),('dependency_lock_sha256','0'*64),('framework_identity_sha256','0'*64)])
def test_identity_and_completeness(field,value):
    with pytest.raises(ValueError):dry_run(proposal(**{field:value}))


@pytest.mark.parametrize('field,value',[('target_id','different'),('profile_sha256','0'*64),('policy_version','unreviewed'),('actor_id',''),('surface','tool_output')])
def test_mapping_mismatches(field,value):
    p=proposal();raw=p.model_dump();raw['mappings'][0][field]=value
    with pytest.raises(ValueError):Plan.model_validate(raw)


def test_duplicate_and_schema_versions():
    p=proposal();raw=p.model_dump();raw['mappings']+=(raw['mappings'][0],)
    with pytest.raises(ValueError):Plan.model_validate(raw)
    with pytest.raises(ValueError):Plan.model_validate({**p.model_dump(),'schema_version':'future'})


@pytest.mark.parametrize('dimension',sorted(DIMENSIONS))
def test_unequal_ceilings(dimension):
    p=proposal();amounts=dict(p.common_limits.amounts);amounts[dimension]+=1
    with pytest.raises(ValueError):matched_ceilings(p.common_limits,Limits(amounts=amounts))


@pytest.mark.parametrize('field,value',[('actor_id','other'),('authorization_context_reference','other')])
def test_counterpart_custody_mismatch(field,value):
    p=proposal();kw=dict(actor_id='explicit-test-actor',authorization_context_reference='synthetic-declaration-not-approval');kw[field]=value
    with pytest.raises(ValueError):match_block(p,block(),p.common_limits,**kw)


def test_counterpart_target_mismatch():
    p=proposal()
    with pytest.raises(ValueError):match_block(p,block('document-management'),p.common_limits,actor_id='a',authorization_context_reference='b')


@pytest.mark.parametrize('outcome',['success','failure','undetermined','synthetic-success-diagnostic'])
def test_native_scores_never_confirm(outcome):
    p=proposal();r=receipt(p).model_copy(update={'native_outcome':outcome});row=normalize_control('test',r)
    assert row.unified_outcome=='UNKNOWN' and row.independently_confirmed_primary_count is None
    assert deterministic_projection(r)['native_outcome']==outcome
    with pytest.raises(ValueError):NormalizedResult.model_validate({**row.model_dump(),'unified_outcome':'CONFIRMED'})


@pytest.mark.parametrize('field,value',[('counts',{'adversarial_stub':1,'objective_stub':0}),('actual_agent_delivery','COMPLETE'),
    ('tokens',0),('cost',0),('provider_model_ids','invented-model'),('phase_elapsed_ms',{})])
def test_invalid_receipt(field,value):
    with pytest.raises(ValueError):NativeReceipt.model_validate({**receipt(proposal()).model_dump(),field:value})


def test_archive_default_and_replay(tmp_path):
    p=proposal();path=tmp_path/'archive';seal=execute(p,path);summary=replay(path,expected_seal=seal)
    assert summary['unified_unknown']==3 and summary['independent_primary_findings'] is None
    assert summary['native_diagnostic_controls']==0
    with pytest.raises(FileExistsError):execute(p,path)
    with pytest.raises(IntegrityError):replay(path,expected_seal='0'*64)
    next((path/'objects').glob('*.json')).write_text('{}')
    with pytest.raises(IntegrityError):replay(path,expected_seal=seal)


def test_incomplete_archive(tmp_path):
    path=tmp_path/'archive'
    with Recorder(path,create=True) as recorder:recorder.append('comparator_manifest',{})
    with pytest.raises(IntegrityError):replay(path,expected_seal='0'*64)


def test_missing_native_usage_stops_and_retains_unknown(monkeypatch,tmp_path):
    import talos.comparator.runtime as runtime
    p=proposal();scripts={p.mappings[0].opportunity_id:{'adversarial_messages':['a','b'],'objective_responses':['c','d'],'marker':'d'}}
    def failed(*a,**kw):raise RuntimeError('synthetic failure')
    monkeypatch.setattr(runtime,'native_control',failed)
    path=tmp_path/'failed';seal=execute(p,path,isolated_python=Path('/not-used'),offline_scripts=scripts)
    summary=replay(path,expected_seal=seal)
    assert summary['states']=={'ERROR':1,'BUDGET_STOP':2}
    assert summary['budget']['used']['attacker_calls'] is None
    assert summary['unified_unknown']==3


def test_budget_stop_before_native_call(tmp_path):
    p=proposal();raw=p.model_dump();raw['common_limits']['amounts']['attacker_calls']=0;p=Plan.model_validate(raw)
    scripts={p.mappings[0].opportunity_id:{'adversarial_messages':['a','b'],'objective_responses':['c','d'],'marker':'d'}}
    path=tmp_path/'exhausted';seal=execute(p,path,isolated_python=Path('/not-used'),offline_scripts=scripts)
    assert replay(path,expected_seal=seal)['states']=={'BUDGET_STOP':3}


def test_explicit_interpreter_and_exact_scripts_required(tmp_path):
    p=proposal()
    with pytest.raises(ValueError):execute(p,tmp_path/'a',isolated_python=Path('/x'))
    with pytest.raises(ValueError):execute(p,tmp_path/'b',isolated_python=Path('/x'),offline_scripts={})


def test_native_control_preflight_no_import_or_launch():
    with pytest.raises(ValueError):native_control(Config(max_turns=2,seed=7),objective='x',marker='x',
        adversarial_messages=('a',),objective_responses=('b',),python=Path('/not-present'),timeout_ms=10)


def test_no_talos_selector_or_pyrit_import_in_main_process():
    import sys
    assert 'pyrit' not in sys.modules
    import talos.comparator.runtime as runtime
    source=Path(runtime.__file__).read_text()
    assert 'talos.ablation' not in source and 'render' not in source


@pytest.mark.parametrize('domain',['it-helpdesk','document-management'])
@pytest.mark.parametrize('fault',['none','missing_audit','rollback_before_commit','contradictory_audit'])
def test_same_oracle_evidence_path_and_no_independent_primary(tmp_path,domain,fault,request):
    from talos.targets import ControlledEnvironment
    from talos.research import execute as research_execute
    from .research_helpers import control_plan
    from talos.comparator.measurement import common_oracle_observer
    environment=ControlledEnvironment(domain,variant='vulnerable');request.addfinalizer(environment.close)
    p=control_plan(environment,trust=True);raw=p.model_dump();raw['cells'][0]['tool_fault']=fault
    from talos.research.contracts import RunPlan
    p=RunPlan.model_validate(raw);path=tmp_path/'evidence';seal=research_execute(p,environment,path)
    actions=[v['packet']['observation']['action']['action_id'] for k,v in read_payloads(path,expected_seal=seal) if k=='action']
    assert actions
    observed=common_oracle_observer(path,expected_seal=seal,action_id=actions[-1])
    assert observed['native_score_used_as_evidence'] is False and observed['primary_count'] is None
    if fault in ('rollback_before_commit','contradictory_audit'):assert observed['verdict']['status']!='CONFIRMED'
    with pytest.raises(ValueError):common_oracle_observer(path,expected_seal=seal,action_id='invented')


@pytest.mark.parametrize('mutation',['primary','unknown','omission','budget','usage','projection','event','manifest'])
def test_resealed_semantic_forgery_rejected(tmp_path,mutation):
    p=proposal();source=tmp_path/'source';seal=execute(p,source);events=read_payloads(source,expected_seal=seal)
    if mutation=='primary':events[-1][1]['independent_primary_findings']=1
    elif mutation=='unknown':events[1][1]['result']['unified_outcome']='CONFIRMED'
    elif mutation=='omission':events.pop(1)
    elif mutation=='budget':events[1][1]['budget']['used']['attacker_calls']=1
    elif mutation=='usage':events[1][1]['provider_tokens']=0
    elif mutation=='projection':events[1][1]['semantic_projection']={'made_up':True}
    elif mutation=='event':events.insert(1,('unreviewed_event',{}))
    else:events[0][1]['plan_sha256']='0'*64
    target=tmp_path/'forged'
    with Recorder(target,create=True) as recorder:
        for kind,payload in events:recorder.append(kind,payload)
        forged=recorder.seal()
    with pytest.raises(ValueError):replay(target,expected_seal=forged)


def test_exact_upstream_registry_version(monkeypatch,tmp_path):
    import talos.comparator.isolation as isolation
    identity=bundle_identity();identity['version']='1.2.0';(tmp_path/'upstream_identity.json').write_text(json.dumps(identity))
    monkeypatch.setattr(isolation,'bundle_root',lambda:tmp_path)
    with pytest.raises(ValueError):isolation.bundle_identity()


def test_mixed_surface_cannot_be_hidden():
    p=proposal();raw=p.model_dump();raw['mappings'][1]['surface']='user_message'
    with pytest.raises(ValueError):Plan.model_validate(raw)


@pytest.mark.parametrize('mutation',['role','text','feedback','gap','odd'])
def test_native_trace_conversion_rejects_inconsistency(mutation):
    raw=receipt(proposal()).model_dump();events=[]
    for index in range(2):
        events.extend([{'sequence':index*2,'role':'adversarial_stub','request_text':'objective' if index==0 else 'response',
            'response_text':json.dumps({'next_message':'generated'})},
            {'sequence':index*2+1,'role':'objective_stub','request_text':'generated','response_text':'response'}])
    raw['events']=events;raw['counts']={'adversarial_stub':2,'objective_stub':2}
    NativeReceipt.model_validate(raw)
    if mutation=='role':events[0]['role']='objective_stub'
    elif mutation=='text':events[1]['request_text']='substituted'
    elif mutation=='feedback':events[2]['request_text']='not previous response'
    elif mutation=='gap':events[2]['sequence']=10
    else:events.pop()
    with pytest.raises(ValueError):NativeReceipt.model_validate(raw)
