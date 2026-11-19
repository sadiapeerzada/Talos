"""No model SDK/network: real isolated fixture tools driven by explicit scripts."""
from pathlib import Path
import json,os,signal,subprocess,sys
import pytest
from talos.readiness import EngineeringPlan,Injection,Reply,ToolCall,execute,replay
from talos.readiness.runtime import run_control,worker_environment
from talos.readiness.replay import validate_control
from talos.research.recorder import Recorder,read_payloads,IntegrityError
from .readiness_helpers import plan


@pytest.mark.parametrize('domain,surface',[('it-helpdesk','direct_user'),('it-helpdesk','tool_output'),
    ('document-management','direct_user'),('document-management','tool_output'),('document-management','retrieved_document')])
@pytest.mark.parametrize('variant',['vulnerable','hardened'])
def test_actual_controlled_delivery_and_private_oracle(tmp_path,domain,surface,variant):
    p=plan(domain,surface,variant);path=tmp_path/'archive';seal=execute(p,path)
    summary=replay(path,expected_seal=seal);result=read_payloads(path,expected_seal=seal)[2][1];control=result['control']
    assert summary['empirical_execution']=='NO-GO' and summary['unknown']==1
    assert control['state']=='COMPLETED' and control['delivery']['consumed_at_request'] is not None
    assert control['actual_provider_usage'] is None and control['primary_eligible'] is False
    assert control['private_packets'][-1]['verdict']['status']==('CONFIRMED' if variant=='vulnerable' else 'BLOCKED')
    assert len(control['private_packets'])==2
    for event in control['public_trace']:
        if event['kind']=='model_request':
            request=event['request'];assert set(request)=={'messages','tools'}
            text=json.dumps(request)
            assert 'private_packets' not in text and 'state_before' not in text and 'verdict' not in text
    assert result['worker_reaped'] is True


@pytest.mark.parametrize('surface',['direct_user','tool_output','retrieved_document'])
def test_missing_consumption_never_claims_delivery(surface):
    domain='document-management';p=plan(domain,surface)
    replies=(p.offline_replies[0],) if surface!='direct_user' else (Reply(text='ordinary reply'),)
    p=EngineeringPlan.model_validate({**p.model_dump(),'offline_replies':replies})
    result=run_control(p);validate_control(p,result)
    assert result['unified_outcome']=='UNKNOWN'
    if surface!='direct_user':
        assert result['control']['state']=='DELIVERY_UNCONSUMED'
        assert result['control']['delivery']['consumed_at_request'] is None


def test_missing_anchor_is_not_a_retrieval_attack():
    p=plan('document-management','retrieved_document');raw=p.model_dump();raw['injection']['anchor_call_id']='absent';p=EngineeringPlan.model_validate(raw)
    result=run_control(p);validate_control(p,result)
    assert result['control']['delivery'] is None and result['control']['state']=='DELIVERY_UNCONSUMED'


@pytest.mark.parametrize('fault',['failed_reset','incomplete_reset'])
def test_reset_fence_no_agent_or_tool_execution(fault):
    p=plan(reset_fault=fault);result=run_control(p);validate_control(p,result)
    assert result['control']['state']=='RESET_FAILED'
    assert result['control']['public_trace']==[] and result['control']['private_packets']==[]


@pytest.mark.parametrize('fault',['failed_tool','rollback_before_commit','missing_audit','contradictory_audit','partial_commit','delayed_audit'])
def test_faults_keep_evidence_and_no_primary(fault,tmp_path):
    p=plan(tool_fault=fault);path=tmp_path/'fault';seal=execute(p,path)
    assert replay(path,expected_seal=seal)['independent_primary_findings'] is None
    result=read_payloads(path,expected_seal=seal)[2][1]
    assert result['unified_outcome']=='UNKNOWN'
    assert result['control']['private_packets']


@pytest.mark.parametrize('fault',['hang','network_probe','process_probe'])
def test_hard_cancellation_and_network_process_denial(fault,tmp_path):
    p=plan(offline_replies=(Reply(fault=fault),),hard_timeout_ms=800 if fault=='hang' else 5000)
    path=tmp_path/'cancel';seal=execute(p,path);summary=replay(path,expected_seal=seal)
    result=read_payloads(path,expected_seal=seal)[2][1]
    assert result['state']==('HARD_TIMEOUT' if fault=='hang' else 'FAILED')
    assert result['worker_reaped'] and result['control'] is None and result['usage_complete'] is False
    with pytest.raises(ProcessLookupError):os.kill(result['worker_pid'],0)
    assert summary['unknown']==1


@pytest.mark.parametrize('dimension',['attempts','elapsed_ms','target_model_calls','target_calls'])
def test_exhausted_budget_prevents_next_interaction(dimension):
    p=plan();raw=p.model_dump();raw['limits']['amounts'][dimension]=0;p=EngineeringPlan.model_validate(raw)
    r=run_control(p);validate_control(p,r)
    if dimension in ('attempts','elapsed_ms'):assert r['state']=='BUDGET_STOP' and r['worker_pid'] is None
    else:
        assert r['control']['state']=='BUDGET_STOP'
        assert r['control']['budget']['used'][dimension]==0


@pytest.mark.parametrize('name',['OPENAI_API_KEY','ANTHROPIC_API_KEY','PYTHONPATH','HOME','HTTP_PROXY','LANGSMITH_API_KEY'])
def test_no_inherited_credentials_or_configuration(monkeypatch,name):
    monkeypatch.setenv(name,'SECRET_MUST_NOT_APPEAR');assert name not in worker_environment()
    result=run_control(plan());assert 'SECRET_MUST_NOT_APPEAR' not in json.dumps(result)


@pytest.mark.parametrize('arm',['A1','A2','A3','A4'])
def test_fresh_state_no_cross_arm_history(arm):
    p=plan(arm=arm);first=run_control(p);second=run_control(p)
    validate_control(p,first);validate_control(p,second)
    a,b=first['control'],second['control']
    assert a['reset']['authorization_context_id']!=b['reset']['authorization_context_id']
    assert a['reset']['target_id']!=b['reset']['target_id']
    assert a['reset']['seed_hash']==b['reset']['seed_hash']
    assert a['public_trace'][0]['request']==b['public_trace'][0]['request']
    assert a['identity']['arm']==arm and a['private_packets'][0]['observation']['action']['action_id'].split(':')[1]==arm


def test_unknown_tool_cannot_reach_private_reader():
    p=plan(offline_replies=(Reply(tool_calls=(ToolCall(call_id='bad',tool_name='reader',arguments={}),)),))
    result=run_control(p);assert result['state']=='FAILED' and result['unified_outcome']=='UNKNOWN'


@pytest.mark.parametrize('field,value',[('surface','imaginary'),('anchor_call_id',None),('anchor_tool',None)])
def test_invalid_indirect_delivery(field,value):
    raw=plan(surface='tool_output').injection.model_dump();raw[field]=value
    with pytest.raises(ValueError):Injection.model_validate(raw)


def test_wrong_document_and_spoofed_direct_source():
    with pytest.raises(ValueError):Injection(surface='retrieved_document',payload='x',anchor_tool='lookup_employee',anchor_call_id='a',document_id='guide')
    with pytest.raises(ValueError):Injection(surface='direct_user',payload='x',anchor_tool='read_document')


def test_unsupported_and_duplicate_calls():
    p=plan(surface='unsupported_workflow');r=run_control(p);validate_control(p,r)
    assert r['control']['state']=='UNSUPPORTED'
    raw=plan().model_dump();raw['offline_replies']=(raw['offline_replies'][0],raw['offline_replies'][0])
    with pytest.raises(ValueError):EngineeringPlan.model_validate(raw)


@pytest.mark.parametrize('mutation',['identity','outcome','primary','payload','consumption','packet','usage','summary','intent','approval'])
def test_resealed_semantic_forgery_rejected(tmp_path,mutation):
    p=plan();source=tmp_path/'source';seal=execute(p,source);events=read_payloads(source,expected_seal=seal)
    r=events[2][1];c=r['control']
    if mutation=='identity':c['identity']['arm']='A4'
    elif mutation=='outcome':r['unified_outcome']='CONFIRMED'
    elif mutation=='primary':c['independent_primary_findings']=1
    elif mutation=='payload':c['delivery']['payload_sha256']='0'*64
    elif mutation=='consumption':c['delivery']['consumed_at_request']=None
    elif mutation=='packet':c['private_packets'][0]['observation']['action']['actor_id']='manager'
    elif mutation=='usage':c['budget']['used']['target_calls']=0
    elif mutation=='summary':events[-1][1]['unknown']=0
    elif mutation=='intent':events[1][1]['identity']['repeat_id']='different'
    else:events[0][1]['readiness']['empirical_execution']='GO'
    forged=tmp_path/'forged'
    with Recorder(forged,create=True) as recorder:
        for kind,payload in events:recorder.append(kind,payload)
        bad=recorder.seal()
    with pytest.raises(ValueError):replay(forged,expected_seal=bad)


def test_seal_and_archive_custody(tmp_path):
    p=plan();path=tmp_path/'archive';seal=execute(p,path)
    with pytest.raises(IntegrityError):replay(path,expected_seal='0'*64)
    with pytest.raises(FileExistsError):execute(p,path)
    next((path/'objects').glob('*.json')).write_text('{}')
    with pytest.raises(IntegrityError):replay(path,expected_seal=seal)


@pytest.mark.parametrize('domain',['it-helpdesk','document-management'])
@pytest.mark.parametrize('variant',['vulnerable','hardened'])
def test_legitimate_task_controls_preserve_authorized_functionality(domain,variant):
    p=plan(domain,variant=variant);raw=p.model_dump()
    if domain=='it-helpdesk':raw['identity']['actor_id']='manager'
    else:raw['offline_replies'][1]['tool_calls'][0]['arguments']={'document_id':'guide','recipient':'manager'}
    p=EngineeringPlan.model_validate(raw);r=run_control(p);validate_control(p,r)
    assert r['control']['private_packets'][-1]['verdict']['status']=='NO_VIOLATION'
    assert r['control']['state']=='COMPLETED' and r['primary_eligible'] is False


def test_model_claim_of_success_without_tools_has_no_finding():
    p=plan(offline_replies=(Reply(text='I changed all permissions successfully.'),));r=run_control(p);validate_control(p,r)
    assert r['control']['private_packets']==[] and r['unified_outcome']=='UNKNOWN'


def test_missing_recorded_evidence_fails_replay():
    p=plan();r=run_control(p);r['control']['private_packets']=[]
    with pytest.raises(ValueError):validate_control(p,r)


@pytest.mark.parametrize('mutation',['private_input','tool_schema','history','ordinary_response','original_hash','limits','elapsed'])
def test_recorded_boundary_and_budget_cannot_be_rewritten(mutation):
    from talos.corpus.models import content_hash
    p=plan(surface='tool_output');r=run_control(p);control=r['control'];trace=control['public_trace']
    request=next(e for e in trace if e['kind']=='model_request')
    if mutation=='private_input':request['request']['private_oracle']={'status':'CONFIRMED'}
    elif mutation=='tool_schema':request['request']['tools']=[]
    elif mutation=='history':request['request']['messages'][1]['content']='different legitimate task'
    elif mutation=='ordinary_response':next(e for e in trace if e['kind']=='tool_response')['message']['content']='invented'
    elif mutation=='original_hash':control['delivery']['original_content_sha256']='0'*64
    elif mutation=='limits':control['budget']['limits']['target_calls']=999
    else:control['budget']['used']['elapsed_ms']=0
    request['request_sha256']=content_hash(request['request'])
    with pytest.raises(ValueError):validate_control(p,r)


def test_exact_call_identity_with_colons_is_preserved():
    p=plan(surface='tool_output');raw=p.model_dump();raw['offline_replies'][0]['tool_calls'][0]['call_id']='call:with:colons'
    raw['injection']['anchor_call_id']='call:with:colons';p=EngineeringPlan.model_validate(raw)
    r=run_control(p);validate_control(p,r)
    assert r['control']['delivery']['source']['call_id']=='call:with:colons'
