"""Offline protocol/fixture controls only; never a model, approval or human label."""
import copy,json,os,sys
from pathlib import Path
import pytest
from talos.pilot import BenignPlan,BenignScope,ModelPlan
from talos.pilot.benign import utility
from talos.pilot.contracts import parse_plan,parse_scope
from talos.pilot.mlx_backend import MLXReplayBackend,MLXModelBackend
from talos.pilot.mlx_limits import MLXBatchLedger
from talos.pilot.mlx_process import OwnedRequest,RequestCancelled
from talos.pilot.runtime import execute
from talos.pilot.replay import replay
from talos.research.recorder import Recorder,read_payloads,IntegrityError
from talos.targets import ControlledEnvironment
from .mlx_helpers import plan as attack_plan,completion
from .pilot_helpers import scope as attack_scope


def benign(domain='it-helpdesk',operations=None):
    base=attack_plan(domain,variant='hardened',max_turns=2)
    default={'tool_name':'lookup_employee','arguments':{'employee_id':'employee'}} if domain=='it-helpdesk' else {'tool_name':'read_document','arguments':{'document_id':'guide'}}
    return BenignPlan.model_validate({**base.model_dump(),'schema_version':'talos.dev-benign-conversation.v1',
        'injection':None,'operations':[default] if operations is None else operations})


def native_call(op):
    return completion('<tool_call>'+json.dumps({'name':op.tool_name,'arguments':op.arguments})+'</tool_call>')


def run(tmp_path,p,raw=None):
    batch=MLXBatchLedger(p.model.batch_id)
    if raw is None:raw=(native_call(p.operations[0]),completion('Synthetic protocol fixture terminal.')) if p.operations else (completion('Synthetic plain reply fixture.'),)
    backend=MLXReplayBackend(p,raw,batch=batch);archive=tmp_path/'archive'
    seal=execute(p,backend,archive);events=read_payloads(archive,expected_seal=seal)
    return events[2][1],events,seal,backend


@pytest.mark.parametrize('domain',['it-helpdesk','document-management'])
def test_real_fixture_utility_is_separate_from_security_and_injection(tmp_path,domain):
    p=benign(domain);value,events,seal,backend=run(tmp_path,p);c=value['control']
    assert c['state']=='COMPLETED' and c['delivery'] is None
    assert value['unified_outcome'] is None and value['security_evaluation']=='NOT_APPLICABLE'
    assert c['legitimate_task_utility']['status']=='SATISFIED_FIXTURE_CHECK'
    assert c['legitimate_task_utility']['answer_quality']=='NOT_ASSESSED'
    assert len(c['private_packets'])==1 and c['private_packets'][0]['policy']['authorization']=='ALLOWED'
    assert c['private_packets'][0]['verdict']['status']=='NO_VIOLATION'
    assert c['private_packets'][0]['evidence']['complete']
    requests=[e['request'] for e in c['public_trace'] if e['kind']=='model_request']
    assert len(requests[0]['messages'])==2
    assert requests[0]['messages'][1]['content']==p.legitimate_task
    for public in requests:
        assert set(public)=={'messages','tools'}
        assert [t['name'] for t in public['tools']]==[p.operations[0].tool_name]
        assert not any(m['role'] in ('oracle','policy','audit','graph') for m in public['messages'])
        assert 'private_packets' not in json.dumps(public) and 'authorization_context_id' not in json.dumps(public)
    summary=replay(tmp_path/'archive',expected_seal=seal)
    assert summary['security_evaluation']=='NOT_APPLICABLE' and 'unknown' not in summary
    assert value['actual_provider_usage'] is None and value['independent_primary_findings'] is None


@pytest.mark.parametrize('domain',['it-helpdesk','document-management'])
def test_plain_model_request_exposes_no_tools(tmp_path,domain):
    p=benign(domain,[]);v,_,seal,_=run(tmp_path,p)
    assert v['control']['public_trace'][0]['request']['tools']==[]
    assert v['control']['private_packets']==[] and v['control']['delivery'] is None
    assert v['legitimate_task_utility']['status']=='PROTOCOL_COMPLETED'
    assert replay(tmp_path/'archive',expected_seal=seal)['state']=='COMPLETED'


@pytest.mark.parametrize('change',[{'injection':{'surface':'direct_user','payload':'dummy'}},
    {'case_identity':'invented-case'},{'common_pool_sha256':'0'*64},{'opportunity_id':'invented'},
    {'schema_version':'talos.dev-model-conversation.v1'}, {'mode':'attack'}])
def test_benign_cannot_be_an_attack_or_fabricated_corpus_binding(change):
    with pytest.raises(ValueError):BenignPlan.model_validate({**benign().model_dump(),**change})


def test_legacy_attack_plan_still_requires_injection():
    with pytest.raises(ValueError):ModelPlan.model_validate({**attack_plan().model_dump(),'injection':None})
    p=attack_plan();assert parse_plan(p)==p and 'mode' not in p.model_dump()


@pytest.mark.parametrize('field,value',[('variant','vulnerable'),('arm','A2'),('partition','TEST')])
def test_benign_scope_is_hardened_dev_only_not_comparative(field,value):
    raw=benign().model_dump();raw['identity'][field]=value
    with pytest.raises(ValueError):BenignPlan.model_validate(raw)


@pytest.mark.parametrize('ops',[[{'tool_name':'private_reader','arguments':{}}],
    [{'tool_name':'lookup_employee','arguments':{'employee_id':'employee','actor_id':'manager'}}],
    [{'tool_name':'lookup_employee','arguments':{'employee_id':'employee'}}]*2])
def test_invalid_or_duplicate_operations_rejected(ops):
    with pytest.raises(ValueError):benign(operations=ops)


@pytest.mark.parametrize('kind',['other_arguments','other_tool','no_tools','metadata_not_policy'])
def test_no_unscoped_or_policy_denied_tool_is_dispatched(tmp_path,monkeypatch,kind):
    p=benign();call={'name':'lookup_employee','arguments':{'employee_id':'outsider'}}
    if kind=='other_tool':call={'name':'approve_expense','arguments':{'expense_id':'expense-1'}}
    if kind=='no_tools':p=benign(operations=[])
    if kind=='metadata_not_policy':
        p=benign(operations=[{'tool_name':'approve_expense','arguments':{'expense_id':'expense-1'}}]);call={'name':'approve_expense','arguments':{'expense_id':'expense-1'}}
    def forbidden(*a,**kw):raise AssertionError('tool dispatch must not occur')
    monkeypatch.setattr(ControlledEnvironment,'execute',forbidden)
    v,_,seal,_=run(tmp_path,p,[completion('<tool_call>'+json.dumps(call)+'</tool_call>')])
    assert v['failure_class']=='PermissionError' and v['control'] is None and v['legitimate_task_utility'] is None
    assert replay(tmp_path/'archive',expected_seal=seal)['state']=='FAILED'


def test_no_called_operation_does_not_satisfy_task(tmp_path):
    p=benign();v,_,seal,_=run(tmp_path,p,[completion('I claim success without using a tool.')])
    assert v['legitimate_task_utility']['status']=='NOT_SATISFIED'
    assert replay(tmp_path/'archive',expected_seal=seal)['state']=='COMPLETED'


@pytest.mark.parametrize('mutation',['missing_evidence','contradictory','failed_tool','rollback'])
def test_utility_abstains_on_incomplete_or_failed_evidence(tmp_path,mutation):
    p=benign();v,_,_,_=run(tmp_path,p);c=copy.deepcopy(v['control']);packet=c['private_packets'][0]
    if mutation=='missing_evidence':packet['evidence']['complete']=False
    if mutation=='contradictory':packet['reader_issues']=['contradictory evidence']
    if mutation in ('failed_tool','rollback'):packet['observation']['events'][0]['status']='FAILED' if mutation=='failed_tool' else 'ROLLED_BACK'
    assert utility(p,c)['status']=='UNKNOWN'


@pytest.mark.parametrize('mutation',['delivery','utility','security','history'])
def test_benign_replay_rejects_resealed_fabrications(tmp_path,mutation):
    p=benign();v,events,_,_=run(tmp_path,p)
    if mutation=='delivery':v['control']['delivery']={'fabricated':'receipt'}
    if mutation=='utility':v['control']['legitimate_task_utility']['satisfied_operations']=900
    if mutation=='security':v['unified_outcome']='CONFIRMED'
    if mutation=='history':v['control']['public_trace'][0]['request']['tools'].append({'name':'private_oracle'})
    with Recorder(tmp_path/'tampered',create=True) as recorder:
        for kind,payload in events:recorder.append(kind,payload)
        seal=recorder.seal()
    with pytest.raises((IntegrityError,ValueError,KeyError)):replay(tmp_path/'tampered',expected_seal=seal)


def test_benign_scope_uses_no_fake_families_graph_or_cases():
    raw=attack_scope(attack_plan()).model_dump()
    for k in ('common_pool_sha256','corpus_sha256','graph_sha256'):raw[k]=None
    raw.update(schema_version='talos.DEV-benign-approval-scope.v1',dev_family_ids=(),permitted_surfaces=())
    s=BenignScope.model_validate(raw);assert parse_scope(s)==s
    with pytest.raises(ValueError):BenignScope.model_validate({**raw,'permitted_surfaces':['direct_user']})


def test_missing_native_usage_halts_benign_batch(tmp_path):
    p=benign();v,_,seal,backend=run(tmp_path,p,[completion('No reliable usage.',generation_tokens=None)])
    assert backend.batch.closed and v['control'] is None
    assert v['budget']['used']['input_tokens'] is None and v['legitimate_task_utility'] is None
    assert replay(tmp_path/'archive',expected_seal=seal)['state']=='FAILED'


def test_no_authority_cannot_spawn_a_benign_worker(tmp_path,monkeypatch):
    p=benign();raw=attack_scope(attack_plan()).model_dump()
    raw.update(schema_version='talos.DEV-benign-approval-scope.v1',plan_sha256=p.digest(),
        common_pool_sha256=None,corpus_sha256=None,graph_sha256=None,dev_family_ids=(),permitted_surfaces=())
    def forbidden(*a,**kw):raise AssertionError('no model process permitted')
    monkeypatch.setattr(OwnedRequest,'run',forbidden)
    backend=MLXModelBackend(p,BenignScope.model_validate(raw),batch=MLXBatchLedger(p.model.batch_id),python_path=Path(sys.executable))
    seal=execute(p,backend,tmp_path/'denied');v=read_payloads(tmp_path/'denied',expected_seal=seal)[2][1]
    assert v['failure_class']=='PermissionError' and not backend.receipts and backend.active is None


@pytest.mark.parametrize('stream',['stdout','stderr'])
def test_native_worker_output_is_bounded_and_reaped_without_a_model(stream):
    request=OwnedRequest();fd=1 if stream=='stdout' else 2
    with pytest.raises(ValueError,match='stream ceiling'):
        request.run([sys.executable,'-c',f'import os; os.write({fd}, b"x" * 2100000)'],{},5000)
    assert request.process.poll() is not None
    assert request.diagnostics[stream]['bytes_retained']<=2000000


def test_non_model_worker_roundtrip_and_private_stderr():
    request=OwnedRequest();result=request.run([sys.executable,'-c',
        'import json,sys; x=json.load(sys.stdin); print(json.dumps(x)); print("private diagnostics",file=sys.stderr)'],{'offline_fixture':True},5000)
    assert result=={'offline_fixture':True} and request.process.poll()==0
    assert 'private diagnostics' in request.diagnostics['stderr_text']


def test_worker_rejects_oversized_input_before_spawn():
    request=OwnedRequest()
    with pytest.raises(ValueError):request.run([sys.executable,'-c','pass'],{'x':'x'*1000001},5000)
    assert request.process is None


@pytest.mark.parametrize('domain',['it-helpdesk','document-management'])
@pytest.mark.parametrize('fault',['failed_tool','rollback_before_commit','missing_audit','contradictory_audit'])
def test_real_fixture_failures_never_pass_benign_utility(tmp_path,monkeypatch,domain,fault):
    from talos.targets.store import Fault
    original=ControlledEnvironment.inject_fault_once
    monkeypatch.setattr(ControlledEnvironment,'inject_fault_once',lambda env,_:original(env,Fault(fault)))
    p=benign(domain);v,_,seal,backend=run(tmp_path,p)
    assert v['legitimate_task_utility']['status']=='UNKNOWN' and backend.batch.closed
    assert replay(tmp_path/'archive',expected_seal=seal)['security_evaluation']=='NOT_APPLICABLE'


def test_incomplete_reset_makes_no_model_request(tmp_path,monkeypatch):
    original=ControlledEnvironment.reset
    def unhealthy(env,**kwargs):return original(env,**kwargs).model_copy(update={'healthy':False})
    monkeypatch.setattr(ControlledEnvironment,'reset',unhealthy)
    p=benign();v,_,seal,backend=run(tmp_path,p)
    assert v['control']['state']=='RESET_FAILED' and not backend.receipts and backend.batch.closed
    assert v['legitimate_task_utility']['status']=='UNKNOWN'
    assert replay(tmp_path/'archive',expected_seal=seal)['state']=='RESET_FAILED'


def test_python_audit_is_demonstrably_not_filesystem_containment(tmp_path):
    # Fresh harmless canary, never an existing user or target-private file.
    canary=tmp_path/'new-canary';canary.write_text('offline containment probe')
    source=str(Path(__file__).resolve().parents[1])
    code=('import sys,json; from pathlib import Path; sys.path.insert(0,'+repr(source)+'); '
          'from talos.pilot.mlx_worker import audit; sys.addaudithook(audit); '
          'print(json.dumps({"can_read_canary_outside_worker_temp":Path('+repr(str(canary))+').read_text()=="offline containment probe"}))')
    result=OwnedRequest().run([sys.executable,'-c',code],{},5000)
    assert result=={'can_read_canary_outside_worker_temp':True}


def test_authorization_request_has_no_supplied_authorities_or_grants():
    from talos.pilot.first_run import request_packet
    packet=request_packet()
    assert packet['operational_DEV']=='NO-GO' and not packet['inference_enabled']
    assert all(v is None for v in packet['authority_assignments'].values())
    assert all(v is None for v in packet['required_evidence'].values())
    assert packet['authenticated_registry_sha256'] is None and packet['signed_approvals'] is None
    assert packet['approved_targets'] is None and packet['approved_DEV_cases'] is None
    assert packet['proposed_ordered_protocol'][1]['operations']==[]


def test_benign_control_cannot_enter_attack_bridge_or_http():
    from talos.pilot.bridge import FourArmBridge
    from talos.pilot.backend import LocalModelBackend
    p=benign()
    with pytest.raises(PermissionError):FourArmBridge.deliver(None,None,None,p,None,None)
    with pytest.raises(PermissionError):LocalModelBackend(p,None)


def test_completed_tool_without_terminal_model_reply_is_not_completed_utility(tmp_path):
    p=benign().model_copy(update={'max_turns':1})
    v,events,_,_=run(tmp_path,p,[native_call(p.operations[0])])
    assert v['control']['state']=='INCOMPLETE' and v['legitimate_task_utility']['status']=='UNKNOWN'
    v['control']['state']='COMPLETED';events[-1][1]['state']='COMPLETED'
    with Recorder(tmp_path/'forged-terminal',create=True) as recorder:
        for kind,payload in events:recorder.append(kind,payload)
        seal=recorder.seal()
    with pytest.raises(IntegrityError):replay(tmp_path/'forged-terminal',expected_seal=seal)
