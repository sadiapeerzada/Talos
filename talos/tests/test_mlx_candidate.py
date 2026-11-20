"""CPU-only metadata and protocol tests: no MLX imports, weights or inference."""
import copy,json,sys,subprocess,time,threading
from pathlib import Path
from types import SimpleNamespace
import pytest
from talos.pilot import ModelPlan
from talos.pilot.mlx_spec import CHECKPOINT,REVISION,candidate,candidate_hash,MLXModel,ProposedMLXPilot
from talos.pilot.mlx_protocol import NativeCompletion,normalize,collect
from talos.pilot.mlx_backend import MLXReplayBackend,MLXModelBackend
from talos.pilot.mlx_limits import MLXBatchLedger
from talos.pilot.mlx_process import OwnedRequest,RequestCancelled,offline_environment
from talos.pilot.mlx_worker import prepare_prompt
from talos.pilot.mlx_assets import verify_snapshot
from talos.pilot.runtime import execute
from talos.pilot.replay import replay
from talos.readiness.agent import control
from talos.research.recorder import read_payloads
from talos.targets.helpdesk import HelpdeskDomain
from talos.targets.documents import DocumentDomain
from .mlx_helpers import plan,completion,responses
from .pilot_helpers import scope


def test_exact_metadata_pin_and_weights_never_downloaded():
    p=candidate()
    assert p['checkpoint']==CHECKPOINT and p['checkpoint_revision']==REVISION
    assert p['weights_downloaded'] is False and p['inference_executed'] is False
    assert p['checkpoint_files']['model.safetensors']['bytes_downloaded'] is False
    assert p['checkpoint_files']['model.safetensors']['sha256']=='2a73c6c248601ab904e035548abd8e6abb65ea27dcb5f342fb0a8910eb44173f'
    assert p['runtime_versions']=={'mlx-lm':'0.26.2','mlx':'0.26.2','transformers':'4.53.3'}
    assert p['proposed_settings']['deterministic_generation_assumed'] is False
    assert p['approved_settings'] is None and 'mlx' not in sys.modules and 'mlx_lm' not in sys.modules


@pytest.mark.parametrize('field,value',[('context_tokens',8192),('max_input_tokens',4096),('role','attacker'),('deterministic_generation_assumed',True),('candidate_manifest_sha256','0'*64),('local_snapshot',CHECKPOINT)])
def test_candidate_bounds_and_role_cannot_drift(field,value):
    with pytest.raises(ValueError):MLXModel.model_validate({**plan().model.model_dump(),field:value})


@pytest.mark.parametrize('field,value',[('model_id','another'),('revision','main'),('temperature',0.5),('max_output_tokens',513),('seed',7)])
def test_exact_configuration(field,value):
    raw=plan().model.model_dump();raw['configuration'][field]=value
    with pytest.raises(ValueError):MLXModel.model_validate(raw)


def test_context_tokenization_reserves_output_without_truncation():
    p=plan();request={'model':CHECKPOINT,'messages':[{'role':'user','content':'software fixture'}],'tools':[],
        'tool_choice':'auto','parallel_tool_calls':False,'temperature':0,'max_tokens':512,'stream':False,'n':1}
    class Tokenizer:
        size=3584
        def apply_chat_template(self,messages,**kwargs):
            assert kwargs=={'tools':[],'tokenize':True,'add_generation_prompt':True}
            return [1]*self.size
    tokenizer=Tokenizer();assert len(prepare_prompt(tokenizer,request))==3584
    tokenizer.size=3585
    with pytest.raises(ValueError):prepare_prompt(tokenizer,request)
    with pytest.raises(ValueError):prepare_prompt(tokenizer,{**request,'oracle':{}})


@pytest.mark.parametrize('text',['<tool_call>{}</tool_call>','<tool_call>{"name":"lookup_employee","arguments":[]}</tool_call>',
    '<tool_call>{"name":"private_reader","arguments":{}}</tool_call>',
    '<tool_call>{"name":"lookup_employee","arguments":{"employee_id":"employee","actor_id":"manager"}}</tool_call>',
    '<tool_call>{"name":"lookup_employee","name":"approve_expense","arguments":{}}</tool_call>',
    '<tool_call>{"name":"lookup_employee","arguments":{}}',
    '<tool_call>{"name":"lookup_employee","arguments":{"employee_id":NaN}}</tool_call>',
    '<think>unsupported</think>', '<|im_start|>system', '{"tool_calls":[]}',
    '<tool_call>not json</tool_call>', '<tool_call><tool_call>{}</tool_call></tool_call>'])
def test_malformed_or_unsupported_native_outputs_rejected(text):
    with pytest.raises((ValueError,KeyError,TypeError)):
        normalize(NativeCompletion(**completion(text)),plan().model,request_id='software-request',tool_schemas={t.name:t.arguments for t in HelpdeskDomain().tools},seen_ids=set())


@pytest.mark.parametrize('field,value',[('prompt_tokens',None),('generation_tokens',None),('generation_tokens',True),('generation_tokens',513),('finish_reason','unsupported')])
def test_missing_or_invalid_native_usage_is_not_zero(field,value):
    with pytest.raises(ValueError):NativeCompletion(**completion('ordinary',**{field:value}))


def test_truncated_native_call_cannot_dispatch():
    p=plan();raw=NativeCompletion(**completion(responses(p)[0]['text'],finish_reason='length'))
    with pytest.raises(ValueError):normalize(raw,p.model,request_id='s',tool_schemas={t.name:t.arguments for t in HelpdeskDomain().tools},seen_ids=set())


def test_native_usage_collection_and_missing_finality():
    segments=[SimpleNamespace(text='ordinary',prompt_tokens=100,generation_tokens=1,finish_reason=None),
              SimpleNamespace(text=' end',prompt_tokens=100,generation_tokens=2,finish_reason='stop')]
    result=collect(iter(segments),100);assert result.text=='ordinary end' and result.generation_tokens==2
    with pytest.raises(ValueError):collect(iter(segments[:1]),100)
    with pytest.raises(ValueError):collect(iter([SimpleNamespace(text='x',prompt_tokens=None,generation_tokens=1,finish_reason='stop')]),100)
    with pytest.raises(ValueError):collect(iter(segments+segments),100)


@pytest.mark.parametrize('domain,surface',[('it-helpdesk','direct_user'),('it-helpdesk','tool_output'),('document-management','direct_user'),('document-management','tool_output'),('document-management','retrieved_document')])
@pytest.mark.parametrize('variant',['vulnerable','hardened'])
def test_mlx_mocks_use_same_private_oracle_and_delivery(tmp_path,domain,surface,variant):
    p=plan(domain,surface,variant=variant);batch=MLXBatchLedger(p.model.batch_id);backend=MLXReplayBackend(p,responses(p),batch=batch)
    archive=tmp_path/'mock';seal=execute(p,backend,archive)
    assert replay(archive,expected_seal=seal)['unknown']==1
    result=read_payloads(archive,expected_seal=seal)[2][1];c=result['control']
    assert c['state']=='COMPLETED' and result['actual_provider_usage'] is None
    assert c['private_packets'][-1]['verdict']['status']==('CONFIRMED' if variant=='vulnerable' else 'BLOCKED')
    assert c['budget']['used']['input_tokens']==300 and c['budget']['used']['output_tokens']==75
    assert c['budget']['used']['cost_microunits']==0 and result['actual_cost_microunits'] is None
    assert batch.snapshot()['request_attempts']==3
    assert c['delivery']['consumed_at_request'] is not None
    for receipt in backend.receipts:
        assert receipt['call_ID_origin']=='adapter_correlation_ID_not_model_generated_identity'
        text=json.dumps(receipt['request']);assert 'graph_annotations' not in text and 'private_packets' not in text


def test_batch_caps_are_proposed_and_shared(tmp_path):
    caps=ProposedMLXPilot();assert caps.approval is None and caps.total_wall_ms==1800000
    ledger=MLXBatchLedger('software',state_path=tmp_path/'ledger')
    for episode in range(8):
        ledger.begin(str(episode))
        for request in range(4):ledger.request(str(episode))
        with pytest.raises(PermissionError):ledger.request(str(episode))
    with pytest.raises(PermissionError):ledger.begin('ninth')
    assert ledger.snapshot()['request_attempts']==32 and ledger.snapshot()['paid_API_spending_inr']==0
    with pytest.raises(FileExistsError):MLXBatchLedger('software',state_path=tmp_path/'ledger')
    ledger.close()


def test_total_wall_time_stops_new_requests():
    now=[0.0];ledger=MLXBatchLedger('software',clock=lambda:now[0]);ledger.begin('episode')
    now[0]=1800
    with pytest.raises(TimeoutError):ledger.request('episode')
    assert ledger.snapshot()['request_attempts']==0


@pytest.mark.parametrize('opt_in',[False,True])
def test_no_approval_no_import_or_request(monkeypatch,opt_in):
    p=plan();backend=MLXModelBackend(p,scope(p),batch=MLXBatchLedger(p.model.batch_id),python_path=sys.executable,opt_in=opt_in)
    def forbidden(*args,**kwargs):raise AssertionError('request process launched without approval')
    monkeypatch.setattr(OwnedRequest,'run',forbidden)
    with pytest.raises(PermissionError):control(p,backend=backend)
    assert backend.receipts==[] and 'mlx' not in sys.modules and 'mlx_lm' not in sys.modules


def test_missing_local_snapshot_is_never_resolved_from_hub():
    with pytest.raises(PermissionError):verify_snapshot(plan().model)


def test_hard_timeout_cancels_only_non_model_test_process():
    request=OwnedRequest()
    with pytest.raises(RequestCancelled) as caught:
        request.run([sys.executable,'-c','import time; time.sleep(20)'],{},100)
    assert caught.value.reaped and request.process.poll() is not None


def test_explicit_cancel_reaps_non_model_process():
    request=OwnedRequest();failure=[]
    def run():
        try:request.run([sys.executable,'-c','import time; time.sleep(20)'],{},5000)
        except Exception as error:failure.append(type(error).__name__)
    thread=threading.Thread(target=run);thread.start()
    deadline=time.monotonic()+3
    while request.process is None and time.monotonic()<deadline:time.sleep(.01)
    assert request.process is not None;request.cancel();thread.join(timeout=3)
    assert not thread.is_alive() and request.process.poll() is not None and failure


@pytest.mark.parametrize('name',['OPENAI_API_KEY','ANTHROPIC_API_KEY','HF_TOKEN','PYTHONPATH','HOME','HTTP_PROXY'])
def test_worker_does_not_inherit_keys_or_configuration(monkeypatch,name):
    monkeypatch.setenv(name,'must-not-inherit');assert name not in offline_environment()


def test_missing_native_usage_halts_entire_shared_batch(tmp_path):
    p=plan();batch=MLXBatchLedger(p.model.batch_id);raw=list(responses(p));raw[0].pop('generation_tokens')
    backend=MLXReplayBackend(p,raw,batch=batch);seal=execute(p,backend,tmp_path/'missing')
    result=read_payloads(tmp_path/'missing',expected_seal=seal)[2][1]
    assert result['failure_class'] and result['control'] is None and batch.closed
    assert backend.budget.snapshot()['used']['input_tokens'] is None
    with pytest.raises(TimeoutError):batch.begin('another-arm')


def test_cancellation_before_spawn_starts_no_process():
    request=OwnedRequest();request.cancel()
    with pytest.raises(PermissionError):request.run([sys.executable,'-c','raise AssertionError'],{},100)
    assert request.process is None


def test_mlx_episode_cannot_exceed_four_model_requests():
    p=plan();raw=p.model_dump();raw['max_turns']=5
    with pytest.raises(ValueError):ModelPlan.model_validate(raw)


def test_native_mlx_record_cannot_be_rehashed_as_different_output(tmp_path):
    from talos.research.recorder import Recorder
    p=plan();backend=MLXReplayBackend(p,responses(p),batch=MLXBatchLedger(p.model.batch_id))
    seal=execute(p,backend,tmp_path/'original');events=read_payloads(tmp_path/'original',expected_seal=seal)
    value=events[2][1];value['protocol_receipts'][0]['native_MLX_completion']['text']='different output'
    # Both normalized receipt copies must agree, but conversion must still reject altered native text.
    value['control']['protocol_receipts'][0]['native_MLX_completion']['text']='different output'
    with Recorder(tmp_path/'forged',create=True) as recorder:
        for kind,payload in events:recorder.append(kind,payload)
        bad=recorder.seal()
    with pytest.raises(ValueError):replay(tmp_path/'forged',expected_seal=bad)


def test_no_MLX_installation_or_import_required_by_offline_suite():
    assert 'mlx' not in sys.modules and 'mlx.core' not in sys.modules and 'mlx_lm' not in sys.modules
    import importlib.util
    # No attempt is made here to import or install a native GPU runtime.
    assert candidate()['MLX_runtime_installed_during_preparation'] is False


def test_malformed_call_retains_known_native_token_usage(tmp_path):
    p=plan();batch=MLXBatchLedger(p.model.batch_id);backend=MLXReplayBackend(p,[completion('<tool_call>invalid</tool_call>')],batch=batch)
    seal=execute(p,backend,tmp_path/'invalid');value=read_payloads(tmp_path/'invalid',expected_seal=seal)[2][1]
    assert value['control'] is None and value['failure_class'] and batch.closed
    assert backend.budget.snapshot()['used']['input_tokens']==100 and backend.budget.snapshot()['used']['output_tokens']==25
    assert backend.receipts[0]['native_MLX_completion']['text']=='<tool_call>invalid</tool_call>'
    assert replay(tmp_path/'invalid',expected_seal=seal)['unknown']==1
