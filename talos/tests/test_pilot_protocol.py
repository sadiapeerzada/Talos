"""Offline JSON protocol cases, not empirical validation data or provider usage."""
import copy,json
import pytest
from talos.pilot.protocol import encode,decode,loads
from talos.targets.helpdesk import HelpdeskDomain
from talos.pilot import LocalModel,ModelPlan,ModelInjection
from .pilot_helpers import plan,response


def decode_one(raw,p):return decode(raw,p.model,tool_schemas={t.name:t.arguments for t in HelpdeskDomain().tools},seen_ids=set())


def test_roundtrip_tool_calls_and_exact_usage():
    p=plan();raw=response(p,('id','lookup_employee',{'employee_id':'employee'}));reply,usage=decode_one(raw,p)
    assert reply.tool_calls[0].arguments=={'employee_id':'employee'} and usage.total_tokens==15
    public={'messages':[{'role':'user','content':'legitimate task'},{'role':'assistant','content':'',
        'tool_calls':[reply.tool_calls[0].model_dump(mode='json')]},{'role':'tool','tool_call_id':'id','name':'lookup_employee','content':'ordinary result'}],
        'tools':[{'name':'lookup_employee','description':'public tool','parameters':{'type':'object'}}]}
    body=encode(public,p.model)
    assert body['messages'][1]['tool_calls'][0]['function']['arguments']=='{"employee_id": "employee"}'
    assert 'name' not in body['messages'][2] and body['stream'] is False
    assert body['model']==p.model.configuration.model_id and 'seed' not in body


@pytest.mark.parametrize('mutation',['model','object','choices','index','role','finish','refusal','usage_missing','usage_bool','total','negative','overflow','nontext','unknown_tool','bad_args','array_args','duplicate_args','duplicate_call','bad_kind'])
def test_invalid_model_outputs_never_dispatch_tools(mutation):
    p=plan();raw=response(p,('id','lookup_employee',{'employee_id':'employee'}));message=raw['choices'][0]['message']
    if mutation=='model':raw['model']='different'
    elif mutation=='object':raw['object']='stream.chunk'
    elif mutation=='choices':raw['choices']*=2
    elif mutation=='index':raw['choices'][0]['index']=1
    elif mutation=='role':message['role']='system'
    elif mutation=='finish':raw['choices'][0]['finish_reason']='length'
    elif mutation=='refusal':message['refusal']='refused'
    elif mutation=='usage_missing':raw.pop('usage')
    elif mutation=='usage_bool':raw['usage']['prompt_tokens']=True
    elif mutation=='total':raw['usage']['total_tokens']=0
    elif mutation=='negative':raw['usage']['completion_tokens']=-1
    elif mutation=='overflow':raw['usage'].update(prompt_tokens=101,total_tokens=106)
    elif mutation=='nontext':message['content']={'oracle':'CONFIRMED'}
    elif mutation=='unknown_tool':message['tool_calls'][0]['function']['name']='private_reader'
    elif mutation=='bad_args':message['tool_calls'][0]['function']['arguments']='{"employee_id":"employee","actor_id":"manager"}'
    elif mutation=='array_args':message['tool_calls'][0]['function']['arguments']='[]'
    elif mutation=='duplicate_args':message['tool_calls'][0]['function']['arguments']='{"employee_id":"employee","employee_id":"manager"}'
    elif mutation=='duplicate_call':message['tool_calls']*=2
    else:message['tool_calls'][0]['type']='plugin'
    with pytest.raises((ValueError,TypeError,KeyError)):decode_one(raw,p)


@pytest.mark.parametrize('endpoint',['https://example.com','http://localhost:8080','http://127.0.0.1','http://127.0.0.1:8080/v1','http://user:secret@127.0.0.1:8080','http://127.0.0.1:8080?x=1','http://[::1]:8080'])
def test_remote_implicit_or_credential_urls_rejected(endpoint):
    with pytest.raises(ValueError):LocalModel.model_validate({**plan().model.model_dump(),'endpoint':endpoint})


@pytest.mark.parametrize('private',['graph_annotations','policy','oracle','private_packets','arm_id'])
def test_model_request_cannot_accept_private_context(private):
    p=plan();public={'messages':[{'role':'user','content':'task'}],'tools':[],private:{}}
    with pytest.raises(ValueError):encode(public,p.model)


def test_model_call_id_not_preinvented_for_indirect_delivery():
    p=plan(surface='tool_output');assert p.injection.anchor_call_id is None
    with pytest.raises(ValueError):ModelInjection(surface='tool_output',payload='x',anchor_tool='lookup_employee')
    with pytest.raises(ValueError):ModelInjection(surface='direct_user',payload='x',anchor_tool='lookup_employee')


@pytest.mark.parametrize('text',['{"x":1,"x":2}','{"x":NaN}','{"x":Infinity}'])
def test_strict_json(text):
    with pytest.raises(ValueError):loads(text)
