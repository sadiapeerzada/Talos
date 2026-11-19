"""Strict nonstreaming chat-completions conversion; no SDK, credentials or calls."""
import json
from pydantic import BaseModel,ConfigDict,Field,StrictInt
from talos.readiness.contracts import Reply,ToolCall
from talos.pilot.contracts import LocalModel
from talos.profiles.models import finite_json


def loads(text):
    def pairs(items):
        out={}
        for k,v in items:
            if k in out:raise ValueError('duplicate JSON key')
            out[k]=v
        return out
    return json.loads(text,object_pairs_hook=pairs,parse_constant=lambda v:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def encode(public:dict,model:LocalModel):
    if set(public)!={'messages','tools'}:raise ValueError('model boundary accepts public messages/tools only')
    tools=[]
    for tool in public['tools']:
        if set(tool)!={'name','description','parameters'}:raise ValueError('unexpected/private tool metadata')
        tools.append({'type':'function','function':tool})
    messages=[];pending=[];seen=set()
    for msg in public['messages']:
        role=msg.get('role')
        if role in ('system','user'):
            if set(msg)!={'role','content'} or not isinstance(msg['content'],str) or pending:raise ValueError('invalid message boundary')
            messages.append(dict(msg))
        elif role=='assistant':
            if set(msg)!={'role','content','tool_calls'} or pending:raise ValueError('invalid assistant tool protocol')
            calls=[]
            for raw in msg['tool_calls']:
                call=ToolCall.model_validate(raw)
                if call.call_id in seen:raise ValueError('duplicate tool ID')
                seen.add(call.call_id);pending.append(call.call_id)
                calls.append({'id':call.call_id,'type':'function','function':{'name':call.tool_name,'arguments':json.dumps(call.arguments,sort_keys=True,allow_nan=False)}})
            item={'role':'assistant','content':msg['content']}
            if calls:item['tool_calls']=calls
            messages.append(item)
        elif role=='tool':
            if set(msg)!={'role','tool_call_id','name','content'} or not pending or msg['tool_call_id']!=pending.pop(0):
                raise ValueError('tool response without exact ordered call')
            messages.append({k:v for k,v in msg.items() if k!='name'})
        else:raise ValueError('unknown/private message role')
    if pending:raise ValueError('incomplete tool outputs')
    cfg=model.configuration
    body={'model':cfg.model_id,'messages':messages,'tools':tools,'tool_choice':'auto','parallel_tool_calls':False,
        'temperature':cfg.temperature,'max_tokens':cfg.max_output_tokens,'stream':False,'n':1}
    if cfg.seed is not None:body['seed']=cfg.seed
    return finite_json(body)


class TokenUsage(BaseModel):
    model_config=ConfigDict(extra='ignore',frozen=True)
    prompt_tokens:int=Field(ge=0,strict=True)
    completion_tokens:int=Field(ge=0,strict=True)
    total_tokens:int=Field(ge=0,strict=True)


def decode(raw:dict,model:LocalModel, *, tool_schemas:dict,seen_ids:set):
    raw=finite_json(raw)
    if raw.get('object')!='chat.completion' or raw.get('model')!=model.configuration.model_id or not isinstance(raw.get('id'),str):
        raise ValueError('model identity/response object mismatch')
    choices=raw.get('choices')
    if not isinstance(choices,list) or len(choices)!=1 or type(choices[0].get('index')) is not int or choices[0].get('index')!=0:raise ValueError('exact single choice required')
    choice=choices[0];message=choice['message']
    if message.get('role')!='assistant' or choice.get('finish_reason') not in ('stop','tool_calls'):
        raise ValueError('truncated/refused/incomplete response cannot dispatch tools')
    if message.get('refusal'):raise ValueError('refusal is not tool completion')
    calls=[]
    for rawcall in message.get('tool_calls') or ():
        if rawcall.get('type')!='function':raise ValueError('unsupported tool call kind')
        function=rawcall['function'];name=function['name']
        if name not in tool_schemas:raise ValueError('unknown tool')
        args=loads(function['arguments'])
        if not isinstance(args,dict):raise ValueError('tool arguments must be JSON object')
        # PR-03 argument schemas are enforced before a tool handle can be used.
        tool_schemas[name].model_validate(args)
        call=ToolCall(call_id=rawcall['id'],tool_name=name,arguments=args)
        if call.call_id in seen_ids or call.call_id in {c.call_id for c in calls}:raise ValueError('reused tool-call ID')
        calls.append(call)
    if bool(calls)!=(choice['finish_reason']=='tool_calls'):raise ValueError('tool finish reason inconsistent')
    text=message.get('content')
    if text is not None and not isinstance(text,str):raise ValueError('nontext output unsupported')
    reply=Reply(text=text or '',tool_calls=tuple(calls))
    usage=TokenUsage.model_validate(raw.get('usage'))
    if usage.total_tokens!=usage.prompt_tokens+usage.completion_tokens:raise ValueError('token totals inconsistent')
    if usage.prompt_tokens>model.max_input_tokens or usage.completion_tokens>model.configuration.max_output_tokens:
        raise ValueError('usage exceeds reserved model bounds')
    return reply,usage
