"""Qwen native tool markers -> versioned normalized records, never eval or guessing."""
import hashlib,re
from pydantic import Field
from typing import Literal
from talos.corpus.models import Model
from talos.pilot.protocol import loads,decode


class NativeCompletion(Model):
    text:str=Field(max_length=200000)
    prompt_tokens:int=Field(ge=1,strict=True)
    generation_tokens:int=Field(ge=1,le=512,strict=True)
    finish_reason:Literal['stop','length']


def normalize(completion:NativeCompletion,model, *, request_id:str,tool_schemas:dict,seen_ids:set):
    completion=NativeCompletion.model_validate(completion.model_dump())
    if completion.finish_reason!='stop':raise ValueError('truncated generation cannot execute tools')
    if completion.prompt_tokens+512>4096:raise ValueError('context ceiling with full output reserve exceeded')
    text=completion.text
    if any(x in text for x in ('<think>','</think>','<|im_start|>','<|im_end|>','<tool_response>','</tool_response>')):
        raise ValueError('unsupported reasoning/role/surface markup')
    pattern=re.compile(r'<tool_call>\s*(.*?)\s*</tool_call>',re.DOTALL)
    matches=list(pattern.finditer(text));outside=pattern.sub('',text)
    if '<tool_call' in outside or '</tool_call' in outside:raise ValueError('unbalanced/unsupported tool marker')
    if not matches and text.lstrip().startswith(('{','[')):
        value=loads(text.strip())
        if isinstance(value,dict) and set(value)&{'name','arguments','tool_calls','role'}:raise ValueError('unsupported bare tool/message JSON')
    calls=[]
    for index,match in enumerate(matches):
        value=loads(match.group(1))
        if not isinstance(value,dict) or set(value)!={'name','arguments'} or not isinstance(value['arguments'],dict):
            raise ValueError('exact Qwen name/arguments object required')
        call_id='mlx-'+hashlib.sha256(request_id.encode()).hexdigest()[:32]+'-'+str(index)
        import json
        calls.append({'id':call_id,'type':'function','function':{'name':value['name'],'arguments':json.dumps(value['arguments'],allow_nan=False)}})
    wire={'id':request_id,'object':'chat.completion','model':model.configuration.model_id,
        'choices':[{'index':0,'finish_reason':'tool_calls' if calls else 'stop','message':{'role':'assistant','content':outside.strip(),'tool_calls':calls}}],
        'usage':{'prompt_tokens':completion.prompt_tokens,'completion_tokens':completion.generation_tokens,
            'total_tokens':completion.prompt_tokens+completion.generation_tokens}}
    # Shared parser enforces the exact PR-03 schemas and max four tool calls.
    decode(wire,model,tool_schemas=tool_schemas,seen_ids=seen_ids)
    return wire


def collect(segments,prompt_tokens, *, check_active=lambda:None):
    """Use native counts, including terminal token if MLX reports it. No text estimates."""
    parts=[];last=None;previous=0
    for segment in segments:
        check_active()
        if last is not None:raise ValueError('generation after terminal event')
        if type(getattr(segment,'prompt_tokens',None)) is not int or segment.prompt_tokens!=prompt_tokens:raise ValueError('missing/mismatched native prompt usage')
        count=getattr(segment,'generation_tokens',None)
        if type(count) is not int or not previous<=count<=512 or count<1:raise ValueError('invalid native generation usage')
        previous=count
        if not isinstance(segment.text,str):raise ValueError('unsupported native text')
        parts.append(segment.text)
        if segment.finish_reason is not None:last=segment
    if last is None:raise ValueError('missing final native usage/finality')
    return NativeCompletion(text=''.join(parts),prompt_tokens=prompt_tokens,generation_tokens=last.generation_tokens,finish_reason=last.finish_reason)
