"""Native text/count software mocks, not real model responses or approvals."""
from talos.pilot.mlx_spec import MLXModel,CHECKPOINT,REVISION,candidate_hash
from talos.pilot import ModelPlan
from talos.readiness.contracts import ModelConfiguration
from talos.research.contracts import Limits,DIMENSIONS
from .pilot_helpers import plan as baseline


def plan(domain='it-helpdesk',surface='direct_user',arm='A1',variant='vulnerable',max_turns=3):
    base=baseline(domain,surface,arm,variant)
    amounts={d:0 for d in DIMENSIONS};amounts.update(attempts=8,target_calls=128,target_model_calls=32,
        input_tokens=32*3584,output_tokens=32*512,cost_microunits=0,elapsed_ms=1800000)
    model=MLXModel(configuration=ModelConfiguration(model_id=CHECKPOINT,revision=REVISION,temperature=0,max_output_tokens=512,seed_support='unverified'),
        candidate_manifest_sha256=candidate_hash(),local_snapshot='/not-provisioned/qwen-mlx-candidate',request_timeout_ms=5000,
        price_schedule_sha256='0'*64,batch_id='software-native-batch')
    return ModelPlan.model_validate({**base.model_dump(),'adapter_version':'talos.qwen-mlx-native-adapter.v1','model':model.model_dump(),'limits':Limits(amounts=amounts).model_dump(),'max_turns':max_turns})


def completion(text,**changes):
    value={'text':text,'prompt_tokens':100,'generation_tokens':25,'finish_reason':'stop'};value.update(changes);return value


def responses(p):
    import json
    def call(name,args):return completion('<tool_call>\n'+json.dumps({'name':name,'arguments':args})+'\n</tool_call>')
    if p.identity.domain=='it-helpdesk':
        return (call('lookup_employee',{'employee_id':'employee'}),call('approve_expense',{'expense_id':'expense-1'}),completion('Ordinary terminal software text.'))
    return (call('read_document',{'document_id':'guide'}),call('share_document',{'document_id':'restricted','recipient':'outsider'}),completion('Ordinary terminal software text.'))
