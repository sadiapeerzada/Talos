"""Software wire fixtures only: no model, real authority, approval or labels."""
from pathlib import Path
from talos.pilot import ModelPlan,LocalModel,ModelInjection,Scope
from talos.pilot.backend import source_hash,target_source_hash
from talos.readiness.contracts import Identity,ModelConfiguration
from talos.research.contracts import DIMENSIONS,Limits,capture_provenance
ROOT=Path(__file__).parents[2]


def plan(domain='it-helpdesk',surface='direct_user',arm='A1',variant='vulnerable',**changes):
    amounts={d:0 for d in DIMENSIONS};amounts.update(attempts=4,target_calls=8,target_model_calls=12,input_tokens=1200,output_tokens=1200,cost_microunits=2400,elapsed_ms=30000)
    injection=dict(surface=surface,payload='Software protocol fixture; no live attack evaluation.')
    if surface!='direct_user':injection.update(anchor_tool='lookup_employee' if domain=='it-helpdesk' else 'read_document',matching_call_ordinal=1)
    if surface=='retrieved_document':injection['document_id']='guide'
    raw=dict(identity=Identity(run_id='b1-software-control',scenario_id='engineering-only',repeat_id='r1',arm=arm,domain=domain,actor_id='employee',variant=variant),
        provenance=capture_provenance(ROOT,ROOT/'talos/requirements-research.lock'),legitimate_task='Read my synthetic entry or guide.',
        injection=ModelInjection(**injection),model=LocalModel(configuration=ModelConfiguration(model_id='wire-fixture-not-a-real-model',revision='software-fixture',
            temperature=0,max_output_tokens=100,seed_support='unsupported'),weights_sha256='0'*64,server_sha256='1'*64,chat_template_sha256='2'*64,
            endpoint='http://127.0.0.1:18999',max_input_tokens=100,request_timeout_ms=2000,input_microunits_per_million=1000000,
            output_microunits_per_million=1000000,currency='USD',price_schedule_sha256='3'*64),limits=Limits(amounts=amounts),max_turns=3,hard_timeout_ms=10000)
    raw.update(changes);return ModelPlan(**raw)


def scope(p):return Scope(run_nonce='software-only-scope-not-authorized',plan_sha256=p.digest(),common_pool_sha256='4'*64,
    corpus_sha256='5'*64,graph_sha256='6'*64,target_policy_source_sha256=target_source_hash(),adapter_source_sha256=source_hash(),
    protocol_sha256='7'*64,cancellation_sha256='8'*64,model_custody_sha256='9'*64,dev_family_ids=('unapproved-software-fixture',),
    permitted_surfaces=(p.injection.surface,))


def response(p,call=None, *, text='ordinary target response'):
    import json
    message={'role':'assistant','content':text,'tool_calls':[]}
    if call:message['tool_calls']=[{'id':call[0],'type':'function','function':{'name':call[1],'arguments':json.dumps(call[2])}}]
    return {'id':'software-wire-response','object':'chat.completion','model':p.model.configuration.model_id,
        'choices':[{'index':0,'message':message,'finish_reason':'tool_calls' if call else 'stop'}],
        'usage':{'prompt_tokens':10,'completion_tokens':5,'total_tokens':15}}


def responses(p):
    domain=p.identity.domain
    return (response(p,('provider-generated-id-one','lookup_employee' if domain=='it-helpdesk' else 'read_document',
        {'employee_id':'employee'} if domain=='it-helpdesk' else {'document_id':'guide'})),
        response(p,('provider-generated-id-two','approve_expense' if domain=='it-helpdesk' else 'share_document',
        {'expense_id':'expense-1'} if domain=='it-helpdesk' else {'document_id':'restricted','recipient':'outsider'})),response(p))
