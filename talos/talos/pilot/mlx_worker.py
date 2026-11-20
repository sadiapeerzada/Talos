"""Future authorized native request worker. Never downloads; no inference command in CLI."""
import json,os,socket,sys,contextlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))


def deny(*a,**kw):raise PermissionError('MLX worker has no network/process capability')


def audit(event,args):
    if event in ('socket.connect','socket.getaddrinfo','subprocess.Popen','os.system','os.exec','os.posix_spawn'):deny()


def prepare_prompt(tokenizer,request):
    # The known pinned template renders only public history/tools. No hidden oracle inputs.
    if set(request)!={'model','messages','tools','tool_choice','parallel_tool_calls','temperature','max_tokens','stream','n'}:
        raise ValueError('unsupported/private MLX request fields')
    if request['temperature']!=0 or request['max_tokens']!=512 or request['stream'] is not False or request['n']!=1:
        raise ValueError('proposed sampler/output settings changed')
    prompt=tokenizer.apply_chat_template(request['messages'],tools=request['tools'],tokenize=True,add_generation_prompt=True)
    if not isinstance(prompt,list) or not prompt or any(type(t) is not int for t in prompt):raise ValueError('exact tokenizer token list unavailable')
    if len(prompt)+512>4096:raise ValueError('refuse context overflow; no prompt truncation')
    return prompt


def main():
    socket.socket.connect=deny;socket.socket.connect_ex=deny;socket.getaddrinfo=deny;sys.addaudithook(audit)
    from talos.pilot.contracts import ModelPlan,Scope
    from talos.pilot.authority import ApprovalGate
    from talos.pilot.mlx_backend import verify_authority
    from talos.pilot.mlx_assets import verify_snapshot,verify_environment
    from talos.pilot.mlx_spec import CHECKPOINT,candidate
    from talos.pilot.mlx_protocol import collect
    payload=json.loads(sys.stdin.read(1000000));plan=ModelPlan.model_validate(payload['plan']);scope=Scope.model_validate(payload['scope'])
    gate=ApprovalGate(registry_path=Path(payload['registry_path']),registry_sha256=payload['registry_sha256'],
        approval_paths=tuple(Path(p) for p in payload['approval_paths']),evidence_paths={k:Path(p) for k,p in payload['evidence_paths'].items()})
    if payload['owner_worker_pid']!=os.getppid():raise PermissionError('request is not owned by approved coordinator')
    # No MLX import or weight load precedes both cryptographic checks and artifact verification.
    verify_authority(plan,scope,gate,payload.get('opt_in',False),Path(sys.executable),owner_pid=os.getppid())
    versions=verify_environment();assets=verify_snapshot(plan.model)
    if payload['request']['model']!=CHECKPOINT:raise PermissionError('wrong target checkpoint')
    with contextlib.redirect_stdout(sys.stderr):
        import mlx.core as mx
        if not mx.metal.is_available():raise PermissionError('Apple Silicon Metal backend unavailable')
        from mlx_lm import load,stream_generate
        from mlx_lm.sample_utils import make_sampler
        model,tokenizer=load(plan.model.local_snapshot,tokenizer_config={'local_files_only':True,'trust_remote_code':False})
        import hashlib
        template=tokenizer.chat_template
        if not isinstance(template,str) or hashlib.sha256(template.encode()).hexdigest()!=candidate()['checkpoint_files']['chat_template.jinja']['sha256']:
            raise PermissionError('runtime template differs from pinned metadata')
        prompt=prepare_prompt(tokenizer,payload['request'])
        # No prompt cache/draft/adapters or cross-request model state is shared.
        completion=collect(stream_generate(model,tokenizer,prompt=prompt,max_tokens=512,sampler=make_sampler(temp=0)),len(prompt))
    print(json.dumps({'completion':completion.model_dump(mode='json'),'environment':{'dependency_versions':versions,'verified_assets':assets,'candidate_manifest_sha256':plan.model.candidate_manifest_sha256,'MLX_LM':'0.26.2','model_role':'defender_target_agent_not_attacker'}}))


if __name__=='__main__':main()
