"""Pinned Qwen MLX target adapter. No imports of MLX, downloads or inference on import."""
import hashlib,json,os,sys,time
from pathlib import Path
from talos.pilot.backend import ProtocolReplayBackend,source_hash,target_source_hash
from talos.pilot.authority import ApprovalGate,file_hash
from talos.pilot.contracts import ModelPlan,Scope,BenignPlan,BenignScope,parse_scope
from talos.pilot.mlx_spec import MLXModel,candidate_hash,ProposedMLXPilot
from talos.pilot.mlx_limits import MLXBatchLedger
from talos.pilot.mlx_protocol import NativeCompletion,normalize
from talos.pilot.mlx_assets import runtime_lock
from talos.pilot.mlx_process import OwnedRequest
from talos.pilot.protocol import loads
from talos.targets.helpdesk import HelpdeskDomain
from talos.targets.documents import DocumentDomain


def verify_authority(plan,scope,gate,opt_in,python_path, *, owner_pid=None,batch=None):
    from talos.pilot.compatibility import CompatibilityPlan,CompatibilityScope,CompatibilityGate,verify_compatibility_authority
    if type(plan) is CompatibilityPlan:
        return verify_compatibility_authority(plan,scope,gate,opt_in,python_path,owner_pid=owner_pid,batch=batch)
    if type(gate) is not ApprovalGate or isinstance(scope,CompatibilityScope):
        raise PermissionError('seven-role execution requires its original gate/scope; no compatibility fallback')
    if not isinstance(plan.model,MLXModel):raise PermissionError('exact MLX model configuration required')
    proof=gate.require(scope,opt_in=opt_in)
    if scope.plan_sha256!=plan.digest() or scope.adapter_source_sha256!=source_hash() or scope.target_policy_source_sha256!=target_source_hash():
        raise PermissionError('MLX plan/source scope differs')
    benign=isinstance(plan,BenignPlan)
    if benign!=isinstance(scope,BenignScope):raise PermissionError('benign/attack scope cannot be interchanged')
    if plan.provenance.target_model_id!=plan.model.configuration.model_id or (not benign and plan.injection.surface not in scope.permitted_surfaces):
        raise PermissionError('explicit defender model provenance/delivery approval missing')
    from talos.corpus import load_corpus,content_hash
    if not benign:
        corpus=load_corpus();record=next((r for r in corpus.records if r.identity==plan.case_identity),None)
        if (record is None or record.case.family_id not in scope.dev_family_ids or content_hash(corpus)!=scope.corpus_sha256
            or plan.common_pool_sha256!=scope.common_pool_sha256 or not plan.opportunity_id):raise PermissionError('approved DEV corpus/family/opportunity missing')
    custody=loads(Path(gate.evidence_paths['model_provider_custody']).read_text())
    worker=Path(__file__).with_name('mlx_worker.py').resolve()
    expected={'runtime':'mlx-lm','role':'defender_target_agent_not_attacker','plan_sha256':plan.digest(),
        'run_nonce':scope.run_nonce,'candidate_manifest_sha256':candidate_hash(),'local_snapshot':plan.model.local_snapshot,
        'worker_sha256':file_hash(worker),'runtime_lock_sha256':file_hash(runtime_lock()),'interpreter_sha256':file_hash(Path(python_path).resolve())}
    if custody!=expected:raise PermissionError('genuine MLX runtime/custody record unavailable')
    budget=loads(Path(gate.evidence_paths['budget_pricing']).read_text())
    from talos.research.recorder import read_payloads
    from talos.corpus.models import content_hash
    ledger_path=budget.get('ledger_root');initial=budget.get('ledger_initial_sha256')
    if not ledger_path or not initial:raise PermissionError('approved durable batch ledger missing')
    events=read_payloads(Path(ledger_path),allow_incomplete=True)
    if not events or events[0][0]!='MLX_batch_manifest' or content_hash(events[0][1])!=initial or events[0][1]['batch_id']!=plan.model.batch_id:
        raise PermissionError('batch ledger identity differs from signed budget')
    if batch is not None and (batch.recorder is None or str(batch.recorder.path)!=ledger_path or batch.initial_sha256!=initial or batch.recorder.lock.closed):
        raise PermissionError('actual batch controller does not own approved ledger')
    if budget!={'ledger_root':ledger_path,'ledger_initial_sha256':initial,'plan_sha256':plan.digest(),'batch_id':plan.model.batch_id,'proposal':ProposedMLXPilot().model_dump(mode='json'),
        'limits':plan.limits.model_dump(mode='json'),'currency':'INR','paid_API_spending_cap':0,'hardware_cost':'UNMEASURED',
        'decision':'APPROVE_DEV_LIMITS','shared_preparation_policy':'PR07_measure_once_equal_debit'}:
        raise PermissionError('proposed settings are not signed DEV batch/budget approval')
    dev=loads(Path(gate.evidence_paths['dev_cases_information']).read_text())
    expected_dev=({'plan_sha256':plan.digest(),'mode':'pure_benign','domain':plan.identity.domain,'actor_id':plan.identity.actor_id,
        'variant':plan.identity.variant,'operations':[op.model_dump(mode='json') for op in plan.operations],
        'partition':'DEV','information':'public_task_and_tool_schemas_only'} if benign else
        {'plan_sha256':plan.digest(),'case_identity':plan.case_identity,'opportunity_id':plan.opportunity_id,
         'common_pool_sha256':plan.common_pool_sha256,'partition':'DEV','attacker_information':'PR07_ordinary_public_feedback_only'})
    if dev!=expected_dev:
        raise PermissionError('DEV/information approval differs')
    containment=loads(Path(gate.evidence_paths['containment_cancellation']).read_text());pid=owner_pid or os.getpid()
    if (containment.get('adapter_source_sha256')!=source_hash() or containment.get('worker_pid')!=pid or os.getpgid(pid)!=pid
        or containment.get('owned_worker_hard_kill_reviewed') is not True or containment.get('egress_containment_reviewed') is not True
        or containment.get('MLX_request_subprocess_reviewed') is not True):raise PermissionError('genuine supervised MLX containment missing')
    supervisor=containment.get('supervisor_pid')
    if type(supervisor) is not int or supervisor<=0 or (owner_pid is None and supervisor!=os.getppid()):
        raise PermissionError('actual supervised coordinator binding absent')
    # The coordinator checks its real parent. The request child rechecks the
    # signed coordinator/supervisor record without mistaking its own parent
    # (the coordinator) for the external supervisor.
    # Hashes bind content, not kernel enforcement or independent review validity.
    reports=containment.get('os_control_reports',{})
    if set(reports)!={'network_denial','filesystem_isolation','process_tree_finality'}:
        raise PermissionError('independently reviewed OS control reports unavailable')
    for entry in reports.values():
        if set(entry)!={'path','sha256'} or file_hash(Path(entry['path']))!=entry['sha256']:
            raise PermissionError('OS control report changed/unavailable')
    return proof


class MLXReplayBackend(ProtocolReplayBackend):
    """Raw Qwen text/count mocks only. Never imports/loads MLX or grants approval."""
    def __init__(self,plan,native_responses, *, batch):
        if not isinstance(plan.model,MLXModel):raise TypeError('MLX candidate plan required')
        super().__init__(plan,());self.native_responses=native_responses;self.batch=batch;self.native_receipts=[]
        self.episode_id=':'.join((plan.identity.run_id,plan.identity.scenario_id,plan.identity.repeat_id,plan.identity.arm))

    def assert_plan(self,plan):
        super().assert_plan(plan)
        from talos.pilot.compatibility import CompatibilityPlan,CompatibilityLedger
        expected=CompatibilityLedger if type(plan) is CompatibilityPlan else MLXBatchLedger
        if type(self.batch) is not expected or self.batch.batch_id!=plan.model.batch_id:raise PermissionError('exact policy-specific batch ledger required')
        self.batch.begin(self.episode_id)

    def guard(self):
        super().guard();self.batch.check()

    def reserve(self,budget):
        super().reserve(budget)
        try:self.batch.request(self.episode_id)
        except BaseException:
            budget.settle({'target_model_calls':0,'input_tokens':0,'output_tokens':0,'cost_microunits':0});raise

    def generate(self,public,step,budget):
        try:return super().generate(public,step,budget)
        except BaseException as failure:
            self.batch.halt('native_result_incomplete_or_invalid:'+type(failure).__name__)
            raise

    def failure_usage(self,receipt):
        try:completion=NativeCompletion.model_validate(receipt.get('native_MLX_completion'))
        except Exception:return super().failure_usage(receipt)
        model=self.plan.model
        receipt['usage']={'input_tokens':completion.prompt_tokens,'output_tokens':completion.generation_tokens,
            'budget_debit_microunits':0,'currency':'INR','cost_basis':model.cost_basis,'price_schedule_sha256':model.price_schedule_sha256}
        return {'target_model_calls':1,'input_tokens':completion.prompt_tokens,'output_tokens':completion.generation_tokens,'cost_microunits':0}

    def _native(self,body,step):
        if step>=len(self.native_responses):raise ValueError('native software mock exhausted')
        return self.native_responses[step]

    def _exchange(self,body,step):
        raw=self._native(body,step);self.native_receipts.append(raw)
        self.receipts[-1]['native_MLX_completion']=raw
        self.receipts[-1]['candidate_manifest_sha256']=candidate_hash()
        completion=NativeCompletion.model_validate(raw)
        domain=HelpdeskDomain() if self.plan.identity.domain=='it-helpdesk' else DocumentDomain()
        request_id='mlx-request-'+hashlib.sha256((self.plan.digest()+':'+str(step)+':'+json.dumps(body,sort_keys=True)).encode()).hexdigest()
        normalized=normalize(completion,self.plan.model,request_id=request_id,tool_schemas={t.name:t.arguments for t in domain.tools},seen_ids=self.seen)
        self.receipts[-1]['native_MLX_completion']=raw
        self.receipts[-1]['call_ID_origin']='adapter_correlation_ID_not_model_generated_identity'
        self.receipts[-1]['candidate_manifest_sha256']=candidate_hash()
        self.receipts[-1]['paid_API_spending_inr']=0
        return normalized


class MLXModelBackend(MLXReplayBackend):
    is_live=True
    def __init__(self,plan,scope, *, batch,gate=None,python_path=None,opt_in=False):
        super().__init__(plan,(),batch=batch);self.scope=parse_scope(scope)
        self.gate=gate or ApprovalGate();self.python_path=Path(python_path) if python_path else None;self.opt_in=opt_in;self.active=None

    def assert_plan(self,plan):
        # No inference/module loading is reachable from proposed settings or API keys.
        if self.python_path is None:raise PermissionError('approved isolated MLX interpreter unavailable')
        self.last_authorization=verify_authority(plan,self.scope,self.gate,self.opt_in,self.python_path,batch=self.batch)
        super().assert_plan(plan)

    def guard(self):
        super().guard()
        self.last_authorization=verify_authority(self.plan,self.scope,self.gate,self.opt_in,self.python_path,batch=self.batch)

    def _native(self,body,step):
        self.guard();remaining=min(self.plan.model.request_timeout_ms,self.batch.remaining_ms(),
            min(self.plan.hard_timeout_ms,self.plan.limits.amounts['elapsed_ms']-self.elapsed_before)-int((time.monotonic()-self.started)*1000))
        from talos.pilot.compatibility import CompatibilityPlan
        compatibility=type(self.plan) is CompatibilityPlan
        if compatibility:remaining-=self.plan.cleanup_reserve_ms
        if remaining<=0:raise TimeoutError('no MLX time remaining')
        self.active=OwnedRequest()
        payload={'plan':self.plan.model_dump(mode='json'),'scope':self.scope.model_dump(mode='json'),'request':body,
            'registry_path':str(self.gate.registry_path),'registry_sha256':self.gate.registry_sha256,
            'approval_paths':[str(p) for p in self.gate.approval_paths],
            'evidence_paths':{k:str(p) for k,p in self.gate.evidence_paths.items()},'opt_in':self.opt_in,
            'owner_worker_pid':os.getpid()}
        if compatibility:
            payload['compatibility_policy_enabled']=self.gate.enabled
            containment=loads(Path(self.gate.evidence_paths['containment']).read_text())
            from talos.pilot.compat_supervisor import CompatibilitySupervisorClient
            if not hasattr(self,'compat_supervisor'):self.compat_supervisor=CompatibilitySupervisorClient(containment['supervisor_pid'])
            result=self.active.run([str(self.python_path),'-I',str(Path(__file__).with_name('mlx_worker.py').resolve())],payload,remaining,
                sandbox_profile=Path(containment['sandbox_profile_path']),supervisor=self.compat_supervisor)
        else:result=self.active.run([str(self.python_path),'-I',str(Path(__file__).with_name('mlx_worker.py').resolve())],payload,remaining)
        self.receipts[-1]['native_MLX_environment']=result['environment']
        return result['completion']

    def close(self):
        self.closed=True
        if self.active is not None and self.active.process is not None and self.active.process.poll() is None:self.active.cancel()
        if hasattr(self,'compat_supervisor'):self.compat_supervisor.close()
        return {'MLX_request_reaped':self.active is None or self.active.process is None or self.active.process.poll() is not None,'hardware_cost':None,
            'private_worker_diagnostics':self.active.diagnostics if self.active else None,
            'OS_containment_verified_by_this_code':False}
