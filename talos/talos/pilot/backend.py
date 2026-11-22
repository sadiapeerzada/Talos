"""Default-disabled local chat adapter and explicitly labeled wire-only replay."""
import json,time
from pathlib import Path
import httpx
from talos.corpus.models import content_hash
from talos.pilot.contracts import ModelPlan,Scope,parse_plan
from talos.pilot.protocol import encode,decode,loads
from talos.pilot.authority import ApprovalGate
from talos.pilot.custody import OwnedServer
from talos.research.budget import BudgetStop
from talos.targets.helpdesk import HelpdeskDomain
from talos.targets.documents import DocumentDomain


def source_hash():
    import hashlib
    root=Path(__file__).parents[1]
    paths=sorted((root/'pilot').glob('*.py'))+[root/'readiness/agent.py',root/'ablation/contracts.py',root/'ablation/strategy.py',root/'pilot/qwen_mlx_candidate.json',root.parent/'requirements-mlx-candidate.lock']
    return content_hash({str(p.relative_to(root.parent)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})


def target_source_hash():
    import hashlib
    root=Path(__file__).parents[1]/'targets'
    return content_hash({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.glob('*.py'))})


class ProtocolReplayBackend:
    """No socket, callable transport or authority. Fixed JSON records test protocol only."""
    is_live=False
    def __init__(self,plan:ModelPlan,responses:tuple[dict,...]):
        self.plan=parse_plan(plan);self.responses=json.loads(json.dumps(responses,allow_nan=False))
        self.receipts=[];self.seen=set();self.budget=None;self.started=None;self.closed=False;self.anchor_matches=0;self.shared_budget=None;self.elapsed_before=0

    def budget_for(self,limits):
        from talos.research.budget import Budget
        if self.shared_budget is None:return Budget(limits)
        if self.shared_budget.limits!=limits.amounts:raise ValueError('unequal shared arm budget')
        return self.shared_budget

    def assert_plan(self,plan):
        if parse_plan(plan)!=self.plan:raise PermissionError('backend/plan differs')
        if self.started is not None:raise PermissionError('conversation backend cannot be reused across runs/arms')
        self.elapsed_before=self.shared_budget.used['elapsed_ms'] if self.shared_budget else 0
        self.started=time.monotonic()

    def guard(self):
        if self.closed or self.started is None:raise PermissionError('inactive/cancelled conversation')
        if (time.monotonic()-self.started)*1000>=min(self.plan.hard_timeout_ms,self.plan.limits.amounts['elapsed_ms']-self.elapsed_before):
            self.closed=True;raise TimeoutError('conversation hard deadline expired')

    def matches_anchor(self,call):
        injection=self.plan.injection
        if injection is None:return False
        if call.tool_name!=injection.anchor_tool:return False
        if injection.surface=='retrieved_document' and call.arguments.get('document_id')!=injection.document_id:return False
        self.anchor_matches+=1
        return self.anchor_matches==injection.matching_call_ordinal

    def reserve(self,budget):
        self.guard();self.budget=budget;m=self.plan.model
        budget.reserve({'target_model_calls':1,'input_tokens':m.max_input_tokens,
            'output_tokens':m.configuration.max_output_tokens,
            'cost_microunits':m.debit(m.max_input_tokens,m.configuration.max_output_tokens)})

    def _exchange(self,body,step):
        if step>=len(self.responses):raise ValueError('wire fixture exhausted')
        return self.responses[step]

    def failure_usage(self,receipt):
        return {'target_model_calls':1,'input_tokens':None,'output_tokens':None,'cost_microunits':None}

    def generate(self,public,step,budget):
        self.guard();started=time.monotonic_ns();model=self.plan.model
        request=encode(public,model)
        receipt={'schema_version':'talos.local-chat-receipt.v1','step':step,'request':request,'request_sha256':content_hash(request),
            'response':None,'response_sha256':None,'usage':None,'actual_cost_microunits':None,
            'basis':'local_provider_response' if self.is_live else 'software_protocol_fixture_not_provider_measurements',
            'authorization':getattr(self,'last_authorization',None),'client_retries':0,'provider_internal_retries':None,'model_artifact_custody':'independently_supplied' if self.is_live else 'NOT_ESTABLISHED'}
        self.receipts.append(receipt)
        try:
            raw=self._exchange(request,step);receipt['response']=raw;receipt['response_sha256']=content_hash(raw)
            domain=HelpdeskDomain() if self.plan.identity.domain=='it-helpdesk' else DocumentDomain()
            reply,usage=decode(raw,model,tool_schemas={t.name:t.arguments for t in domain.tools},seen_ids=self.seen)
            self.guard()
            receipt['usage']={'input_tokens':usage.prompt_tokens,'output_tokens':usage.completion_tokens,
                'budget_debit_microunits':model.debit(usage.prompt_tokens,usage.completion_tokens),
                'currency':model.currency,'cost_basis':model.cost_basis,'price_schedule_sha256':model.price_schedule_sha256}
            budget.settle({'target_model_calls':1,'input_tokens':usage.prompt_tokens,'output_tokens':usage.completion_tokens,
                'cost_microunits':model.debit(usage.prompt_tokens,usage.completion_tokens)})
            self.seen.update(c.call_id for c in reply.tool_calls)
            return reply
        except BaseException:
            if budget.pending is not None:
                try:budget.settle(self.failure_usage(receipt))
                except BudgetStop:pass
            self.closed=True
            raise
        finally:receipt['elapsed_ms']=(time.monotonic_ns()-started+999999)//1000000

    def close(self):self.closed=True


class LocalModelBackend(ProtocolReplayBackend):
    """No key, endpoint or enabled flag alone can open a connection."""
    is_live=True
    def __init__(self,plan:ModelPlan,scope:Scope, *, gate:ApprovalGate|None=None,owned_server:OwnedServer|None=None,opt_in=False):
        if plan.injection is None:raise PermissionError('benign v1 requires the native MLX backend, not HTTP')
        super().__init__(plan,());self.scope=Scope.model_validate(scope.model_dump());self.gate=gate or ApprovalGate()
        self.owned_server=owned_server;self.opt_in=opt_in

    def assert_plan(self,plan):
        super().assert_plan(plan)
        if self.scope.plan_sha256!=plan.digest() or plan.injection.surface not in self.scope.permitted_surfaces:
            raise PermissionError('model/delivery/approval scope mismatch')
        if self.scope.adapter_source_sha256!=source_hash() or self.scope.target_policy_source_sha256!=target_source_hash():
            raise PermissionError('approved adapter/target source changed')
        if plan.provenance.target_model_id!=plan.model.configuration.model_id:raise PermissionError('explicit target model provenance required')
        from talos.corpus import load_corpus
        corpus=load_corpus()
        record=next((r for r in corpus.records if r.identity==plan.case_identity),None)
        if (record is None or record.case.family_id not in self.scope.dev_family_ids or self.scope.corpus_sha256!=content_hash(corpus)
            or not plan.opportunity_id or plan.common_pool_sha256!=self.scope.common_pool_sha256):
            raise PermissionError('approved source-identified DEV case/family/common opportunity absent')
        self.guard()
        self.owned_server.arm_deadline(max(1,min(plan.hard_timeout_ms,plan.limits.amounts['elapsed_ms']-self.elapsed_before)-int((time.monotonic()-self.started)*1000)))

    def guard(self):
        super().guard()
        self.last_authorization=self.gate.require(self.scope,opt_in=self.opt_in)
        if type(self.owned_server) is not OwnedServer:raise PermissionError('genuine owned local server/cancellation unavailable')
        self.owned_server.check(self.plan.model,self.gate.evidence_paths['model_provider_custody'],self.scope)
        budget=loads(Path(self.gate.evidence_paths['budget_pricing']).read_text())
        expected={'plan_sha256':self.plan.digest(),'limits':self.plan.limits.model_dump(mode='json'),
            'currency':self.plan.model.currency,'price_schedule_sha256':self.plan.model.price_schedule_sha256,
            'cost_basis':self.plan.model.cost_basis,'shared_preparation_policy':'PR07_measure_once_equal_debit','actual_hardware_spend':'UNMEASURED_ACCEPTED_BY_BUDGET_OWNER'}
        if budget!=expected:raise PermissionError('approved budget/cost semantics incomplete or different')
        dev=loads(Path(self.gate.evidence_paths['dev_cases_information']).read_text())
        if dev!={'plan_sha256':self.plan.digest(),'case_identity':self.plan.case_identity,'opportunity_id':self.plan.opportunity_id,
            'common_pool_sha256':self.plan.common_pool_sha256,'partition':'DEV','attacker_information':'PR07_ordinary_public_feedback_only'}:
            raise PermissionError('independently supplied DEV case/information approval differs')
        # No in-process convenience path may stand in for a reviewed operational worker.
        containment=loads(Path(self.gate.evidence_paths['containment_cancellation']).read_text())
        if (containment.get('adapter_source_sha256')!=source_hash() or containment.get('worker_pid')!=__import__('os').getpid()
            or __import__('os').getpgid(0)!=__import__('os').getpid() or containment.get('supervisor_pid')!=__import__('os').getppid()
            or containment.get('owned_worker_hard_kill_reviewed') is not True or containment.get('egress_containment_reviewed') is not True):
            raise PermissionError('actual isolated/supervised worker containment evidence unavailable')
        super().guard()

    def _exchange(self,body,step):
        self.guard();m=self.plan.model
        remaining=min(m.request_timeout_ms/1000,min(self.plan.hard_timeout_ms,self.plan.limits.amounts['elapsed_ms']-self.elapsed_before)/1000-(time.monotonic()-self.started))
        if remaining<=0:raise TimeoutError('no remaining model time')
        # Fresh no-proxy/no-redirect/no-retry client, no API-key/.env discovery.
        with httpx.Client(trust_env=False,follow_redirects=False,timeout=remaining,transport=httpx.HTTPTransport(retries=0)) as client:
            with client.stream('POST',m.endpoint+'/v1/chat/completions',json=body,headers={'Content-Type':'application/json'}) as response:
                if response.status_code!=200:raise ValueError('local provider failed/refused/redirected; no retry')
                chunks=[];size=0
                for chunk in response.iter_bytes():
                    size+=len(chunk)
                    if size>2000000:raise ValueError('model response too large')
                    chunks.append(chunk);self.guard()
                return loads(b''.join(chunks).decode('utf-8'))

    def close(self):
        self.closed=True
        if self.owned_server is not None:return self.owned_server.cancel()
