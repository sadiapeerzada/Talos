"""PR-07 selectors see public pools/topology/ordinary feedback, never agent internals."""
import time
from talos.ablation.contracts import Arm,Block,PublicFeedback,view_for
from talos.ablation.planning import public_topology
from talos.ablation.strategy import Strategy
from talos.corpus.models import Surface
from talos.pilot.contracts import ModelInjection


class FourArmBridge:
    def __init__(self,block:Block,seed:int, *, scope_id:str):
        started=time.monotonic_ns()
        self.block=Block.model_validate(block.model_dump())
        graph=public_topology(self.block)
        self.strategies={arm:Strategy(arm,view_for(self.block.pool,arm,graph),seed,
            scope_id=scope_id+':'+self.block.block_id) for arm in Arm}
        self.preparation_elapsed_ms=(time.monotonic_ns()-started+999999)//1000000
        self.selection_elapsed_ms={arm:0 for arm in Arm}

    def choose(self,arm:Arm):
        arm=Arm(arm);started=time.monotonic_ns();choice=self.strategies[arm].choose()
        elapsed=(time.monotonic_ns()-started+999999)//1000000
        self.selection_elapsed_ms[arm]+=elapsed
        if hasattr(self,'budgets'):
            self.budgets[arm].reserve({'elapsed_ms':elapsed});self.budgets[arm].settle({'elapsed_ms':elapsed})
        return choice

    def injection(self,choice, *, anchor_tool=None,matching_call_ordinal=None,document_id=None):
        opportunity=next((o for o in self.block.pool.opportunities if o.opportunity_id==choice.opportunity_id),None)
        if opportunity is None:raise ValueError('no exact selected common opportunity')
        # Multiple surfaces/workflows remain unsupported rather than quietly narrowed.
        if len(opportunity.stimuli)!=1:return {'status':'UNSUPPORTED','opportunity_id':opportunity.opportunity_id,'injection':None}
        stimulus=opportunity.stimuli[0];surfaces={Surface.USER:'direct_user',Surface.TOOL:'tool_output',Surface.DOCUMENT:'retrieved_document'}
        if stimulus.surface not in surfaces:return {'status':'UNSUPPORTED','opportunity_id':opportunity.opportunity_id,'injection':None}
        injection=ModelInjection(surface=surfaces[stimulus.surface],payload=stimulus.text,anchor_tool=anchor_tool,
            matching_call_ordinal=matching_call_ordinal,document_id=document_id)
        return {'status':'PROPOSED_NOT_AUTHORIZED','opportunity_id':opportunity.opportunity_id,'injection':injection}

    def finish(self,arm,choice, *, completed:bool,response_text:str|None,model_feedback=False):
        # Caller must supply only ordinary target text, not the control/private result.
        if response_text is not None and not isinstance(response_text,str):raise TypeError('ordinary text only')
        feedback=PublicFeedback(response_text=response_text,**({'schema_version':'talos.ordinary-feedback.v2','source':'ordinary_local_model_response_not_ground_truth'} if model_feedback else {})) if completed and response_text is not None else None
        return self.strategies[Arm(arm)].finish(choice,status='completed' if completed else 'incomplete',feedback=feedback)

    def inventory(self):
        return [{'opportunity_id':o.opportunity_id,'surfaces':[s.surface.value for s in o.stimuli],
            'supported':len(o.stimuli)==1 and o.stimuli[0].surface in (Surface.USER,Surface.TOOL,Surface.DOCUMENT)} for o in self.block.pool.opportunities]

    def bind_budgets(self,limits):
        from talos.research.budget import Budget
        if hasattr(self,'budgets'):raise ValueError('arm ledgers cannot be reset mid-comparison')
        self.budgets={arm:Budget(limits) for arm in Arm}
        for arm,budget in self.budgets.items():
            charge=self.preparation_elapsed_ms+self.selection_elapsed_ms[arm]
            budget.reserve({'elapsed_ms':charge});budget.settle({'elapsed_ms':charge})

    def deliver(self,arm,choice,plan,backend,archive):
        """Same selected content; only ordinary terminal text may update PR-07 state."""
        if plan.injection is None:raise PermissionError('pure-benign utility controls are outside attack-arm delivery')
        from talos.pilot.runtime import execute
        from talos.research.recorder import read_payloads
        arm=Arm(arm)
        if not hasattr(self,'budgets'):raise PermissionError('explicit common arm ceilings required')
        if plan.identity.arm!=arm.name or plan.identity.domain!=self.block.target_profile.domain:
            raise ValueError('cross-arm/domain delivery')
        if choice!=self.strategies[arm].choose():raise ValueError('stale/foreign strategy choice')
        mapped=self.injection(choice,anchor_tool=plan.injection.anchor_tool,
            matching_call_ordinal=plan.injection.matching_call_ordinal,document_id=plan.injection.document_id)
        if mapped['injection']!=plan.injection:raise ValueError('delivered content differs from selected common opportunity')
        if backend.is_live:
            from talos.corpus import load_corpus,content_hash
            corpus=load_corpus()
            preparation=next((p for p in self.block.case_preparation if p.opportunity_id==choice.opportunity_id),None)
            if (backend.scope.common_pool_sha256!=self.block.pool.digest() or backend.scope.graph_sha256!=content_hash(public_topology(self.block))
                or preparation is None or plan.case_identity!=preparation.case_identity or plan.opportunity_id!=choice.opportunity_id
                or plan.common_pool_sha256!=self.block.pool.digest() or backend.scope.corpus_sha256!=content_hash(corpus)):
                raise PermissionError('approved common pool/case/graph scope mismatch')
        backend.shared_budget=self.budgets[arm]
        seal=execute(plan,backend,archive)
        result=read_payloads(archive,expected_seal=seal)[2][1];control=result['control']
        completed=bool(control and control['state']=='COMPLETED' and not control['budget']['stop_reason'])
        replies=[e['reply']['text'] for e in control['public_trace'] if e['kind']=='model_reply'] if control else []
        update=self.finish(arm,choice,completed=completed,response_text=replies[-1] if completed and replies else None,model_feedback=backend.is_live)
        return {'seal':seal,'update':update,'ordinary_text':replies[-1] if completed and replies else None,
            'private_evidence_returned_to_strategy':False,'independent_primary_findings':None}
