"""One selector, differing only in two declared factorial switches."""
import re
from talos.corpus.models import content_hash
from talos.ablation.contracts import Arm,Choice,PublicFeedback,PublicView,State,Update


def mentions(text,names):
    return {name for name in names if re.search(r'(?<![\w])'+re.escape(name)+r'(?![\w])',text)}


class Strategy:
    def __init__(self,arm:Arm,view:PublicView,seed:int, *, scope_id='standalone-engineering'):
        self.arm=Arm(arm);self.view=PublicView.model_validate(view.model_dump());self.seed=seed
        if self.arm.graph!=(self.view.graph_annotations is not None): raise ValueError('graph visibility disagrees with arm')
        self.inventory={t.name for o in self.view.pool.opportunities for t in o.tools}
        self.ids=tuple(sorted(o.opportunity_id for o in self.view.pool.opportunities))
        self.tool_mentions={o.opportunity_id:mentions(' '.join(s.text for s in o.stimuli),self.inventory)
                            for o in self.view.pool.opportunities}
        self.graph_scores={ident:0 for ident in self.ids}
        if self.view.graph_annotations:
            for ident in self.ids:
                nodes={'tool:'+n for n in self.tool_mentions[ident]}
                self.graph_scores[ident]=sum(e.relation=='possible_data_flow' and e.source in nodes and e.target in nodes
                                             for e in self.view.graph_annotations.edges)
        self.tie={ident:content_hash({'seed':seed,'opportunity_id':ident}) for ident in self.ids}
        self.frozen_order=tuple(sorted(self.ids,key=lambda i:(-self.graph_scores[i],self.tie[i],i)))
        self.owner=content_hash({'arm':self.arm.value,'pool':view.pool.digest(),'seed':seed,'scope_id':scope_id})
        self.state=State(owner_sha256=self.owner,slot=0,weights={i:0 for i in self.ids},visits={i:0 for i in self.ids},updates=0)

    def choose(self):
        current=State.model_validate(self.state.model_dump())
        if current.owner_sha256!=self.owner or set(current.weights)!=set(self.ids): raise ValueError('cross-arm/block state contamination')
        if not self.ids: selected=None
        elif not self.arm.adaptive: selected=self.frozen_order[current.slot%len(self.ids)]
        else:
            selected=min(self.ids,key=lambda i:(-current.weights[i],(self.frozen_order.index(i)-current.slot)%len(self.ids),i))
        return Choice(slot=current.slot,opportunity_id=selected,state_before_sha256=content_hash(current),graph_used=self.arm.graph)

    def finish(self,choice:Choice, *, status:str, feedback:PublicFeedback|None):
        if Choice.model_validate(choice.model_dump())!=self.choose(): raise ValueError('stale/forged/cross-arm choice')
        before=State.model_validate(self.state.model_dump())
        feedback=PublicFeedback.model_validate(feedback.model_dump()) if feedback is not None else None
        if feedback and not set(feedback.referenced_tools)<=self.inventory: raise ValueError('feedback names unknown/private tools')
        weights=dict(before.weights);visits=dict(before.visits)
        if choice.opportunity_id is not None: visits[choice.opportunity_id]+=1
        applied=self.arm.adaptive and status=='completed' and feedback is not None and choice.opportunity_id is not None
        if applied:
            visible=mentions(feedback.response_text,self.inventory)|set(feedback.referenced_tools)
            for ident in self.ids: weights[ident]+=len(self.tool_mentions[ident]&visible)
        after=State(owner_sha256=self.owner,slot=before.slot+1,weights=weights,visits=visits,updates=before.updates+int(applied))
        self.state=after
        return Update(applied=bool(applied),reason='ordinary public tool mentions only' if applied else 'static/incomplete/no permitted feedback',
                      state_before=before,state_after=after,feedback=feedback if applied else None)
