"""Explicit hypothetical common pools and data-only scripts, not attack campaigns."""
from pathlib import Path
from talos.ablation import Plan,corpus_block
from talos.ablation.contracts import PublicFeedback
from talos.ablation.doubles import Reply,Script
from talos.corpus import load_bindings,load_corpus,content_hash
from talos.research.contracts import DIMENSIONS,Limits,capture_provenance
from talos.targets.profiles import target_profile
from talos.targets.helpdesk import HelpdeskDomain
from talos.targets.documents import DocumentDomain

ROOT=Path(__file__).parents[2]


def block(domain='it-helpdesk',variant='vulnerable',ident='block-one'):
    profile=target_profile(HelpdeskDomain() if domain=='it-helpdesk' else DocumentDomain(),domain+'.synthetic-matched-id',
                           domain+'.test-source',variant)
    ids=[b.binding_id for b in load_bindings().bindings if b.domain==domain and any(
        b.case_identity.startswith(suffix+'@') for suffix in ('TP1-DIRECT','TP1-WORKFLOW','TP1-AUTHORIZED'))]
    return corpus_block(profile,block_id=ident,scenario_id='synthetic-scenario',scenario_cluster_id='synthetic-cluster',
                        variant_group_id=domain+'.paired-fixtures',binding_ids=ids)


def plan(blocks=None,**changes):
    amounts={d:0 for d in DIMENSIONS};amounts.update(attempts=20,target_calls=20,elapsed_ms=100000)
    p=Plan(comparison_id='synthetic-scheduler-only',provenance=capture_provenance(ROOT,ROOT/'talos/requirements-research.lock'),
        corpus_sha256=content_hash(load_corpus()),seed=41,limits=Limits(amounts=amounts),preparation_reserve_ms=5000,
        attempt_timeout_ms=1000,selection_slots=4,blocks=tuple(blocks or (block(),)))
    return Plan.model_validate({**p.model_dump(),**changes})


def script(p,**reply_changes):
    names=sorted({t.name for b in p.blocks for o in b.pool.opportunities for t in o.tools})
    replies={}
    for b in p.blocks:
        for o in b.pool.opportunities:
            raw=dict(status='completed',feedback=PublicFeedback(response_text=' '.join(names),referenced_tools=tuple(names)),
                     usage={'attempts':1,'target_calls':1},utility_success=True)
            raw.update(reply_changes);replies[o.opportunity_id]=Reply(**raw)
    return Script(replies=replies,reservation={'attempts':1,'target_calls':1})


class Clock:
    """Synthetic deterministic clock; archive labels it injected, not measured wall time."""
    def __init__(self,step_ns=100000): self.current=0;self.step=step_ns
    def __call__(self): self.current+=self.step;return self.current
