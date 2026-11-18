"""Matched planning-only PR-04 inputs and prospective schedules, never a cohort."""
import random
from talos.ablation.contracts import Arm,Block,CasePreparation,Plan
from talos.corpus import load_corpus,load_bindings,plan_case
from talos.corpus.models import Surface,content_hash
from talos.corpus.planning import CommonPool,PublicGraph,public_opportunity,project_possible_graph
from talos.graph.portable import build_profile_graph


def corpus_block(profile, *, block_id,scenario_id,scenario_cluster_id,variant_group_id,binding_ids):
    """Explicit supplied bindings only; surfaces are hypothetical for scheduler tests."""
    corpus=load_corpus();bindings=load_bindings()
    records={r.identity:r for r in corpus.records};indexed={b.binding_id:b for b in bindings.bindings}
    if len(set(binding_ids))!=len(binding_ids): raise ValueError('duplicate case binding')
    opportunities=[];prepared=[];utility=[]
    for ident in binding_ids:
        if ident not in indexed: raise ValueError('unknown case binding')
        binding=indexed[ident];record=records[binding.case_identity]
        actual=plan_case(record,profile,binding)
        hypothetical=plan_case(record,profile,binding,available_surfaces=frozenset(Surface))
        opportunity=None
        if hypothetical.status=='APPLICABLE':
            opportunity=public_opportunity(record,profile,binding,hypothetical)
            opportunities.append(opportunity)
            if record.case.kind=='authorized_task': utility.append(opportunity.opportunity_id)
        prepared.append(CasePreparation(case_identity=record.identity,binding_id=ident,
            real_applicability=actual.status,planning_applicability=hypothetical.status,
            opportunity_id=opportunity.opportunity_id if opportunity else None,reasons=actual.reasons))
    return Block(block_id=block_id,target_profile=profile,target_version=profile.fixture_id,scenario_id=scenario_id,
        scenario_cluster_id=scenario_cluster_id,variant_group_id=variant_group_id,
        pool=CommonPool(opportunities=tuple(opportunities)),utility_opportunity_ids=tuple(utility),case_preparation=tuple(prepared))


def public_topology(block:Block):
    if not block.pool.opportunities: return PublicGraph(nodes=(),edges=())
    return project_possible_graph(build_profile_graph(block.target_profile))


def schedule(plan:Plan):
    plan=Plan.model_validate(plan.model_dump())
    base=list(Arm);random.Random(plan.seed).shuffle(base)
    return [{'block_id':block.block_id,'arm':base[(position+index)%4].value,'position':position,
             'shared_pool_sha256':block.pool.digest(),'reset_contract':block.reset_contract}
            for index,block in enumerate(plan.blocks) for position in range(4)]


def reset_scope(plan:Plan,block:Block,arm:Arm,slot:int):
    return content_hash({'comparison_id':plan.comparison_id,'block_id':block.block_id,'arm':arm.value,'slot':slot,
                         'seed':plan.seed,'reset_contract':block.reset_contract})


def gates():
    return {'operational_status':'BLOCKED','delivery':'UNAVAILABLE','independent_oracle_validation':'PENDING',
        'cohort':'UNASSIGNED','primary_findings':None,'effect_sizes':None,
        'reasons':['No reviewed corpus prompt delivery adapter.','No genuine independent reference labels/source custody approvals.',
                   'No approved empirical protocol, primary budget, clustering, information rules or held-out cohort.']}


def dry_run(plan:Plan):
    plan=Plan.model_validate(plan.model_dump())
    return {'schema_version':'talos.factorial-dry-run.v1','plan_sha256':plan.digest(),'schedule':schedule(plan),
            'blocks':{b.block_id:{'pool_sha256':b.pool.digest(),'planning_opportunities':len(b.pool.opportunities),
                                 'case_preparation':[p.model_dump(mode='json') for p in b.case_preparation]} for b in plan.blocks},
            'gates':gates()}


def preparation_counts(plan):
    return {b.block_id:{'requested_cases':len(b.case_preparation),
        'real_applicability':{state:sum(c.real_applicability==state for c in b.case_preparation) for state in ('UNKNOWN','INAPPLICABLE')},
        'planning_applicability':{state:sum(c.planning_applicability==state for c in b.case_preparation) for state in ('APPLICABLE','UNKNOWN','INAPPLICABLE')}}
        for b in plan.blocks}
