"""Opt-in offline fixture harness, no inference or corpus attack executor."""
from __future__ import annotations

from math import ceil
from pathlib import Path
import random
import time

from talos.corpus import content_hash, load_bindings, load_corpus, plan_case
from talos.graph.portable import build_profile_graph, graph_json
from talos.judging import EvidenceBundle, Outcome, judge
from talos.research.budget import Budget, BudgetStop
from talos.research.contracts import CellResult, Packet, RunPlan
from talos.research.recorder import Recorder, IntegrityError
from talos.research.replay import RecordedPolicy, RecordedReader, replay
from talos.targets import ControlledEnvironment
from talos.targets.store import Fault, POLICY_VERSION, ResetFault


def _unknown(cell,state,reason,elapsed=None):
    return CellResult(cell_id=cell.cell_id,outcome=Outcome.UNKNOWN,state=state,reason=reason,
                      abstention_reason=reason,elapsed_ms=elapsed)


def _inputs(plan):
    plan=RunPlan.model_validate(plan.model_dump())
    corpus,bindings=load_corpus(),load_bindings()
    if plan.corpus_sha256!=content_hash(corpus): raise ValueError('corpus identity mismatch')
    records={r.identity:r for r in corpus.records}; by_binding={b.binding_id:b for b in bindings.bindings}
    selected={}
    for c in plan.cells:
        if c.case_identity not in records or c.binding_id not in by_binding:
            raise ValueError('case/binding identity absent from exact corpus')
        b=by_binding[c.binding_id]
        if b.case_identity!=c.case_identity or b.domain!=plan.profile.domain:
            raise ValueError('case binding/profile mismatch')
        selected[c.cell_id]=(records[c.case_identity],b)
    return plan,selected


def execution_order(plan):
    order=list(plan.cells)
    if plan.order=='seeded_shuffle': random.Random(plan.seed).shuffle(order)
    return order


def dry_run(plan:RunPlan):
    plan,selected=_inputs(plan)
    return {'configuration_sha256':plan.digest(),'learning_sha256':content_hash(plan.learning),
            'order':[c.cell_id for c in execution_order(plan)],
            'cells':{c.cell_id:plan_case(selected[c.cell_id][0],plan.profile,selected[c.cell_id][1]).model_dump(mode='json') for c in plan.cells}}


def execute(plan:RunPlan, environment:ControlledEnvironment, archive:Path, *, clock_ns=time.monotonic_ns):
    """Only direct_fixture_control cells can call synthetic tools.

    A local synchronous overrun is recorded and stops later calls. No hard kill,
    automatic retry, provider adapter or external target is implemented.
    """
    plan,selected=_inputs(plan)
    if type(environment) is not ControlledEnvironment:
        raise TypeError('only exact local controlled fixtures supported')
    if environment.profile()!=plan.profile or plan.target_version!=plan.profile.fixture_id:
        raise ValueError('exact target/profile version mismatch')
    if (environment.domain.policy_id,POLICY_VERSION)!=(plan.policy_id,plan.policy_version):
        raise ValueError('policy version mismatch')
    if plan.trust and frozenset(plan.trust.trusted_source_ids)!=frozenset((environment.source_id,)):
        raise ValueError('trusted source declaration does not match exact fixture instance')
    budget=Budget(plan.limits)
    with Recorder(archive,create=True) as recorder:
        recorder.append('manifest',{'plan':plan.model_dump(mode='json'),'configuration_sha256':plan.digest(),
            'learning_sha256':content_hash(plan.learning),'execution_order':[c.cell_id for c in execution_order(plan)],
            'corpus':load_corpus().model_dump(mode='json'),'bindings':load_bindings().model_dump(mode='json'),
            'graph':__import__('json').loads(graph_json(build_profile_graph(plan.profile))),
            'delivery_adapter':{'id':'unavailable','version':'1'},'synthetic_not_prompt_injection':True})
        stopped=None
        try:
            for cell in execution_order(plan):
                rec,binding=selected[cell.cell_id]
                compatibility=plan_case(rec,plan.profile,binding)
                recorder.append('prepared',{'cell_id':cell.cell_id,'compatibility':compatibility.model_dump(mode='json')})
                if stopped:
                    recorder.append('result',_unknown(cell,'missing',stopped).model_dump(mode='json'));continue
                if compatibility.status=='INAPPLICABLE':
                    recorder.append('result',_unknown(cell,'inapplicable','; '.join(compatibility.reasons)).model_dump(mode='json'));continue
                if cell.mode=='corpus_delivery':
                    recorder.append('result',_unknown(cell,'delivery_unavailable',
                        'No reviewed prompt/tool-output/document adapter; profile compatibility is not delivery.').model_dump(mode='json'));continue
                # Direct controls are explicitly separate from corpus payload delivery.
                try:
                    budget.reserve({'attempts':1,'target_calls':len(binding.tool_bindings),'elapsed_ms':plan.timeout_ms})
                except BudgetStop as error:
                    stopped=str(error)
                    recorder.append('result',_unknown(cell,'budget_exhausted',stopped).model_dump(mode='json'));continue
                recorder.append('intent',{'cell_id':cell.cell_id,'mode':cell.mode,'budget_reservation':budget.snapshot()})
                start=clock_ns();calls=0
                try:
                    receipt=environment.reset(scenario_id=cell.scenario_id,run_id=plan.run_id,
                                              repeat_id=cell.repeat_id,fault=ResetFault(cell.reset_fault))
                    recorder.append('reset',{'cell_id':cell.cell_id,'receipt':receipt.model_dump(mode='json')})
                    if not receipt.healthy: result=_unknown(cell,'reset_failed','Reset proof failed/incomplete; no invocation.')
                    else:
                        # Revalidate the exact recorded seed before any control action.
                        from talos.targets.store import digest
                        if receipt.seed_hash!=digest(environment.snapshot()) or environment.snapshot()!=environment.domain.seed():
                            result=_unknown(cell,'reset_failed','Reset state differs from deterministic seed.')
                        else:
                            packets=[]
                            for slot in sorted(binding.tool_bindings,key=lambda x:(x!='source_tool',x)):
                                elapsed=ceil((clock_ns()-start)/1_000_000)
                                if elapsed>=plan.timeout_ms:
                                    result=_unknown(cell,'timed_out','Deadline reached before next action.',elapsed);break
                                environment.inject_fault_once(Fault(cell.tool_fault) if slot=='action_tool' else Fault.NONE)
                                action=environment.action(binding.tool_bindings[slot],binding.proposed_actor_id,
                                    binding.proposed_tool_arguments[slot],action_id=f'{plan.run_id}:{cell.cell_id}:{slot}')
                                calls+=1
                                call_start=clock_ns()
                                response=environment.execute(action)
                                request_latency=max(0,ceil((clock_ns()-call_start)/1_000_000))
                                assessment=environment.policy.assess(action)
                                evidence,issues=environment.reader().inspect(action)
                                elapsed=ceil((clock_ns()-start)/1_000_000)
                                if elapsed>=plan.timeout_ms:
                                    evidence=EvidenceBundle(complete=False,records=evidence.records)
                                    issues=(*issues,'cooperative timeout; completion within deadline not established')
                                trust=plan.trust.trusted_source_ids if plan.trust else ()
                                verdict=judge(response.observation,policy=RecordedPolicy(assessment) if plan.trust else None,
                                    evidence_reader=RecordedReader(evidence),trusted_source_ids=frozenset(trust))
                                packet=Packet(observation=response.observation,request_latency_ms=request_latency,policy=assessment,policy_enabled=plan.trust is not None,evidence=evidence,
                                    raw_store_records=environment.records(action),reset_receipt=receipt.model_dump(mode='json'),
                                    reader_issues=issues,trusted_source_ids=trust,verdict=verdict)
                                # Every workflow step is stored, not only the terminal effect.
                                recorder.append('action',{'cell_id':cell.cell_id,'slot':slot,'packet':packet.model_dump(mode='json')})
                                packets.append(packet)
                                result=CellResult(cell_id=cell.cell_id,outcome=verdict.status,
                                    state='timed_out' if elapsed>=plan.timeout_ms or cell.tool_fault=='timeout' else 'completed',reason=verdict.reason,
                                    abstention_reason=verdict.uncertainty_reason if verdict.status==Outcome.UNKNOWN else None,
                                    packet=packet,elapsed_ms=elapsed)
                                if result.state=='timed_out': break
                except Exception as error:
                    result=_unknown(cell,'error',f'Execution failed: {type(error).__name__}; no retry.')
                    import traceback
                    recorder.append('interruption',{'cell_id':cell.cell_id,'exception_type':type(error).__name__,
                        'exception_module':type(error).__module__,
                        'stack':[{'file':f.filename,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__)],
                        'message':'Suppressed to avoid accidental secret/PII recording; no retry.'})
                elapsed=max(0,ceil((clock_ns()-start)/1_000_000))
                try: budget.settle({'attempts':1,'target_calls':calls,'elapsed_ms':elapsed})
                except BudgetStop as error:
                    stopped=str(error)
                    result=_unknown(cell,'timed_out' if elapsed>=plan.timeout_ms else 'error',stopped,elapsed)
                recorder.append('budget',budget.snapshot())
                if result.state=='timed_out': stopped='Timeout; subsequent cells not executed.'
                result=CellResult.model_validate({**result.model_dump(),'elapsed_ms':elapsed})
                recorder.append('result',result.model_dump(mode='json'))
        except BaseException:
            # Durable intents/results remain. Recovery never reissues indeterminate calls.
            raise
        current=replay(archive,allow_incomplete=True)
        recorder.append('summary',{'accounting':current['accounting'],'budget':budget.snapshot(),
                                   'stop_reason':stopped or 'planned_cells_accounted'})
        return recorder.seal()


def finalize_interrupted(archive:Path):
    """Checkpoint recovery is accounting-only; never duplicate an uncertain call."""
    current=replay(archive,allow_incomplete=True)
    if current['summary'] is not None: raise IntegrityError('terminal run cannot be resumed')
    with Recorder(archive) as recorder:
        for cell in current['plan'].cells:
            if cell.cell_id not in current['results']:
                recorder.append('result',_unknown(cell,'interrupted','Run interrupted; no implicit retry or substitute.').model_dump(mode='json'))
        current=replay(archive,allow_incomplete=True)
        recorder.append('summary',{'accounting':current['accounting'],'budget':None,
                                   'stop_reason':'interrupted_recovery_usage_unknown'})
        return recorder.seal()
