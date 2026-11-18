"""Scheduler verification only. No delivery, model, target or tool executor."""
from __future__ import annotations
from math import ceil
from pathlib import Path
import time

from talos.corpus.models import content_hash
from talos.ablation.contracts import Arm,Plan,view_for
from talos.ablation.doubles import Script,Session
from talos.ablation.planning import gates,preparation_counts,public_topology,reset_scope,schedule
from talos.ablation.strategy import Strategy
from talos.research.budget import Budget,BudgetStop
from talos.research.recorder import Recorder


def slots(plan,block):
    return [('selection',i,None) for i in range(plan.selection_slots)]+[
        ('utility',i,ident) for i,ident in enumerate(block.utility_opportunity_ids)]


def cell_id(plan,block,arm,kind,index):
    return content_hash([plan.comparison_id,block.block_id,arm.value,kind,index])


def execute(plan:Plan,archive:Path, *, script:Script|None=None, clock_ns=None):
    plan=Plan.model_validate(plan.model_dump())
    if script is not None:
        if type(script) is not Script: raise TypeError('only data-only scheduler test scripts accepted')
        script=Script.model_validate(script.model_dump())
        expected={o.opportunity_id for b in plan.blocks for o in b.pool.opportunities}
        if set(script.replies)!=expected: raise ValueError('script must cover exactly the common opportunity set')
    clock=clock_ns or time.monotonic_ns
    def elapsed(start): return max(0,ceil((clock()-start)/1_000_000))
    with Recorder(Path(archive),create=True) as recorder:
        recorder.append('factorial_manifest',{'plan':plan.model_dump(mode='json'),'plan_sha256':plan.digest(),
            'schedule':schedule(plan),'script':script.model_dump(mode='json') if script else None,
            'clock_basis':'injected_synthetic_scheduler_clock' if clock_ns else 'measured_local_monotonic',
            'gates':gates()})
        records=[];all_budgets={}
        for block in plan.blocks:
            budgets={arm:Budget(plan.limits) for arm in Arm};views={};graph=None;prep_ms=None
            for budget in budgets.values():
                try: budget.reserve({'elapsed_ms':plan.preparation_reserve_ms})
                except BudgetStop: pass
            if all(b.pending is not None for b in budgets.values()):
                start=clock()
                graph=public_topology(block)
                views={arm:view_for(block.pool,arm,graph) for arm in Arm}
                prep_ms=elapsed(start)
                for budget in budgets.values():
                    try: budget.settle({'elapsed_ms':prep_ms})
                    except BudgetStop: pass
            recorder.append('common_preparation',{'block_id':block.block_id,'graph':graph.model_dump(mode='json') if graph else None,
                'actual_shared_elapsed_ms':prep_ms,'matched_debit_each_arm_ms':prep_ms,
                'physical_builds':int(graph is not None and bool(block.pool.opportunities)),'accounting':plan.accounting.model_dump(mode='json')})
            for scheduled in [s for s in schedule(plan) if s['block_id']==block.block_id]:
                arm=Arm(scheduled['arm']);budget=budgets[arm]
                strategy=Strategy(arm,views[arm],plan.seed,scope_id=plan.comparison_id+':'+block.block_id) if arm in views else None
                session=Session(script) if script else None
                recorder.append('arm_start',{'block_id':block.block_id,'arm':arm.value,
                    'view':views[arm].model_dump(mode='json') if strategy else None,'limits_sha256':content_hash(plan.limits),
                    'initial_state':strategy.state.model_dump(mode='json') if strategy else None})
                for ordinal,(kind,index,utility_id) in enumerate(slots(plan,block)):
                    ident=cell_id(plan,block,arm,kind,index)
                    row={'cell_id':ident,'block_id':block.block_id,'arm':arm.value,'kind':kind,'index':index,
                        'state':'unknown','reason':'not executed','opportunity_id':utility_id,'choice':None,'update':None,
                        'reset':None,'reply':None,'elapsed_ms':None,'completion_status':None,'error_type':None,'security_outcome':'UNKNOWN',
                        'primary_finding_eligible':False,'actual_task_success':None,'simulated_utility_success':None}
                    if budget.stop_reason:
                        row.update(state='budget_exhausted',reason=budget.stop_reason)
                    elif script is None:
                        row.update(state='delivery_unavailable',reason='No corpus delivery adapter; no direct-tool substitute.')
                    elif strategy is None or not block.pool.opportunities:
                        row.update(state='unsupported',reason='No planning-compatible public opportunities.')
                    else:
                        reserve={**script.reservation,'elapsed_ms':plan.attempt_timeout_ms}
                        try: budget.reserve(reserve)
                        except BudgetStop as error:
                            row.update(state='budget_exhausted',reason=str(error))
                        else:
                            recorder.append('attempt_intent',{'cell_id':ident,'block_id':block.block_id,'arm':arm.value,
                                                             'kind':kind,'reservation':budget.snapshot()})
                            start=clock();choice=None;reply=None;usage={'attempts':1,'target_calls':0};status='failed'
                            try:
                                if kind=='selection':
                                    choice=strategy.choose();row['choice']=choice.model_dump(mode='json')
                                    selected=choice.opportunity_id
                                else: selected=utility_id
                                row['opportunity_id']=selected
                                scope=reset_scope(plan,block,arm,ordinal)
                                reset=session.reset(scope,selected);row['reset']=reset
                                if not reset['healthy']:
                                    row.update(state='reset_failed',reason='Test-double reset failed; no dispatch.')
                                elif elapsed(start)>=plan.attempt_timeout_ms:
                                    row.update(state='timed_out',reason='Deadline reached before simulated dispatch.')
                                else:
                                    reply=session.dispatch(selected);row['reply']=reply.model_dump(mode='json')
                                    usage=dict(reply.usage);status=reply.status
                                    row.update(state='simulated_'+reply.status,reason='Scheduler test double; not a prompt attack or oracle result.')
                                    if kind=='utility': row['simulated_utility_success']=reply.utility_success
                                late=elapsed(start)>=plan.attempt_timeout_ms
                                if late: status='timed_out';row.update(state='timed_out',reason='Cooperative scheduler deadline exceeded.')
                                if choice:
                                    feedback=reply.feedback if reply and status=='completed' and arm.adaptive else None
                                    update=strategy.finish(choice,status=status,feedback=feedback)
                                    row['update']=update.model_dump(mode='json')
                            except Exception as error:
                                status='failed';row['error_type']=type(error).__name__
                                row.update(state='error',reason=f'Scheduler failed: {type(error).__name__}; no retry.')
                                # Any begun dispatch with lost accounting must stop, not become zero usage.
                                usage=dict(reply.usage) if reply is not None else {'attempts':1,'target_calls':None}
                            row['completion_status']=status
                            measured=elapsed(start);row['elapsed_ms']=measured
                            usage['elapsed_ms']=measured
                            try: budget.settle(usage)
                            except BudgetStop as error:
                                row.update(state='accounting_failure',reason=str(error))
                            if row['error_type'] is not None and not budget.stop_reason:
                                budget.stop_reason='Selector/feedback error; no subsequent simulated calls.'
                            if status=='timed_out' and not budget.stop_reason: budget.stop_reason='Timeout; no subsequent simulated calls.'
                    row['budget']=budget.snapshot();recorder.append('factorial_cell',row);records.append(row)
                final={'block_id':block.block_id,'arm':arm.value,'budget':budget.snapshot(),
                       'final_state':strategy.state.model_dump(mode='json') if strategy else None}
                recorder.append('arm_end',final);all_budgets[(block.block_id,arm.value)]=final
        summary={'planned_cells':sum(4*len(slots(plan,b)) for b in plan.blocks),'recorded_cells':len(records),
                 'execution_states':{state:sum(r['state']==state for r in records) for state in sorted({r['state'] for r in records})},
                 'independently_confirmed_primary_findings':None,'empirical_effect_sizes':None,
                 'actual_legitimate_task_success':None,'gates':gates(),'case_preparation_counts':preparation_counts(plan),
                 'actual_provider_measurements':{'attacker_model':None,'target_model':None,'tokens':None,'cost':None}}
        recorder.append('factorial_summary',summary)
        return recorder.seal()
