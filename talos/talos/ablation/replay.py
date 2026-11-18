"""Verify factor isolation, decisions, updates and exact budget/denominator replay."""
from pathlib import Path
from talos.ablation.contracts import Arm,Plan,PublicView,Choice,PublicFeedback
from talos.ablation.doubles import Reply,Script,Session
from talos.ablation.planning import gates,preparation_counts,public_topology,reset_scope,schedule
from talos.ablation.runtime import cell_id,slots
from talos.ablation.strategy import Strategy
from talos.corpus.models import content_hash
from talos.research.budget import Budget,BudgetStop
from talos.research.recorder import IntegrityError,read_payloads


def replay(archive:Path, *, expected_seal:str):
    events=read_payloads(archive,expected_seal=expected_seal)
    if not events or events[0][0]!='factorial_manifest': raise IntegrityError('factorial manifest missing')
    header=events[0][1];plan=Plan.model_validate(header['plan'])
    if plan.digest()!=header['plan_sha256'] or header['schedule']!=schedule(plan) or header['gates']!=gates():
        raise IntegrityError('plan/schedule/gate mismatch')
    script=Script.model_validate(header['script']) if header['script'] else None
    if script and set(script.replies)!={o.opportunity_id for b in plan.blocks for o in b.pool.opportunities}:
        raise IntegrityError('unmatched scripted opportunities')
    block_map={b.block_id:b for b in plan.blocks};budgets={};strategies={};sessions={};rows=[];intents={};ended=set();summary=None
    expected_order=[(entry['block_id'],entry['arm']) for entry in schedule(plan)];starts=[]
    for kind,data in events[1:]:
        if summary is not None: raise IntegrityError('data appended after summary')
        if kind=='common_preparation':
            block=block_map[data['block_id']]
            if any((block.block_id,a.value) in budgets for a in Arm): raise IntegrityError('duplicate shared preparation')
            measured=data['actual_shared_elapsed_ms']
            if measured!=data['matched_debit_each_arm_ms'] or data['accounting']!=plan.accounting.model_dump(mode='json'):
                raise IntegrityError('unequal/unversioned overhead charge')
            graph=public_topology(block) if data['graph'] is not None else None
            if graph and data['graph']!=graph.model_dump(mode='json'): raise IntegrityError('graph contains disallowed topology/metadata')
            for arm in Arm:
                budget=Budget(plan.limits)
                try: budget.reserve({'elapsed_ms':plan.preparation_reserve_ms})
                except BudgetStop: pass
                if budget.pending is not None:
                    if measured is None or type(measured) is not int or measured<0: raise IntegrityError('unmeasured preparation')
                    try: budget.settle({'elapsed_ms':measured})
                    except BudgetStop: pass
                budgets[(block.block_id,arm.value)]=budget
            if data['physical_builds']!=int(graph is not None and bool(block.pool.opportunities)):
                raise IntegrityError('shared projection build count mismatch')
            if graph is None and measured is not None: raise IntegrityError('missing prepared graph')
        elif kind=='arm_start':
            key=(data['block_id'],data['arm']);block=block_map[key[0]];arm=Arm(key[1])
            if key in starts or key not in budgets: raise IntegrityError('arm restart or preparation absent')
            if starts and starts[-1] not in ended: raise IntegrityError('overlapping/reordered arms')
            starts.append(key)
            if starts!=expected_order[:len(starts)]: raise IntegrityError('unmatched/reordered arms')
            if data['limits_sha256']!=content_hash(plan.limits): raise IntegrityError('unequal arm ceilings')
            if data['view'] is not None:
                from talos.ablation.contracts import view_for
                view=PublicView.model_validate(data['view'])
                if view!=view_for(block.pool,arm,public_topology(block)): raise IntegrityError('graph/feedback/public pool leakage')
                strategy=Strategy(arm,view,plan.seed,scope_id=plan.comparison_id+':'+block.block_id);strategies[key]=strategy
                if data['initial_state']!=strategy.state.model_dump(mode='json'): raise IntegrityError('arm state contamination')
            elif data['initial_state'] is not None: raise IntegrityError('state without view')
            sessions[key]=Session(script) if script else None
        elif kind=='attempt_intent':
            ident=data['cell_id'];key=(data['block_id'],data['arm'])
            if ident in intents or key not in starts or key in ended: raise IntegrityError('duplicate/misplaced intent')
            budget=budgets[key]
            try: budget.reserve({**script.reservation,'elapsed_ms':plan.attempt_timeout_ms})
            except (BudgetStop,AttributeError): raise IntegrityError('unbudgeted attempt') from None
            if data['reservation']!=budget.snapshot(): raise IntegrityError('reservation mismatch')
            intents[ident]=key
        elif kind=='factorial_cell':
            key=(data['block_id'],data['arm']);block=block_map[key[0]];arm=Arm(key[1]);budget=budgets[key]
            if key not in starts or key in ended: raise IntegrityError('cell outside active arm')
            count=sum((r['block_id'],r['arm'])==key for r in rows)
            planned=slots(plan,block)
            if count>=len(planned): raise IntegrityError('extra cell')
            expected_kind,index,utility_id=planned[count]
            if (data['kind'],data['index'],data['cell_id'])!=(expected_kind,index,cell_id(plan,block,arm,expected_kind,index)):
                raise IntegrityError('missing/reordered/substituted cell')
            if data['security_outcome']!='UNKNOWN' or data['primary_finding_eligible'] or data['actual_task_success'] is not None:
                raise IntegrityError('test doubles cannot establish actual security or utility outcomes')
            if data['cell_id'] in intents:
                if intents[data['cell_id']]!=key: raise IntegrityError('cross-arm intent')
                strategy=strategies[key]
                if expected_kind=='selection':
                    choice=Choice.model_validate(data['choice'])
                    if choice!=strategy.choose() or data['opportunity_id']!=choice.opportunity_id: raise IntegrityError('decision/state replay mismatch')
                else:
                    choice=None
                    if data['choice'] is not None or data['opportunity_id']!=utility_id or data['update'] is not None:
                        raise IntegrityError('utility slot changed selection/feedback policy')
                if data['reset'] is not None:
                    reset=sessions[key].reset(reset_scope(plan,block,arm,count),data['opportunity_id'])
                    if data['reset']!=reset: raise IntegrityError('failed/stale/cross-arm reset scope')
                reply=Reply.model_validate(data['reply']) if data['reply'] else None
                if reply and (data['reset'] is None or not data['reset']['healthy']): raise IntegrityError('dispatch without healthy reset')
                if reply and reply!=sessions[key].dispatch(data['opportunity_id']): raise IntegrityError('asymmetric simulated response')
                if choice and data['update'] is not None:
                    status=data['completion_status']
                    if status not in ('completed','failed','timed_out','unsupported','unknown'): raise IntegrityError('completion status missing')
                    if reply and status!=reply.status and not (status=='timed_out' and data['elapsed_ms']>=plan.attempt_timeout_ms):
                        raise IntegrityError('completion/feedback timing mismatch')
                    feedback=reply.feedback if reply and status=='completed' and arm.adaptive else None
                    actual=strategy.finish(choice,status=status,feedback=feedback)
                    if data['update']!=actual.model_dump(mode='json'): raise IntegrityError('private/incomplete/cross-arm feedback update')
                elif choice and data['error_type'] is None: raise IntegrityError('selection disposition/update missing')
                if data['error_type'] is not None: usage=dict(reply.usage) if reply else {'attempts':1,'target_calls':None}
                else: usage=dict(reply.usage) if reply else {'attempts':1,'target_calls':0}
                if type(data['elapsed_ms']) is not int or data['elapsed_ms']<0: raise IntegrityError('elapsed measurement missing')
                usage['elapsed_ms']=data['elapsed_ms']
                accounting_failure=False
                try: budget.settle(usage)
                except BudgetStop: accounting_failure=True
                if accounting_failure: expected_state='accounting_failure'
                elif data['error_type'] is not None: expected_state='error'
                elif data['completion_status']=='timed_out' and (reply is None or reply.status!='timed_out'): expected_state='timed_out'
                elif reply: expected_state='simulated_'+reply.status
                elif data['reset'] and not data['reset']['healthy']: expected_state='reset_failed'
                else: raise IntegrityError('attempt disposition missing')
                if data['state']!=expected_state: raise IntegrityError('failed/unknown/timeout disposition concealed')
                if data['error_type'] is not None and not budget.stop_reason:
                    budget.stop_reason='Selector/feedback error; no subsequent simulated calls.'
                if data['completion_status']=='timed_out' and not budget.stop_reason:
                    budget.stop_reason='Timeout; no subsequent simulated calls.'
            else:
                if any(data[field] is not None for field in ('choice','update','reset','reply','elapsed_ms','completion_status','error_type')):
                    raise IntegrityError('work performed without durable budget reservation')
                if data['state']=='budget_exhausted' and not budget.stop_reason:
                    try: budget.reserve({**script.reservation,'elapsed_ms':plan.attempt_timeout_ms})
                    except BudgetStop: pass
                    if not budget.stop_reason: raise IntegrityError('false budget exhaustion')
            if data['budget']!=budget.snapshot(): raise IntegrityError('budget usage/unknown accounting mismatch')
            rows.append(data)
        elif kind=='arm_end':
            key=(data['block_id'],data['arm'])
            if key in ended or key not in starts: raise IntegrityError('duplicate arm finalization')
            block=block_map[key[0]]
            if sum((r['block_id'],r['arm'])==key for r in rows)!=len(slots(plan,block)): raise IntegrityError('arm omitted planned cells')
            if data['budget']!=budgets[key].snapshot(): raise IntegrityError('arm totals mismatch')
            expected_state=strategies[key].state.model_dump(mode='json') if key in strategies else None
            if data['final_state']!=expected_state: raise IntegrityError('final adaptive state mismatch')
            ended.add(key)
        elif kind=='factorial_summary': summary=data
        else: raise IntegrityError('unknown factorial event')
    expected={'planned_cells':sum(4*len(slots(plan,b)) for b in plan.blocks),'recorded_cells':len(rows),
        'execution_states':{state:sum(r['state']==state for r in rows) for state in sorted({r['state'] for r in rows})},
        'independently_confirmed_primary_findings':None,'empirical_effect_sizes':None,'actual_legitimate_task_success':None,'gates':gates(),'case_preparation_counts':preparation_counts(plan),
        'actual_provider_measurements':{'attacker_model':None,'target_model':None,'tokens':None,'cost':None}}
    if summary!=expected or len(ended)!=len(expected_order) or len(rows)!=expected['planned_cells']:
        raise IntegrityError('incomplete/altered matched denominators')
    return {'plan':plan,'rows':rows,'summary':summary,'budgets':{str(k):v.snapshot() for k,v in budgets.items()}}
