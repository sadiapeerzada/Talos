"""Append-only normalized comparator results with no operational execution path."""
from math import ceil
from pathlib import Path
import time

from talos.comparator.contracts import Plan,NormalizedResult
from talos.comparator.isolation import native_control,deterministic_projection
from talos.comparator.matching import gates,mapping_status,validate_plan
from talos.comparator.measurement import normalize_control
from talos.research.budget import Budget,BudgetStop
from talos.research.recorder import Recorder


def execute(plan:Plan,archive:Path, *, isolated_python:Path|None=None,offline_scripts:dict|None=None):
    plan=validate_plan(plan)
    if (isolated_python is None)!=(offline_scripts is None): raise ValueError('explicit interpreter and offline scripts must be supplied together')
    if offline_scripts is not None and set(offline_scripts)!={m.opportunity_id for m in plan.mappings if m.surface.value=='user_message'}:
        raise ValueError('all and only direct native-control opportunities require scripts; unsupported remain visible')
    budget=Budget(plan.common_limits);rows=[]
    with Recorder(Path(archive),create=True) as recorder:
        recorder.append('comparator_manifest',{'plan':plan.model_dump(mode='json'),'plan_sha256':plan.digest(),
            'offline_native_controls':offline_scripts is not None,'gates':gates()})
        for mapping in plan.mappings:
            state,reason=mapping_status(mapping);receipt=None;measured=None;projection=None
            row=NormalizedResult(opportunity_id=mapping.opportunity_id,state=state,reason=reason)
            if budget.stop_reason: row=NormalizedResult(opportunity_id=mapping.opportunity_id,state='BUDGET_STOP',reason=budget.stop_reason)
            elif state=='DELIVERY_UNAVAILABLE' and offline_scripts is not None:
                # Strict common ceilings; every native attacker/refinement request is included.
                reservation={'attempts':1,'attacker_calls':plan.config.max_turns,'target_calls':plan.config.max_turns,
                             'elapsed_ms':plan.initialization_reserve_ms+plan.attempt_timeout_ms}
                try: budget.reserve(reservation)
                except BudgetStop as error: row=NormalizedResult(opportunity_id=mapping.opportunity_id,state='BUDGET_STOP',reason=str(error))
                else:
                    recorder.append('native_control_intent',{'opportunity_id':mapping.opportunity_id,'reservation':budget.snapshot()})
                    start=time.monotonic_ns()
                    try:
                        fixture=offline_scripts[mapping.opportunity_id]
                        if set(fixture)!={'adversarial_messages','objective_responses','marker'}: raise ValueError('plugins/provider substitutions not allowed')
                        receipt,measured=native_control(plan.config,objective=mapping.shared_objective,
                            adversarial_messages=tuple(fixture['adversarial_messages']),objective_responses=tuple(fixture['objective_responses']),
                            marker=fixture['marker'],python=isolated_python,
                            timeout_ms=plan.initialization_reserve_ms+plan.attempt_timeout_ms)
                        row=normalize_control(mapping.opportunity_id,receipt);projection=deterministic_projection(receipt)
                        actual={'attempts':1,'attacker_calls':receipt.counts['adversarial_stub'],
                                'target_calls':receipt.counts['objective_stub'],'elapsed_ms':measured}
                    except Exception as error:
                        measured=ceil((time.monotonic_ns()-start)/1000000)
                        row=NormalizedResult(opportunity_id=mapping.opportunity_id,state='ERROR',reason=f'Native control failed: {type(error).__name__}; no retry.')
                        actual={'attempts':1,'attacker_calls':None,'target_calls':None,'elapsed_ms':measured}
                    try: budget.settle(actual)
                    except BudgetStop: pass
            record={'result':row.model_dump(mode='json'),'worker_elapsed_ms':measured,'semantic_projection':projection,
                'budget':budget.snapshot(),'provider_tokens':None,'provider_cost':None,
                'resource_breakdown':{'generation_callbacks':min(receipt.counts['adversarial_stub'],1) if receipt else None,
                    'refinement_callbacks':max(receipt.counts['adversarial_stub']-1,0) if receipt else None,
                    'native_local_grading':len(receipt.native_scores) if receipt else None,
                    'framework_phase_ms':receipt.phase_elapsed_ms if receipt else None,
                    'worker_total_ms':measured,'graph_preparation_ms':None,'shared_preparation_ms':None,
                    'actual_attacker_model_calls':None,'actual_target_model_calls':None,'actual_target_tool_calls':None,
                    'actual_provider_retries':None,'input_tokens':None,'output_tokens':None,'actual_cost':None},
                'accounting_basis':'native_offline_stub_callbacks_not_model_or_agent_tool_calls'}
            recorder.append('comparator_cell',record);rows.append(row)
        summary={'planned_opportunities':len(plan.mappings),'recorded_opportunities':len(rows),
            'states':{state:sum(r.state==state for r in rows) for state in sorted({r.state for r in rows})},
            'native_diagnostic_controls':sum(r.native_receipt is not None for r in rows),'unified_unknown':len(rows),
            'independent_primary_findings':None,'empirical_effect_sizes':None,'budget':budget.snapshot(),'gates':gates()}
        recorder.append('comparator_summary',summary)
        return recorder.seal()
