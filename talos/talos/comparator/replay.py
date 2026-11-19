"""Verify sealed native receipts without launching the external framework."""
from pathlib import Path
from talos.corpus.models import content_hash
from talos.comparator.contracts import Plan,NormalizedResult
from talos.comparator.isolation import bundle_identity,deterministic_projection
from talos.comparator.matching import validate_plan,gates
from talos.research.budget import Budget,BudgetStop
from talos.research.recorder import read_payloads,IntegrityError


def replay(path:Path, *, expected_seal:str):
    events=read_payloads(path,expected_seal=expected_seal)
    if not events or events[0][0]!='comparator_manifest' or events[-1][0]!='comparator_summary':
        raise IntegrityError('complete comparator manifest/summary required')
    manifest=events[0][1];plan=validate_plan(Plan.model_validate(manifest['plan']))
    if manifest['plan_sha256']!=plan.digest() or manifest['gates']!=gates(): raise IntegrityError('manifest mismatch')
    budget=Budget(plan.common_limits);pending_intent=None;cursor=0
    for kind,value in events[1:-1]:
        if kind=='native_control_intent':
            if pending_intent is not None or cursor>=len(plan.mappings): raise IntegrityError('unexpected native intent')
            pending_intent=value
            reservation={'attempts':1,'attacker_calls':plan.config.max_turns,'target_calls':plan.config.max_turns,
                'elapsed_ms':plan.initialization_reserve_ms+plan.attempt_timeout_ms}
            budget.reserve(reservation)
            if value!={'opportunity_id':plan.mappings[cursor].opportunity_id,'reservation':budget.snapshot()}:
                raise IntegrityError('intent reservation mismatch')
        elif kind=='comparator_cell':
            row=NormalizedResult.model_validate(value['result'])
            if row.state in ('ERROR','OFFLINE_NATIVE_CONTROL'):
                if pending_intent is None or not manifest['offline_native_controls']: raise IntegrityError('native result without intent')
                receipt=row.native_receipt
                actual={'attempts':1,'attacker_calls':receipt.counts['adversarial_stub'] if receipt else None,
                    'target_calls':receipt.counts['objective_stub'] if receipt else None,'elapsed_ms':value['worker_elapsed_ms']}
                try:budget.settle(actual)
                except BudgetStop:pass
                pending_intent=None
            elif pending_intent is not None: raise IntegrityError('native intent missing result')
            elif row.state=='BUDGET_STOP' and not budget.stop_reason:
                try:budget.reserve({'attempts':1,'attacker_calls':plan.config.max_turns,'target_calls':plan.config.max_turns,
                    'elapsed_ms':plan.initialization_reserve_ms+plan.attempt_timeout_ms})
                except BudgetStop:pass
                else:raise IntegrityError('unjustified budget stop')
            if value['budget']!=budget.snapshot(): raise IntegrityError('replayed budget differs')
            if value['provider_tokens'] is not None or value['provider_cost'] is not None: raise IntegrityError('fabricated provider usage')
            cursor+=1
        else:raise IntegrityError('unexpected comparator event')
    if pending_intent is not None:raise IntegrityError('incomplete native intent')
    cells=[v for k,v in events if k=='comparator_cell']
    if [v['result']['opportunity_id'] for v in cells]!=[m.opportunity_id for m in plan.mappings]:
        raise IntegrityError('opportunities omitted/reordered')
    for cell,mapping in zip(cells,plan.mappings):
        row=NormalizedResult.model_validate(cell['result']);receipt=row.native_receipt
        if receipt:
            if row.state!='OFFLINE_NATIVE_CONTROL' or mapping.surface.value!='user_message': raise IntegrityError('invalid native result surface/state')
            if receipt.config_sha256!=content_hash(plan.config) or receipt.objective_sha256!=content_hash(mapping.shared_objective) or receipt.source_files!=bundle_identity()['source_files']:
                raise IntegrityError('native receipt identity mismatch')
            if any(n>plan.config.max_turns for n in receipt.counts.values()): raise IntegrityError('native bound exceeded')
            if cell['semantic_projection']!=deterministic_projection(receipt): raise IntegrityError('normalized projection mismatch')
        elif row.state=='OFFLINE_NATIVE_CONTROL' or cell['semantic_projection'] is not None:
            raise IntegrityError('native result missing receipt')
    summary=events[-1][1]
    expected={'planned_opportunities':len(cells),'recorded_opportunities':len(cells),
        'states':{s:sum(v['result']['state']==s for v in cells) for s in sorted({v['result']['state'] for v in cells})},
        'native_diagnostic_controls':sum(v['result']['native_receipt'] is not None for v in cells),
        'unified_unknown':len(cells),'independent_primary_findings':None,'empirical_effect_sizes':None,
        'budget':cells[-1]['budget'] if cells else summary['budget'],'gates':gates()}
    if summary!=expected: raise IntegrityError('summary differs from normalized cells')
    return summary
