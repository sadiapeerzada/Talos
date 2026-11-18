"""Pure recorded-evidence replay; never reconnect to the original target."""
from pathlib import Path
from talos.corpus.models import Corpus, content_hash
from talos.corpus.planning import BindingSet
from talos.judging import Outcome, judge
from talos.research.contracts import CellResult, Packet, RunPlan
from talos.research.recorder import IntegrityError, read_payloads


class RecordedPolicy:
    def __init__(self,assessment): self.assessment=assessment
    def assess(self,action): return self.assessment


class RecordedReader:
    def __init__(self,evidence): self.evidence=evidence
    def read(self,action): return self.evidence


def replay_packet(packet: Packet):
    packet=Packet.model_validate(packet.model_dump())
    replayed=judge(packet.observation,policy=RecordedPolicy(packet.policy) if packet.policy_enabled and packet.policy else None,
                   evidence_reader=RecordedReader(packet.evidence),trusted_source_ids=frozenset(packet.trusted_source_ids))
    if replayed!=packet.verdict: raise IntegrityError('recorded verdict differs from offline oracle replay')
    return replayed


def replay(path:Path, *, expected_seal=None, allow_incomplete=False):
    events=read_payloads(path,expected_seal=expected_seal,allow_incomplete=allow_incomplete)
    if not events or events[0][0]!='manifest': raise IntegrityError('run manifest missing')
    plan=RunPlan.model_validate(events[0][1]['plan'])
    if events[0][1].get('configuration_sha256')!=plan.digest(): raise IntegrityError('configuration hash mismatch')
    corpus=Corpus.model_validate(events[0][1]['corpus'])
    bindings=BindingSet.model_validate(events[0][1]['bindings']);bindings.validate_against(corpus)
    if content_hash(corpus)!=plan.corpus_sha256: raise IntegrityError('archived corpus identity mismatch')
    by_binding={b.binding_id:b for b in bindings.bindings}
    from talos.research.runner import execution_order
    if events[0][1].get('execution_order')!=[c.cell_id for c in execution_order(plan)]:
        raise IntegrityError('execution order mismatch')
    if events[0][1].get('learning_sha256')!=content_hash(plan.learning):
        raise IntegrityError('learning snapshot hash mismatch')
    cells={c.cell_id:c for c in plan.cells}
    for cell in cells.values():
        if cell.binding_id not in by_binding or by_binding[cell.binding_id].case_identity!=cell.case_identity:
            raise IntegrityError('archived cell identity mismatch')
    results={}; intents=set(); actions={}; final=None
    for kind,payload in events[1:]:
        if final is not None: raise IntegrityError('events after terminal summary')
        if kind=='intent':
            ident=payload['cell_id']
            if ident not in cells or ident in intents or ident in results: raise IntegrityError('duplicate/unknown execution intent')
            intents.add(ident)
        elif kind=='result':
            result=CellResult.model_validate(payload)
            if result.cell_id not in cells or result.cell_id in results: raise IntegrityError('duplicate/unknown cell result')
            if result.packet:
                packet=result.packet
                validate_packet(packet,result.cell_id,plan,cells,by_binding,intents)
                if actions.get(packet.observation.action.action_id)!=packet:
                    raise IntegrityError('terminal packet differs from durable action journal')
            results[result.cell_id]=result
        elif kind=='action':
            ident=payload['cell_id'];packet=Packet.model_validate(payload['packet'])
            if ident in results: raise IntegrityError('action after cell finalization')
            validate_packet(packet,ident,plan,cells,by_binding,intents)
            aid=packet.observation.action.action_id
            if aid in actions or aid!=f'{plan.run_id}:{ident}:{payload["slot"]}':
                raise IntegrityError('duplicate/mismatched action identity')
            actions[aid]=packet
        elif kind=='summary': final=payload
        elif kind not in ('prepared','reset','budget','interruption'):
            raise IntegrityError('unknown event kind')
    missing=sorted(set(cells)-set(results))
    counts={o.value:sum(r.outcome==o for r in results.values()) for o in Outcome}
    states={state:sum(r.state==state for r in results.values()) for state in sorted({r.state for r in results.values()})}
    accounting={'planned_cells':len(cells),'recorded_cells':len(results),'missing_cell_ids':missing,
                'outcome_counts':counts,'cell_states':states,'execution_intents':len(intents),
                'action_outcome_counts':{o.value:sum(p.verdict.status==o for p in actions.values()) for o in Outcome},
                'recorded_actions':len(actions)}
    if final is not None and final.get('accounting')!=accounting: raise IntegrityError('summary denominator mismatch')
    if not allow_incomplete and (missing or final is None): raise IntegrityError('complete execution summary absent')
    return {'plan':plan,'results':results,'accounting':accounting,'summary':final}


def validate_packet(packet,ident,plan,cells,by_binding,intents):
    if ident not in cells or ident not in intents: raise IntegrityError('action without exact durable cell intent')
    cell=cells[ident];binding=by_binding[cell.binding_id];action=packet.observation.action
    if (action.target_id!=plan.profile.target_id or action.run_id!=plan.run_id
        or action.scenario_id!=cell.scenario_id or action.repeat_id!=cell.repeat_id
        or action.actor_id!=binding.proposed_actor_id):
        raise IntegrityError('cross-run/cell/actor packet contamination')
    slot=action.action_id.removeprefix(f'{plan.run_id}:{ident}:')
    if (slot not in binding.tool_bindings or action.tool_name!=binding.tool_bindings[slot]
        or action.arguments!=binding.proposed_tool_arguments[slot]):
        raise IntegrityError('action differs from frozen binding')
    if packet.trusted_source_ids != (() if plan.trust is None else plan.trust.trusted_source_ids):
        raise IntegrityError('packet trust differs from run declaration')
    if packet.policy_enabled != (plan.trust is not None): raise IntegrityError('policy gate mismatch')
    if packet.policy and (packet.policy.policy_id,packet.policy.policy_version)!=(plan.policy_id,plan.policy_version):
        raise IntegrityError('packet policy differs from manifest')
    receipt=packet.reset_receipt
    if any(receipt.get(k)!=getattr(action,k) for k in ('target_id','run_id','scenario_id','repeat_id','authorization_context_id')):
        raise IntegrityError('action/reset receipt mismatch')
    if not receipt.get('healthy') or type(receipt.get('generation')) is not int or receipt['generation']<1:
        raise IntegrityError('action followed unhealthy/unversioned reset')
    validate_raw_packet(packet)
    replay_packet(packet)


def validate_raw_packet(packet):
    import json
    from talos.judging import Action
    raw=packet.raw_store_records;action=packet.observation.action
    row=raw.get('action')
    if not row or row['digest']!=action.digest() or Action.model_validate_json(row['action_json'])!=action:
        raise IntegrityError('raw stored action mismatch')
    snapshots={s['id']:s for s in raw.get('snapshots',[])}
    for snap in snapshots.values():
        if content_hash(json.loads(snap['state_json']))!=snap['state_hash']:
            raise IntegrityError('raw snapshot content hash mismatch')
        if snap['context']!=action.authorization_context_id:
            raise IntegrityError('raw snapshot scope mismatch')
    if not {row['before_id'],row['after_id']}<=set(snapshots):
        raise IntegrityError('raw snapshots absent')
    before,after=snapshots[row['before_id']],snapshots[row['after_id']]
    if after['parent_id']!=before['id'] or Action.model_validate_json(after['action_json'])!=action:
        raise IntegrityError('raw snapshot lineage/action mismatch')
    if packet.reader_issues and packet.evidence.complete:
        raise IntegrityError('reader issues cannot attest complete evidence')
    for evidence in packet.evidence.records:
        if evidence.kind=='state_transition' and (evidence.state_before!=json.loads(before['state_json'])
                or evidence.state_after!=json.loads(after['state_json'])):
            raise IntegrityError('normalized/raw state evidence mismatch')
    for event in raw.get('audit_events',[]):
        if event['digest']!=action.digest() or Action.model_validate_json(event['action_json'])!=action:
            raise IntegrityError('raw audit scope mismatch')
