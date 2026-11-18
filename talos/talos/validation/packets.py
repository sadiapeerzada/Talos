"""Explicit raw-evidence projection, separate private prediction and linkage."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from talos.corpus.models import Corpus, content_hash
from talos.research.contracts import Packet
from talos.research.recorder import read_payloads
from talos.research.replay import replay
from talos.validation.models import EvidenceItem, PolicyMaterial, Prediction, ReviewPacket, Sample

FORBIDDEN=frozenset(('prediction','oracle_prediction','verdict','expected_outcome','expectations','admissible_outcomes',
                     'attack_arm','arm','reviewer_label','reference_label','other_review','policy_assessment'))
IDENTITIES=frozenset(('target_id','scenario_id','run_id','repeat_id','action_id','authorization_context_id',
                      'action_digest','digest','source_id','context'))


def reject_label_metadata(value):
    """Key-level screening only. Free text requires human disclosure review."""
    if isinstance(value,dict):
        for key,child in value.items():
            if key.casefold() in FORBIDDEN: raise ValueError('forbidden prediction/arm/label metadata in reviewer view')
            reject_label_metadata(child)
    elif isinstance(value,(list,tuple)):
        for child in value: reject_label_metadata(child)


def from_archive(archive:Path, *, expected_seal:str, action_id:str, policy:PolicyMaterial, key:bytes,
                 case_unit_id:str, target_unit_id:str, independence_cluster_id:str, effect_type:str,
                 evidence_condition:str, supplements:tuple[dict,...]=()):
    """Select one explicitly named action; never automatically sample/cohort it.

    Original archive is verified/replayed but never changed. Returned objects
    must be separated by custody: packet for disclosure review; everything else private.
    """
    if not isinstance(key,bytes) or len(key)<32: raise ValueError('at least 32 bytes of private pseudonymization key required')
    replayed=replay(archive,expected_seal=expected_seal)
    records=[p for kind,p in read_payloads(archive,expected_seal=expected_seal) if kind=='action'
             and p['packet']['observation']['action']['action_id']==action_id]
    if len(records)!=1: raise ValueError('exactly one archived action required')
    packet=Packet.model_validate(records[0]['packet']); action=packet.observation.action
    policy=PolicyMaterial.model_validate(policy.model_dump())
    plan=replayed['plan']
    if (policy.policy_id,policy.policy_version,policy.rule_id)!=(plan.policy_id,plan.policy_version,action.tool_name):
        raise ValueError('policy material differs from exact action rule/version')
    mapping={}
    def alias(value):
        value=str(value)
        tag=hmac.new(key,value.encode(),hashlib.sha256).hexdigest()
        mapping[tag]=value
        return tag
    def project(value,field=None):
        if isinstance(value,dict): return {k:project(v,k) for k,v in value.items()}
        if isinstance(value,(list,tuple)): return [project(v,field) for v in value]
        if field in IDENTITIES and value is not None: return alias(value)
        return value
    sid='sample-'+alias(action.digest())[:32]
    # Explicit allowlist: no trace claims, computed policy, normalized verdict,
    # reader completion assessment, profile variant, corpus family or arm.
    evidence=[]
    def item(kind,content):
        projected=project(content)
        reject_label_metadata(projected)
        reference='evidence-'+alias(f'{action.digest()}:{kind}:{len(evidence)}')[:24]
        evidence.append(EvidenceItem(evidence_ref=reference,kind=kind,content=projected,
                                     content_sha256=content_hash(projected)))
    raw=packet.raw_store_records
    row=raw['action']
    # Redact original content digests: projected state has its own explicit hash.
    item('stored_action',{'action':json.loads(row['action_json']),
                          'status':row['status'],'effect':row['effect'],
                          'before_snapshot':row['before_id'],'after_snapshot':row['after_id']})
    for event in raw['audit_events']:
        item('audit',{'action':json.loads(event['action_json']),'status':event['status'],
                      'effect':event['effect'],'before_snapshot':event['before_id'],'after_snapshot':event['after_id']})
    for snap in raw['snapshots']:
        item('state_snapshot',{'snapshot_id':snap['id'],'parent_id':snap['parent_id'],
            'context':snap['context'],'state':json.loads(snap['state_json']),
            'action':json.loads(snap['action_json']) if snap['action_json'] else None})
    item('reset',packet.reset_receipt)
    for supplement in supplements:
        # Caller-provided explanatory/source material is not treated as trusted by construction.
        item('supplement',supplement)
    view=ReviewPacket(sample_id=sid,domain=plan.profile.domain,action_context=project(action.model_dump()),policy=policy,
        evidence=tuple(evidence),source_kind='researcher_controlled_synthetic',limitations=(
            'Scope/digests are pseudonymized; business facts are retained. These are transformed views, not original raw bytes.',
            'No oracle prediction, computed policy assessment, fixture expectation or arm is part of this view.',
            'PR-05 raw packets omit the complete database/finalization journal; establish finality/custody from reviewed source material or abstain.',
            'Source and policy review references are declarations, not authenticated approvals; free-text blinding needs curator clearance.'))
    reject_label_metadata(view.model_dump(mode='json'))
    selected_cell=next(c for c in plan.cells if c.cell_id==records[0]['cell_id'])
    original=next(r.case for r in Corpus.model_validate(
        read_payloads(archive,expected_seal=expected_seal)[0][1]['corpus']).records if r.identity==selected_cell.case_identity)
    sample=Sample(sample_id=sid,packet_sha256=content_hash(view),source_archive_seal=expected_seal,
        source_target_id=action.target_id,source_case_identity=selected_cell.case_identity,
        source_run_id=action.run_id,source_repeat_id=action.repeat_id,
        related_case_ids=tuple(sorted({original.case_id,*original.parent_case_ids,original.template_family_id,original.paraphrase_family_id,*original.scenario_ancestry})),
        source_action_digest=action.digest(),case_unit_id=case_unit_id,target_unit_id=target_unit_id,
        independence_cluster_id=independence_cluster_id,domain=plan.profile.domain,effect_type=effect_type,
        policy_boundary=f'{policy.policy_id}@{policy.policy_version}:{policy.rule_id}',evidence_condition=evidence_condition)
    prediction=Prediction(sample_id=sid,packet_sha256=content_hash(view),source_archive_seal=expected_seal,verdict=packet.verdict)
    return {'packet':view,'sample':sample,'prediction':prediction,'private_linkage':mapping}
