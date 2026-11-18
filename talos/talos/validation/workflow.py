"""Offline append-only submissions; never synthesize human labels."""
from __future__ import annotations

from datetime import datetime,timezone
from pathlib import Path

from talos.corpus.models import content_hash
from talos.research.recorder import IntegrityError, Recorder, _create, read_payloads
from talos.validation.models import (
    Adjudication,Assignment,Clearance,Prediction,Protocol,ReviewPacket,Sample,Submission,
)
from talos.validation.packets import reject_label_metadata
from talos.validation.instructions import INSTRUCTIONS

CORE_FIELDS=('authorization','effect','violation','evidence_completeness','finality','custody','outcome')


def differences(left,right):
    return {field:[getattr(left,field),getattr(right,field)] for field in CORE_FIELDS
            if getattr(left,field)!=getattr(right,field)}


def _label_context(label,packet):
    if label.sample_id!=packet.sample_id or label.packet_sha256!=content_hash(packet):
        raise ValueError('label/review packet identity mismatch')
    if (label.policy_id,label.policy_version,label.rule_id)!=(packet.policy.policy_id,packet.policy.policy_version,packet.policy.rule_id):
        raise ValueError('label policy rule/version mismatch')
    if not set(label.evidence_refs)<={e.evidence_ref for e in packet.evidence}:
        raise ValueError('label cites evidence outside exact reviewer packet')


class Study:
    """Coordinator-private ledger. Never hand this directory to reviewers."""
    def __init__(self,path): self.path=Path(path)

    @classmethod
    def create(cls,path,protocol:Protocol,prepared:list[dict],assignments:list[Assignment]):
        protocol=Protocol.model_validate(protocol.model_dump())
        samples=[Sample.model_validate(p['sample'].model_dump()) for p in prepared]
        packets=[ReviewPacket.model_validate(p['packet'].model_dump()) for p in prepared]
        predictions=[Prediction.model_validate(p['prediction'].model_dump()) for p in prepared]
        manifest={'schema_version':'talos.validation-study.v1','protocol':protocol.model_dump(mode='json'),
            'samples':[s.model_dump(mode='json') for s in samples],
            'packets':[p.model_dump(mode='json') for p in packets],
            'predictions':[p.model_dump(mode='json') for p in predictions],
            'assignments':[a.model_dump(mode='json') for a in assignments],
            'private_linkages':[p.get('private_linkage',{}) for p in prepared]}
        validate_manifest(manifest)
        compact={k:v for k,v in manifest.items() if k not in ('packets','predictions','private_linkages')}
        compact['instructions_sha256']=content_hash(INSTRUCTIONS)
        compact['packet_sha256']=[content_hash(p) for p in manifest['packets']]
        compact['prediction_sha256']=[content_hash(p) for p in manifest['predictions']]
        linkages=[{'schema_version':'talos.validation-linkage.v1','sample_id':s.sample_id,'mapping':p.get('private_linkage',{})}
                  for s,p in zip(samples,prepared)]
        compact['linkage_sha256']=[content_hash(p) for p in linkages]
        with Recorder(Path(path),create=True) as recorder:
            recorder.append('validation_manifest',compact)
            recorder.append('annotation_instructions',INSTRUCTIONS)
            for packet in manifest['packets']: recorder.append('review_packet',packet)
            for prediction in manifest['predictions']: recorder.append('oracle_prediction',prediction)
            for linkage in linkages: recorder.append('private_linkage',linkage)
        return cls(path)

    def state(self):
        events=read_payloads(self.path,allow_incomplete=True)
        if not events or events[0][0]!='validation_manifest': raise IntegrityError('validation manifest missing')
        manifest=dict(events[0][1])
        instructions=[p for k,p in events[1:] if k=='annotation_instructions']
        if len(instructions)!=1 or content_hash(instructions[0])!=manifest.get('instructions_sha256'):
            raise IntegrityError('annotation guidance identity mismatch')
        manifest['packets']=[p for k,p in events[1:] if k=='review_packet']
        manifest['predictions']=[p for k,p in events[1:] if k=='oracle_prediction']
        linkages=[p for k,p in events[1:] if k=='private_linkage']
        if (manifest.get('packet_sha256')!=[content_hash(p) for p in manifest['packets']]
            or manifest.get('prediction_sha256')!=[content_hash(p) for p in manifest['predictions']]
            or manifest.get('linkage_sha256')!=[content_hash(p) for p in linkages]):
            raise IntegrityError('separate validation artifact identity mismatch')
        validate_manifest(manifest)
        state={'manifest':manifest,'instructions':instructions[0],'protocol':Protocol.model_validate(manifest['protocol']),
            'samples':{s['sample_id']:Sample.model_validate(s) for s in manifest['samples']},
            'packets':{p['sample_id']:ReviewPacket.model_validate(p) for p in manifest['packets']},
            'predictions':{p['sample_id']:Prediction.model_validate(p) for p in manifest['predictions']},
            'assignments':{a['assignment_id']:Assignment.model_validate(a) for a in manifest['assignments']},
            'submissions':{},'adjudications':{},'disclosures':{}}
        annotation_started=False
        for kind,payload in events[1:]:
            if kind in ('review_packet','oracle_prediction','private_linkage','annotation_instructions'):
                if annotation_started: raise IntegrityError('evidence/predictions appended after annotation began')
                continue
            annotation_started=True
            if kind=='submission':
                submission=Submission.model_validate(payload['submission'])
                if content_hash(submission)!=payload['sha256']: raise IntegrityError('submission hash mismatch')
                validate_submission(state,submission)
                state['submissions'][submission.assignment_id]=submission
            elif kind=='adjudication':
                adjudication=Adjudication.model_validate(payload['adjudication'])
                if content_hash(adjudication)!=payload['sha256']: raise IntegrityError('adjudication hash mismatch')
                validate_adjudication(state,adjudication)
                state['adjudications'][adjudication.sample_id]=adjudication
            elif kind=='disclosure':
                assignment=state['assignments'].get(payload['assignment_id'])
                clearance=Clearance.model_validate(payload['clearance'])
                if (not assignment or clearance.packet_sha256!=assignment.packet_sha256
                    or clearance.instructions_sha256!=content_hash(state['instructions'])): raise IntegrityError('disclosure identity mismatch')
                if assignment.assignment_id in state['disclosures']: raise IntegrityError('duplicate disclosure')
                state['disclosures'][assignment.assignment_id]=payload
            else: raise IntegrityError('unknown validation event')
        return state

    def export(self,assignment_id:str,destination:Path,clearance:Clearance):
        with Recorder(self.path) as recorder:
            state=self.state();assignment=state['assignments'][assignment_id]
            packet=state['packets'][assignment.sample_id]
            if not isinstance(clearance,Clearance): raise ValueError('exact-view curator clearance required')
            clearance=Clearance.model_validate(clearance.model_dump())
            if clearance.packet_sha256!=content_hash(packet) or clearance.instructions_sha256!=content_hash(state['instructions']): raise ValueError('clearance must bind exact reviewer view')
            if assignment_id in state['disclosures']: raise ValueError('assignment already exported')
            reject_label_metadata(packet.model_dump(mode='json'))
            destination=Path(destination)
            if destination.resolve().is_relative_to(self.path.resolve()):
                raise ValueError('review bundles must be outside the coordinator-private study directory')
            destination.mkdir(exist_ok=False)
            _create(destination/'assignment.json',assignment.model_dump(mode='json'))
            _create(destination/'packet.json',packet.model_dump(mode='json'))
            _create(destination/'instructions.json',state['instructions'])
            template={'schema_version':'talos.review-submission.v1','assignment_id':assignment.assignment_id,
                'reviewer_pseudonym':assignment.reviewer_pseudonym,'origin':None,'authorship_reference':None,
                'started_at':None,'submitted_at':None,'blinded':None,'leakage_note':None,
                'label':{'schema_version':'talos.reference-label.v1','sample_id':packet.sample_id,
                    'packet_sha256':content_hash(packet),'policy_id':packet.policy.policy_id,'policy_version':packet.policy.policy_version,
                    'rule_id':packet.policy.rule_id,'authorization':None,'effect':None,'violation':None,
                    'evidence_completeness':None,'finality':None,'custody':None,'custody_reference':None,'evidence_refs':[],
                    'outcome':None,'confidence':None,'uncertainty_reasons':[],'rationale':None}}
            _create(destination/'submission-template.json',template)
            recorder.append('disclosure',{'assignment_id':assignment_id,'clearance':clearance.model_dump(mode='json'),
                                          'exported_at':datetime.now(timezone.utc).isoformat()})
            return content_hash(packet)

    def import_submission(self,submission:Submission):
        submission=Submission.model_validate(submission.model_dump());state=self.state()
        validate_submission(state,submission)
        with Recorder(self.path) as recorder:
            validate_submission(self.state(),submission)
            recorder.append('submission',{'submission':submission.model_dump(mode='json'),'sha256':content_hash(submission),
                'received_at':datetime.now(timezone.utc).isoformat()})
        return content_hash(submission)

    def adjudication_packet(self,sample_id):
        state=self.state();reviews=reviews_for(state,sample_id)
        if len(reviews)!=2: raise ValueError('both independent submissions required before adjudication disclosure')
        return {'schema_version':'talos.adjudication-view.v1','packet':state['packets'][sample_id].model_dump(mode='json'),
                'reviews':[r.model_dump(mode='json') for r in reviews],
                'submission_sha256':[content_hash(r) for r in reviews],
                'disagreements':differences(reviews[0].label,reviews[1].label)}

    def import_adjudication(self,adjudication:Adjudication):
        adjudication=Adjudication.model_validate(adjudication.model_dump());state=self.state()
        validate_adjudication(state,adjudication)
        with Recorder(self.path) as recorder:
            validate_adjudication(self.state(),adjudication)
            recorder.append('adjudication',{'adjudication':adjudication.model_dump(mode='json'),'sha256':content_hash(adjudication)})
        return content_hash(adjudication)

    def seal(self):
        self.state()
        with Recorder(self.path) as recorder: return recorder.seal()


def validate_manifest(manifest):
    if manifest.get('schema_version')!='talos.validation-study.v1': raise ValueError('study version mismatch')
    protocol=Protocol.model_validate(manifest['protocol'])
    samples={s['sample_id']:Sample.model_validate(s) for s in manifest['samples']}
    packets={p['sample_id']:ReviewPacket.model_validate(p) for p in manifest['packets']}
    predictions={p['sample_id']:Prediction.model_validate(p) for p in manifest['predictions']}
    assignments=[Assignment.model_validate(a) for a in manifest['assignments']]
    if len(samples)!=len(manifest['samples']) or len(packets)!=len(manifest['packets']) or len(predictions)!=len(manifest['predictions']):
        raise ValueError('duplicate sample/packet/prediction')
    if set(samples)!=set(packets) or set(samples)!=set(predictions): raise ValueError('sample artifact coverage mismatch')
    if len({s.source_action_digest for s in samples.values()})!=len(samples):
        raise ValueError('duplicate underlying action')
    for sid,sample in samples.items():
        packet,prediction=packets[sid],predictions[sid]
        reject_label_metadata(packet.model_dump(mode='json'))
        if (sample.packet_sha256!=content_hash(packet) or prediction.packet_sha256!=sample.packet_sha256
            or prediction.source_archive_seal!=sample.source_archive_seal or prediction.verdict.action_digest!=sample.source_action_digest):
            raise ValueError('evidence/prediction identity mismatch')
    if len({a.assignment_id for a in assignments})!=len(assignments): raise ValueError('duplicate assignment')
    assigned=set()
    for a in assignments:
        if a.sample_id not in samples or a.packet_sha256!=samples[a.sample_id].packet_sha256: raise ValueError('assignment packet mismatch')
        if a.reviewer_pseudonym not in {r.pseudonym for r in protocol.reviewers}: raise ValueError('unassigned reviewer')
        pair=(a.sample_id,a.reviewer_pseudonym)
        if pair in assigned: raise ValueError('duplicate reviewer/sample assignment')
        assigned.add(pair)
    expected={(sid,r.pseudonym) for sid in samples for r in protocol.reviewers}
    if assigned!=expected: raise ValueError('two reviewer assignments per sample required')


def reviews_for(state,sample_id):
    return sorted([r for r in state['submissions'].values() if r.label.sample_id==sample_id],key=lambda r:r.reviewer_pseudonym)


def validate_submission(state,submission):
    assignment=state['assignments'].get(submission.assignment_id)
    if not assignment or assignment.reviewer_pseudonym!=submission.reviewer_pseudonym: raise ValueError('submission assignment/reviewer mismatch')
    if submission.assignment_id in state['submissions']: raise ValueError('submitted labels cannot be overwritten')
    if submission.assignment_id not in state['disclosures']: raise ValueError('review view was not cleared/exported')
    if submission.started_at<assignment.assigned_at: raise ValueError('review predates assignment')
    disclosed=datetime.fromisoformat(state['disclosures'][submission.assignment_id]['exported_at'])
    if submission.started_at<disclosed: raise ValueError('review predates cleared evidence disclosure')
    _label_context(submission.label,state['packets'][assignment.sample_id])


def validate_adjudication(state,adjudication):
    if adjudication.adjudicator_pseudonym!=state['protocol'].adjudicator.pseudonym: raise ValueError('adjudicator assignment mismatch')
    if adjudication.sample_id in state['adjudications']: raise ValueError('adjudication cannot be overwritten')
    reviews=reviews_for(state,adjudication.sample_id)
    if len(reviews)!=2: raise ValueError('two labels required for adjudication')
    if tuple(content_hash(r) for r in reviews)!=adjudication.submission_sha256: raise ValueError('adjudication references altered reviews')
    if adjudication.adjudicated_at<max(r.submitted_at for r in reviews): raise ValueError('adjudication predates independent submissions')
    _label_context(adjudication.label,state['packets'][adjudication.sample_id])
