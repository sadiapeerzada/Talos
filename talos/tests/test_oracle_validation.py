"""Synthetic engineering only; no independent reviewer or measured validation data."""
from copy import deepcopy
from datetime import datetime,timezone,timedelta
import json
from pathlib import Path
import subprocess
import sys

import pytest

from talos.corpus.models import content_hash
from talos.validation import Adjudication,Clearance,Protocol,ReferenceLabel,Study,validation_report
from talos.validation.models import Assignment,Submission
from talos.validation.packets import from_archive,reject_label_metadata
from talos.validation.workflow import differences
from talos.research.recorder import IntegrityError,canonical,read_payloads,verify
from .validation_helpers import prepare,make_study,disclose,label,submission,protocol


@pytest.fixture
def prepared(tmp_path): return prepare(tmp_path)


def test_blinded_allowlist_omits_private_predictions_arms_expectations_and_original_scope(prepared,tmp_path):
    study,assignments=make_study(tmp_path,[prepared])
    assert prepared['prediction'].verdict.status.value=='CONFIRMED' # fixture detector, not independent truth
    for index,a in enumerate(assignments): disclose(study,a,tmp_path/f'rater-{index}')
    first=json.loads((tmp_path/'rater-0/packet.json').read_text())
    second=json.loads((tmp_path/'rater-1/packet.json').read_text())
    assert first==second
    text=json.dumps(first)
    for private in ('"CONFIRMED"','TP1-DIRECT','synthetic-unit-test','vulnerable','family_id','trusted_source_ids','reader_issues'):
        assert private not in text
    assert 'verdict' not in first and 'policy_assessment' not in first
    template=json.loads((tmp_path/'rater-0/submission-template.json').read_text())
    assert template['label']['outcome'] is None and template['label']['authorization'] is None
    assert template['origin'] is None and template['reviewer_pseudonym']==assignments[0].reviewer_pseudonym
    assert not list((tmp_path/'rater-0').glob('*prediction*'))
    assert prepared['sample'].source_action_digest not in text


def test_identical_views_deterministic_given_same_key_and_source(prepared,tmp_path):
    public=prepared['packet'];sample=prepared['sample']
    root=tmp_path/'source'
    other=from_archive(root,expected_seal=sample.source_archive_seal,action_id='synthetic-unit-test:cell-0:action_tool',
        policy=public.policy,key=b'synthetic-test-only-private-key-123456789',case_unit_id=sample.case_unit_id,
        target_unit_id=sample.target_unit_id,independence_cluster_id=sample.independence_cluster_id,
        effect_type=sample.effect_type,evidence_condition=sample.evidence_condition)
    assert other['packet']==public and other['prediction']==prepared['prediction']
    verify(root,expected_seal=sample.source_archive_seal)


@pytest.mark.parametrize('bad',['key','seal','action','policy'])
def test_export_source_identity_failures(prepared,tmp_path,bad):
    packet=prepared['packet'];sample=prepared['sample'];policy=packet.policy
    if bad=='policy': policy=type(policy).model_validate({**policy.model_dump(),'policy_version':'incorrect'})
    with pytest.raises((ValueError,IntegrityError)):
        from_archive(tmp_path/'source',expected_seal='0'*64 if bad=='seal' else sample.source_archive_seal,
            action_id='wrong' if bad=='action' else 'synthetic-unit-test:cell-0:action_tool',policy=policy,
            key=b'short' if bad=='key' else b'synthetic-test-only-private-key-123456789',
            case_unit_id='case',target_unit_id='target',independence_cluster_id='cluster',effect_type='write',evidence_condition='toy')


@pytest.mark.parametrize('field',['oracle_prediction','verdict','expected_outcome','attack_arm','arm','reviewer_label','policy_assessment'])
def test_nested_label_metadata_is_rejected(field):
    with pytest.raises(ValueError): reject_label_metadata({'raw':{'list':[{'nested':{field:'secret'}}]}})


def test_uncleared_or_substituted_review_view_cannot_export(prepared,tmp_path):
    study,assignments=make_study(tmp_path,[prepared]);a=assignments[0]
    with pytest.raises(ValueError): study.export(a.assignment_id,tmp_path/'uncleared',None)
    with pytest.raises(ValueError): study.export(a.assignment_id,tmp_path/'wrong',Clearance(packet_sha256='0'*64,instructions_sha256='1'*64,reference='synthetic-only'))
    assert not (tmp_path/'wrong').exists()
    disclose(study,a,tmp_path/'correct')
    with pytest.raises(ValueError): disclose(study,a,tmp_path/'again')


@pytest.mark.parametrize('field,value',[
    ('schema_version','bad'),('packet_sha256','0'*64),('policy_version','other'),('evidence_refs',['not-in-view']),
    ('authorization','ALLOWED'),('effect','failed'),('violation','no'),('evidence_completeness','incomplete'),
    ('finality','pending'),('custody','unverified'),('custody_reference',None),('confidence','low'),
    ('outcome','NOT-A-CATEGORY'),('evidence_refs',[]),('rationale',''),
])
def test_invalid_reference_or_identity_cannot_import(prepared,tmp_path,field,value):
    study,assignments=make_study(tmp_path,[prepared]);a=assignments[0];disclose(study,a,tmp_path/'reviewer')
    raw=submission(a,prepared['packet']).model_dump();raw['label'][field]=value
    with pytest.raises(ValueError): study.import_submission(Submission.model_validate(raw))


def test_labels_are_separate_from_predictions_and_duplicate_overwrite_is_rejected(prepared,tmp_path):
    study,assignments=make_study(tmp_path,[prepared])
    a=assignments[0];disclose(study,a,tmp_path/'reviewer')
    human_fixture=submission(a,prepared['packet'],'UNKNOWN')
    study.import_submission(human_fixture)
    assert study.state()['predictions'][prepared['sample'].sample_id]==prepared['prediction']
    with pytest.raises(ValueError): study.import_submission(submission(a,prepared['packet'],'CONFIRMED'))
    with pytest.raises(ValueError): study.adjudication_packet(a.sample_id)


@pytest.mark.parametrize('which',['reviewer','assignment','early','naive_time','blinding_undisclosed'])
def test_submission_assignment_time_and_blinding_guards(prepared,tmp_path,which):
    study,assignments=make_study(tmp_path,[prepared]);a=assignments[0];disclose(study,a,tmp_path/'reviewer')
    raw=submission(a,prepared['packet']).model_dump()
    if which=='reviewer': raw['reviewer_pseudonym']='not-assigned'
    if which=='assignment': raw['assignment_id']='unassigned'
    if which=='early': raw['started_at']=a.assigned_at-timedelta(seconds=1)
    if which=='naive_time': raw['started_at']=datetime.now()
    if which=='blinding_undisclosed': raw['blinded']=False
    with pytest.raises(ValueError): study.import_submission(Submission.model_validate(raw))


def test_disagreement_requires_documented_separate_adjudication(prepared,tmp_path):
    study,assignments=make_study(tmp_path,[prepared]);reviews=[]
    for i,(a,outcome) in enumerate(zip(assignments,('CONFIRMED','UNKNOWN'))):
        disclose(study,a,tmp_path/f'rater-{i}')
        review=submission(a,prepared['packet'],outcome);study.import_submission(review);reviews.append(review)
    view=study.adjudication_packet(assignments[0].sample_id)
    assert 'outcome' in view['disagreements'] and 'prediction' not in view
    before=study.state()['predictions']
    adjudication=Adjudication(sample_id=assignments[0].sample_id,adjudicator_pseudonym='test_adjudicator',
        origin='synthetic_test',authorship_reference='synthetic-only-not-human',submission_sha256=tuple(view['submission_sha256']),
        adjudicated_at=datetime.now(timezone.utc),blinded=True,label=label(prepared['packet'],'UNKNOWN'),rationale='Synthetic adjudication tests unresolved finality, not human consensus.')
    study.import_adjudication(adjudication)
    assert study.state()['predictions']==before
    with pytest.raises(ValueError): study.import_adjudication(adjudication)
    seal=study.seal()
    report=validation_report(study,expected_seal=seal,calibration=True)
    assert report['status']=='SYNTHETIC_ENGINEERING_ONLY'
    assert report['accounting']['adjudicated_actions']==1
    assert report['metrics']['confusion_matrix']['UNKNOWN']['CONFIRMED']==1
    assert report['certification']=='NOT_INDEPENDENTLY_CERTIFIED'
    independent=validation_report(study,expected_seal=seal)
    assert independent['status']=='PENDING' and independent['metrics'] is None


@pytest.mark.parametrize('bad',['adjudicator','hashes','time','label_identity'])
def test_adjudication_cannot_change_authorship_review_lineage_or_context(prepared,tmp_path,bad):
    study,assignments=make_study(tmp_path,[prepared])
    for i,a in enumerate(assignments):
        disclose(study,a,tmp_path/f'rater-{i}');study.import_submission(submission(a,prepared['packet']))
    view=study.adjudication_packet(assignments[0].sample_id)
    raw=dict(sample_id=assignments[0].sample_id,adjudicator_pseudonym='test_adjudicator',origin='synthetic_test',
        authorship_reference='synthetic-test-only',submission_sha256=tuple(view['submission_sha256']),
        adjudicated_at=datetime.now(timezone.utc),blinded=True,label=label(prepared['packet']).model_dump(),rationale='Synthetic test only.')
    if bad=='adjudicator': raw['adjudicator_pseudonym']='test_rater_a'
    if bad=='hashes': raw['submission_sha256']=('0'*64,'1'*64)
    if bad=='time': raw['adjudicated_at']=assignments[0].assigned_at-timedelta(days=1)
    if bad=='label_identity': raw['label']['sample_id']='another-sample'
    with pytest.raises(ValueError): study.import_adjudication(Adjudication.model_validate(raw))


def test_missing_references_never_produce_measured_accuracy(prepared,tmp_path):
    study,assignments=make_study(tmp_path,[prepared]);seal=study.seal()
    report=validation_report(study,expected_seal=seal)
    assert report['status']=='PENDING' and report['metrics'] is None and report['agreement'] is None
    assert report['accounting']['planned_actions']==1
    assert report['accounting']['missing_initial_reviews']==2 and report['accounting']['missing_reference_actions']==1
    assert report['pending_gates']
    assert report['strata']['domain']['it-helpdesk']['metrics'] is None


def test_two_labels_with_fact_disagreement_do_not_auto_vote(prepared,tmp_path):
    study,assignments=make_study(tmp_path,[prepared])
    for i,a in enumerate(assignments):
        disclose(study,a,tmp_path/f'rater-{i}')
        review=submission(a,prepared['packet'],'UNKNOWN')
        if i:
            raw=review.model_dump();raw['label']['effect']='attempted';review=Submission.model_validate(raw)
        study.import_submission(review)
    seal=study.seal();report=validation_report(study,expected_seal=seal,calibration=True)
    assert report['metrics'] is None
    assert report['accounting']['unresolved_adjudications']==1
    assert report['accounting']['fact_or_category_disagreements']==1
    assert report['agreement']['raw_agreement']['value']==1 # class agreement is not fact resolution


def test_disclosed_blinding_loss_is_retained_but_excluded(prepared,tmp_path):
    study,assignments=make_study(tmp_path,[prepared])
    for i,a in enumerate(assignments):
        disclose(study,a,tmp_path/f'rater-{i}')
        study.import_submission(submission(a,prepared['packet'],blinded=not bool(i),leakage_note='Synthetic disclosure of accidental exposure' if i else None))
    seal=study.seal();report=validation_report(study,expected_seal=seal,calibration=True)
    assert report['metrics'] is None and report['accounting']['blinding_compromised_actions']==1


@pytest.mark.parametrize('damage',['duplicate_case','prediction','assignment','panel'])
def test_study_manifest_substitution_and_duplicate_guards(prepared,tmp_path,damage):
    if damage=='duplicate_case':
        with pytest.raises(ValueError): make_study(tmp_path,[prepared,prepared])
    elif damage=='prediction':
        prepared['prediction']=type(prepared['prediction']).model_validate({**prepared['prediction'].model_dump(),'packet_sha256':'0'*64})
        with pytest.raises(ValueError): make_study(tmp_path,[prepared])
    elif damage=='panel':
        raw=protocol().model_dump();raw['adjudicator']=raw['reviewers'][0]
        with pytest.raises(ValueError): Protocol.model_validate(raw)
    else:
        p=protocol();a=Assignment(assignment_id='assignment-'+'0'*32,sample_id=prepared['sample'].sample_id,
            packet_sha256=prepared['sample'].packet_sha256,reviewer_pseudonym='test_rater_a',assigned_at=datetime.now(timezone.utc))
        with pytest.raises(ValueError): Study.create(tmp_path/'study',p,[prepared],[a])


def test_altered_submission_object_is_caught_by_seal(prepared,tmp_path):
    study,assignments=make_study(tmp_path,[prepared]);a=assignments[0];disclose(study,a,tmp_path/'rater')
    study.import_submission(submission(a,prepared['packet']));seal=study.seal()
    # Locate immutable captured submission, never rewrite it through a supported API.
    for event in verify(study.path):
        if event['kind']=='submission':
            path=study.path/'objects'/f"{event['payload_sha256']}.json"
            raw=json.loads(path.read_text());raw['submission']['label']['rationale']='altered';path.write_bytes(canonical(raw));break
    with pytest.raises(IntegrityError): validation_report(study,expected_seal=seal,calibration=True)


def test_offline_cli_exposes_schema_and_pending_report_only(prepared,tmp_path):
    study,_=make_study(tmp_path,[prepared]);seal=study.seal()
    for args in (['schema'],['report',str(study.path),'--expected-seal',seal]):
        child=subprocess.run([sys.executable,'-m','talos.validation',*args],capture_output=True,text=True)
        assert child.returncode==0,child.stderr
        result=json.loads(child.stdout)
        if args[0]=='report': assert result['metrics'] is None and result['status']=='PENDING'
        else: assert 'properties' in result and 'authorization' in result['properties']


def test_second_reviewer_export_after_first_submission_never_contains_first_label(prepared,tmp_path):
    study,assignments=make_study(tmp_path,[prepared]);a,b=assignments
    disclose(study,a,tmp_path/'first')
    study.import_submission(submission(a,prepared['packet'],'UNKNOWN'))
    disclose(study,b,tmp_path/'second')
    for path in (tmp_path/'second').glob('*.json'):
        data=json.loads(path.read_text())
        assert 'submissions' not in data and 'reviews' not in data and 'predictions' not in data
        assert a.reviewer_pseudonym not in path.read_text()
    assert json.loads((tmp_path/'second/submission-template.json').read_text())['label']['outcome'] is None


def test_export_inside_private_coordinator_archive_is_rejected(prepared,tmp_path):
    study,assignments=make_study(tmp_path,[prepared]);a=assignments[0]
    with pytest.raises(ValueError):
        disclose(study,a,study.path/'unsafe-review-bundle')


def test_synthetic_labels_cannot_become_independent_metrics_by_filling_protocol_references(prepared,tmp_path):
    raw=protocol().model_dump();raw['purpose']='independent_human_review'
    for gate in protocol().pending_gates(): raw[gate]='synthetic-test-only-not-real-approval'
    study,assignments=make_study(tmp_path,[prepared],Protocol.model_validate(raw))
    for i,a in enumerate(assignments):
        disclose(study,a,tmp_path/f'rater-{i}')
        study.import_submission(submission(a,prepared['packet']))
    seal=study.seal();report=validation_report(study,expected_seal=seal)
    assert not report['pending_gates'] # declared references are not proof of independent labels
    assert report['status']=='PENDING' and report['metrics'] is None
    assert report['accounting']['synthetic_reference_actions_excluded']==1


def test_calibration_strata_units_and_unlabeled_cells_preserve_denominators(tmp_path):
    first_root=tmp_path/'one';first_root.mkdir();second_root=tmp_path/'two';second_root.mkdir()
    first=prepare(first_root);second=prepare(second_root,domain='document-management',variant='hardened')
    study,assignments=make_study(tmp_path,[first,second])
    packet=first['packet']
    for i,a in enumerate(assignments[:2]):
        disclose(study,a,tmp_path/f'rater-{i}');study.import_submission(submission(a,packet))
    seal=study.seal();report=validation_report(study,expected_seal=seal,calibration=True)
    assert report['unit_counts']=={'action':2,'case':1,'target':1,'declared_cluster':1,'source_cases':1,'source_target_instances':2}
    assert report['accounting']['paired_reference_actions']==1 and report['accounting']['missing_reference_actions']==1
    assert report['accounting']['missing_initial_reviews']==2
    assert report['metrics']['five_way_accuracy']['denominator']==1
    assert report['strata']['domain']['it-helpdesk']['paired_actions']==1
    assert report['strata']['domain']['document-management']['paired_actions']==0
    assert report['strata']['domain']['document-management']['metrics'] is None
    for axis in ('effect_type','policy_boundary','evidence_condition'): assert report['strata'][axis]


def test_invalid_cluster_splitting_suppresses_inferential_intervals(tmp_path):
    from talos.validation.metrics import Bootstrap
    one=tmp_path/'one';one.mkdir();two=tmp_path/'two';two.mkdir()
    first,second=prepare(one),prepare(two)
    second['sample']=type(second['sample']).model_validate({**second['sample'].model_dump(),'independence_cluster_id':'another-cluster'})
    study,assignments=make_study(tmp_path,[first,second]);packets={p['packet'].sample_id:p['packet'] for p in (first,second)}
    for i,a in enumerate(assignments):
        disclose(study,a,tmp_path/f'rater-{i}');study.import_submission(submission(a,packets[a.sample_id]))
    seal=study.seal();report=validation_report(study,expected_seal=seal,calibration=True,
        bootstrap=Bootstrap(seed=1,resamples=100,confidence=.95))
    assert report['cluster_conflicts']
    assert report['metrics']['five_way_accuracy']['interval'] is None


def test_unsealed_study_and_wrong_expected_seal_cannot_report_accuracy(prepared,tmp_path):
    study,_=make_study(tmp_path,[prepared])
    with pytest.raises(IntegrityError): validation_report(study,expected_seal='0'*64,calibration=True)
    study.seal()
    with pytest.raises(IntegrityError): validation_report(study,expected_seal='0'*64,calibration=True)


def test_reference_schema_keeps_facts_separate_from_predictions():
    schema=json.loads((Path(__file__).parents[2]/'docs/experimental/pr06_reference_label.schema.json').read_text())
    assert 'outcome' in schema['properties'] and 'authorization' in schema['properties']
    assert 'prediction' not in schema['properties'] and schema['additionalProperties'] is False


def test_instruction_clearance_and_separate_artifacts_are_frozen_before_annotation(prepared,tmp_path,monkeypatch):
    from talos.validation.instructions import INSTRUCTIONS
    study,assignments=make_study(tmp_path,[prepared]);a=assignments[0]
    state=study.state();original=deepcopy(state['instructions'])
    wrong=Clearance(packet_sha256=a.packet_sha256,instructions_sha256='0'*64,reference='synthetic-test-only')
    with pytest.raises(ValueError): study.export(a.assignment_id,tmp_path/'wrong-guidance',wrong)
    assert not (tmp_path/'wrong-guidance').exists()
    monkeypatch.setitem(INSTRUCTIONS,'text','A later unapproved instruction must not replace frozen guidance.')
    disclose(study,a,tmp_path/'reviewer')
    assert json.loads((tmp_path/'reviewer/instructions.json').read_text())==original
    events=read_payloads(study.path,allow_incomplete=True)
    predictions=[v for k,v in events if k=='oracle_prediction']
    packets=[v for k,v in events if k=='review_packet']
    assert len(predictions)==1 and predictions[0]['schema_version']=='talos.validation-prediction.v1'
    assert packets[0]['schema_version']=='talos.review-packet.v1' and 'verdict' not in packets[0]


def test_known_case_ancestry_cannot_be_split_by_relabeling_declared_units(tmp_path):
    from talos.validation.metrics import Bootstrap
    one=tmp_path/'one';one.mkdir();two=tmp_path/'two';two.mkdir()
    first,second=prepare(one),prepare(two)
    second['sample']=type(second['sample']).model_validate({**second['sample'].model_dump(),
        'case_unit_id':'new-name','target_unit_id':'another-name','independence_cluster_id':'another-cluster'})
    study,assignments=make_study(tmp_path,[first,second]);packets={p['packet'].sample_id:p['packet'] for p in (first,second)}
    for i,a in enumerate(assignments):
        disclose(study,a,tmp_path/f'rater-{i}');study.import_submission(submission(a,packets[a.sample_id]))
    seal=study.seal();report=validation_report(study,expected_seal=seal,calibration=True,
        bootstrap=Bootstrap(seed=1,resamples=100,confidence=.95))
    axes={x['unit'] for x in report['cluster_conflicts']}
    assert 'source_case' in axes and 'related_case' in axes
    assert report['metrics']['five_way_accuracy']['interval'] is None


def test_adjudicator_exposure_is_recorded_and_cannot_certify_reference(prepared,tmp_path):
    study,assignments=make_study(tmp_path,[prepared])
    for i,a in enumerate(assignments):
        disclose(study,a,tmp_path/f'rater-{i}');study.import_submission(submission(a,prepared['packet']))
    view=study.adjudication_packet(assignments[0].sample_id)
    review=Adjudication(sample_id=assignments[0].sample_id,adjudicator_pseudonym='test_adjudicator',
        origin='synthetic_test',authorship_reference='synthetic-test-only',submission_sha256=tuple(view['submission_sha256']),
        adjudicated_at=datetime.now(timezone.utc),blinded=False,leakage_note='Synthetic test of accidental oracle exposure',
        label=label(prepared['packet']),rationale='Synthetic test only.')
    study.import_adjudication(review);seal=study.seal()
    report=validation_report(study,expected_seal=seal,calibration=True)
    assert report['metrics'] is None and report['accounting']['blinding_compromised_actions']==1
