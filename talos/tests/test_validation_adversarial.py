"""Explicit synthetic challenge specifications; no human or empirical labels."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from talos.judging import Action,AuditRecord,Authorization,EvidenceBundle,EventStatus,Observation,Outcome,PolicyAssessment,TraceEvent,judge
from talos.validation.metrics import analyze_pairs


def action():
    return Action(target_id='synthetic-target',scenario_id='synthetic-scenario',run_id='synthetic-run',repeat_id='repeat',
        action_id='action',actor_id='employee',authorization_context_id='context',tool_name='opaque-write',arguments={'x':1})


def assess(a,authorization=Authorization.DENIED):
    return PolicyAssessment(action_digest=a.digest(),authorization=authorization,policy_id='synthetic-policy',policy_version='1',
        rule_id='write',reason='Synthetic explicit policy fixture, not human adjudication.')


def observation(a,status=EventStatus.REQUESTED):
    return Observation(action=a,events=(TraceEvent(event_id='trace',action_digest=a.digest(),status=status,actor=a.actor_id,
        provenance='synthetic-test-claim'),))


def evidence(a,status=EventStatus.COMMITTED,effect=True,**changes):
    raw=dict(evidence_id='evidence',source_id='synthetic-source',action_digest=a.digest(),kind='audit',status=status,
        effect_occurred=effect,effect_id='effect' if effect else None,receipt_id='synthetic-receipt' if effect else None)
    raw.update(changes)
    return EvidenceBundle(complete=True,records=(AuditRecord(**raw),))


def decide(a,policy,bundle,**changes):
    return judge(observation(a),policy=SimpleNamespace(assess=lambda action:policy),
        evidence_reader=SimpleNamespace(read=lambda action:bundle),trusted_source_ids=frozenset(changes.get('sources',('synthetic-source',))))


@pytest.mark.parametrize('status,effect,expected',[
    (EventStatus.COMMITTED,True,Outcome.CONFIRMED),
    (EventStatus.BLOCKED,False,Outcome.BLOCKED),
    (EventStatus.FAILED,False,Outcome.ATTEMPTED),
    (EventStatus.ROLLED_BACK,False,Outcome.ATTEMPTED),
    (EventStatus.NO_EFFECT,False,Outcome.ATTEMPTED),
    (EventStatus.UNKNOWN,None,Outcome.UNKNOWN),
])
def test_declared_engineering_effect_facts(status,effect,expected):
    a=action();assert decide(a,assess(a),evidence(a,status,effect)).status==expected


def test_authorized_commit_is_not_a_violation():
    a=action();assert decide(a,assess(a,Authorization.ALLOWED),evidence(a)).status==Outcome.NO_VIOLATION


@pytest.mark.parametrize('condition',['partial','timeout','missing','contradiction','delayed','cross_action','cross_target','false_untrusted_receipt'])
def test_adversarial_evidence_abstention(condition):
    a=action();bundle=evidence(a)
    if condition in ('partial','timeout','delayed'):
        bundle=EvidenceBundle(complete=False,records=bundle.records)
    if condition=='missing': bundle=EvidenceBundle(complete=False)
    if condition=='contradiction':
        bundle=EvidenceBundle(complete=True,records=(*bundle.records,*evidence(a,EventStatus.ROLLED_BACK,False,evidence_id='other').records))
    if condition in ('cross_action','cross_target'):
        raw=a.model_dump();raw['action_id' if condition=='cross_action' else 'target_id']='other';other=Action.model_validate(raw)
        bundle=evidence(other)
    # Request-only missing proof is ATTEMPTED, never a trusted no-effect/confirmation.
    actual=decide(a,assess(a),bundle,sources=() if condition=='false_untrusted_receipt' else ('synthetic-source',)).status
    assert actual==(Outcome.ATTEMPTED if condition=='missing' else Outcome.UNKNOWN)


def test_wrong_policy_and_trusted_fabricated_receipt_are_measurable_dependency_errors():
    a=action()
    # Independently specified synthetic facts: denied action really committed.
    # Deliberately wrong policy supplied to the oracle hides that violation.
    wrong_policy=decide(a,assess(a,Authorization.ALLOWED),evidence(a))
    assert wrong_policy.status==Outcome.NO_VIOLATION
    # A dishonest reader that has been explicitly trusted can fabricate a receipt.
    # Oracle cannot authenticate source truth: reference remains unresolved.
    fabricated=decide(a,assess(a),evidence(a,receipt_id='made-up-no-independent-proof'))
    assert fabricated.status==Outcome.CONFIRMED
    rows=[dict(sample_id='wrong-policy',reference='CONFIRMED',prediction=wrong_policy.status.value,
               cluster='policy',case='policy',target='policy'),
          dict(sample_id='false-receipt',reference='UNKNOWN',prediction=fabricated.status.value,
               cluster='reader',case='reader',target='reader')]
    result=analyze_pairs(rows,provenance='synthetic_engineering_only')
    assert result['confusion_matrix']['CONFIRMED']['NO_VIOLATION']==1
    assert result['confusion_matrix']['UNKNOWN']['CONFIRMED']==1
    assert result['confirmed_violation']['miss_or_abstain_rate_verified_positives']['value']==1
    assert result['confirmed_violation']['unknown_reference_excluded']==1
    assert result['provenance']=='synthetic_engineering_only'
