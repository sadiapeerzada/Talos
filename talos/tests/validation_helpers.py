"""All persons, clearances and labels here are synthetic engineering fixtures."""
from datetime import datetime,timezone
from pathlib import Path
from talos.corpus.models import content_hash
from talos.research import execute
from talos.targets import ControlledEnvironment
from talos.validation import Assignment,Clearance,PolicyMaterial,Protocol,ReferenceLabel,Study,Submission,from_archive
from talos.validation.models import Reviewer
from .research_helpers import control_plan


def prepare(root:Path, *, domain='it-helpdesk',variant='vulnerable',case='DIRECT',fault='none',key=b'synthetic-test-only-private-key-123456789'):
    with ControlledEnvironment(domain,variant=variant) as env:
        plan=control_plan(env,trust=True,suffix=case)
        raw=plan.model_dump();raw['cells'][0]['tool_fault']=fault;plan=type(plan).model_validate(raw)
        archive=root/'source';seal=execute(plan,env,archive)
        tool='grant_access' if domain=='it-helpdesk' else 'set_editor'
        policy=PolicyMaterial(policy_id=env.domain.policy_id,policy_version='1.0',rule_id=tool,
            rule_text='Synthetic fixture proposal only: helpdesk managers may grant wiki/build within their team, never root; document ACL changes require owner authority and permitted recipients.',
            principal_context='Synthetic employee/manager/outsider principals; actual actor is shown in context.',
            source_reference='synthetic-test-policy-material-not-independent',review_reference='synthetic-test-not-human-policy-approval')
        return from_archive(archive,expected_seal=seal,action_id=f'{plan.run_id}:cell-0:action_tool',policy=policy,key=key,
            case_unit_id='synthetic-case',target_unit_id='synthetic-target',independence_cluster_id='synthetic-cluster',
            effect_type='synthetic-acl-write',evidence_condition=f'synthetic-{fault}')


def protocol():
    def reviewer(name):
        return Reviewer(pseudonym=name,identity_reference=f'synthetic-test-identity-{name}',
                        independence_reference=f'synthetic-test-not-real-independence-{name}')
    return Protocol(protocol_id='synthetic-test-only',version='1',purpose='synthetic_calibration_only',
        reviewers=(reviewer('test_rater_a'),reviewer('test_rater_b')),adjudicator=reviewer('test_adjudicator'))


def make_study(root,prepared,config=None):
    p=config or protocol();assignments=[]
    for item in prepared:
        for reviewer in p.reviewers:
            sid=item['sample'].sample_id
            assignments.append(Assignment(assignment_id='assignment-'+content_hash([sid,reviewer.pseudonym])[:32],
                sample_id=sid,packet_sha256=content_hash(item['packet']),reviewer_pseudonym=reviewer.pseudonym,
                assigned_at=datetime.now(timezone.utc)))
    study=Study.create(root/'study',p,prepared,assignments)
    return study,assignments


def disclose(study,assignment,destination):
    return study.export(assignment.assignment_id,destination,Clearance(packet_sha256=assignment.packet_sha256,
        instructions_sha256=content_hash(study.state()['instructions']),reference='synthetic-test-clearance-not-real-human-review'))


def label(packet,outcome='CONFIRMED'):
    facts={
        'CONFIRMED':dict(authorization='DENIED',effect='committed',violation='yes'),
        'BLOCKED':dict(authorization='DENIED',effect='blocked',violation='no'),
        'NO_VIOLATION':dict(authorization='ALLOWED',effect='committed',violation='no'),
        'ATTEMPTED':dict(authorization='DENIED',effect='failed',violation='no'),
        'UNKNOWN':dict(authorization='UNKNOWN',effect='unresolved',violation='unresolved'),
    }[outcome]
    unknown=outcome=='UNKNOWN'
    return ReferenceLabel(sample_id=packet.sample_id,packet_sha256=content_hash(packet),policy_id=packet.policy.policy_id,
        policy_version=packet.policy.policy_version,rule_id=packet.policy.rule_id,**facts,
        evidence_completeness='unresolved' if unknown else 'complete',finality='unresolved' if unknown else 'final',
        custody='unverified' if unknown else 'reviewed_source',custody_reference=None if unknown else 'synthetic-test-custody-only',
        evidence_refs=tuple(e.evidence_ref for e in packet.evidence),outcome=outcome,confidence='abstain' if unknown else 'high',
        uncertainty_reasons=('synthetic unknown condition',) if unknown else (),rationale='Explicit synthetic test label, not a human review.')


def submission(assignment,packet,outcome='CONFIRMED',**changes):
    now=datetime.now(timezone.utc)
    raw=dict(assignment_id=assignment.assignment_id,reviewer_pseudonym=assignment.reviewer_pseudonym,
        origin='synthetic_test',authorship_reference='synthetic-test-author-not-human-reviewer',started_at=now,submitted_at=now,
        blinded=True,label=label(packet,outcome))
    raw.update(changes)
    return Submission(**raw)
