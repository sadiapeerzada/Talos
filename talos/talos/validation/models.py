"""Independent reference declarations, separate from oracle predictions."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import Field, StrictBool, field_validator, model_validator
from talos.corpus.models import Model, content_hash
from talos.judging import Authorization, Outcome, Verdict
from talos.profiles.models import finite_json

HASH = r'^[0-9a-f]{64}$'


class Timed(Model):
    @field_validator('*')
    @classmethod
    def timezone_required(cls,value):
        if isinstance(value,datetime) and value.utcoffset() is None:
            raise ValueError('review timestamps require an explicit timezone')
        return value


class EffectFact(str,Enum):
    COMMITTED='committed'
    BLOCKED='blocked'
    FAILED='failed'
    ROLLED_BACK='rolled_back'
    NO_EFFECT='no_effect'
    ATTEMPTED='attempted'
    UNRESOLVED='unresolved'


class PolicyMaterial(Model):
    policy_id: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    rule_text: str = Field(min_length=1)
    principal_context: str = Field(min_length=1)
    source_reference: str = Field(min_length=1)
    review_reference: str = Field(min_length=1)


class EvidenceItem(Model):
    evidence_ref: str = Field(min_length=1)
    kind: Literal['stored_action','audit','state_snapshot','reset','supplement']
    content: dict
    content_sha256: str = Field(pattern=HASH)
    transformed: Literal[True] = True

    @field_validator('content')
    @classmethod
    def json_content(cls,value): return finite_json(value)

    @model_validator(mode='after')
    def identity(self):
        if content_hash(self.content)!=self.content_sha256: raise ValueError('review evidence hash mismatch')
        return self


class ReviewPacket(Model):
    schema_version: Literal['talos.review-packet.v1'] = 'talos.review-packet.v1'
    sample_id: str = Field(pattern=r'^sample-[0-9a-f]{32}$')
    domain: str
    action_context: dict
    policy: PolicyMaterial
    evidence: tuple[EvidenceItem,...] = Field(min_length=1)
    limitations: tuple[str,...] = Field(min_length=1)
    source_kind: Literal['researcher_controlled_synthetic','independently_supplied']
    transformation: Literal['scope_pseudonymization_not_original_bytes'] = 'scope_pseudonymization_not_original_bytes'

    @field_validator('action_context')
    @classmethod
    def json_action(cls,value): return finite_json(value)

    @model_validator(mode='after')
    def evidence_unique(self):
        refs=[e.evidence_ref for e in self.evidence]
        if len(set(refs))!=len(refs): raise ValueError('duplicate reviewer evidence reference')
        return self


class Sample(Model):
    sample_id: str
    packet_sha256: str = Field(pattern=HASH)
    source_archive_seal: str = Field(pattern=HASH)
    source_action_digest: str = Field(pattern=HASH)
    source_target_id: str = Field(min_length=1)
    source_case_identity: str = Field(min_length=1)
    source_run_id: str = Field(min_length=1)
    source_repeat_id: str = Field(min_length=1)
    related_case_ids: tuple[str,...] = Field(min_length=1)
    case_unit_id: str = Field(min_length=1)
    target_unit_id: str = Field(min_length=1)
    independence_cluster_id: str = Field(min_length=1)
    domain: str = Field(min_length=1)
    effect_type: str = Field(min_length=1)
    policy_boundary: str = Field(min_length=1)
    evidence_condition: str = Field(min_length=1)


class Prediction(Model):
    schema_version: Literal['talos.validation-prediction.v1'] = 'talos.validation-prediction.v1'
    sample_id: str
    packet_sha256: str = Field(pattern=HASH)
    source_archive_seal: str = Field(pattern=HASH)
    verdict: Verdict


class ReferenceLabel(Model):
    schema_version: Literal['talos.reference-label.v1'] = 'talos.reference-label.v1'
    sample_id: str
    packet_sha256: str = Field(pattern=HASH)
    policy_id: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    authorization: Authorization
    effect: EffectFact
    violation: Literal['yes','no','unresolved']
    evidence_completeness: Literal['complete','incomplete','unresolved']
    finality: Literal['final','pending','unresolved']
    custody: Literal['reviewed_source','unverified']
    custody_reference: str | None = None
    evidence_refs: tuple[str,...] = Field(min_length=1)
    outcome: Outcome
    confidence: Literal['high','medium','low','abstain']
    uncertainty_reasons: tuple[str,...] = ()
    rationale: str = Field(min_length=1)

    @model_validator(mode='after')
    def logical_facts(self):
        if len(set(self.evidence_refs))!=len(self.evidence_refs): raise ValueError('duplicate evidence references')
        if self.custody=='reviewed_source' and not self.custody_reference: raise ValueError('custody reference required')
        if (self.outcome==Outcome.UNKNOWN or self.confidence in ('low','abstain')) and not self.uncertainty_reasons:
            raise ValueError('uncertainty/abstention requires reasons')
        if self.outcome==Outcome.CONFIRMED and not (
            self.authorization==Authorization.DENIED and self.effect==EffectFact.COMMITTED and self.violation=='yes'):
            raise ValueError('confirmed reference conflicts with stated facts')
        if self.outcome==Outcome.BLOCKED and not (
            self.authorization==Authorization.DENIED and self.effect==EffectFact.BLOCKED and self.violation=='no'):
            raise ValueError('blocked reference conflicts with stated facts')
        if self.outcome==Outcome.NO_VIOLATION and not (self.authorization==Authorization.ALLOWED and self.violation=='no' and self.effect not in (EffectFact.ATTEMPTED,EffectFact.UNRESOLVED)):
            raise ValueError('allowed reference conflicts with stated facts')
        if self.outcome==Outcome.ATTEMPTED and not (self.authorization==Authorization.DENIED and
            self.effect in (EffectFact.ATTEMPTED,EffectFact.FAILED,EffectFact.ROLLED_BACK,EffectFact.NO_EFFECT)):
            raise ValueError('attempt reference conflicts with stated facts')
        if self.outcome in (Outcome.CONFIRMED,Outcome.BLOCKED,Outcome.NO_VIOLATION) and not (
            self.evidence_completeness=='complete' and self.finality=='final' and self.custody=='reviewed_source'):
            raise ValueError('terminal reference requires reviewed complete final evidence')
        if self.violation=='yes' and not (self.authorization==Authorization.DENIED and self.effect==EffectFact.COMMITTED):
            raise ValueError('violation requires denied committed effect')
        return self


class Reviewer(Model):
    pseudonym: str = Field(pattern=r'^[A-Za-z0-9_-]+$')
    identity_reference: str = Field(min_length=1)
    independence_reference: str = Field(min_length=1)


class Protocol(Model):
    schema_version: Literal['talos.validation-protocol.v1'] = 'talos.validation-protocol.v1'
    protocol_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    purpose: Literal['synthetic_calibration_only','independent_human_review']
    sampling_reference: str | None = None
    custody_reference: str | None = None
    reviewed_policy_reference: str | None = None
    independence_reference: str | None = None
    clustering_reference: str | None = None
    adjudication_reference: str | None = None
    thresholds_reference: str | None = None
    retention_reference: str | None = None
    reviewers: tuple[Reviewer,Reviewer]
    adjudicator: Reviewer

    @model_validator(mode='after')
    def panel_distinct(self):
        panel=(*self.reviewers,self.adjudicator)
        if len({r.pseudonym for r in panel})!=3 or len({r.identity_reference for r in panel})!=3:
            raise ValueError('two distinct raters and separate adjudicator required')
        return self

    def pending_gates(self):
        names=('sampling_reference','custody_reference','reviewed_policy_reference','independence_reference',
               'clustering_reference','adjudication_reference','thresholds_reference','retention_reference')
        return [name for name in names if not getattr(self,name)]


class Assignment(Timed):
    schema_version: Literal['talos.review-assignment.v1'] = 'talos.review-assignment.v1'
    assignment_id: str = Field(pattern=r'^assignment-[0-9a-f]{32}$')
    sample_id: str
    packet_sha256: str = Field(pattern=HASH)
    reviewer_pseudonym: str
    assigned_at: datetime


class Submission(Timed):
    schema_version: Literal['talos.review-submission.v1'] = 'talos.review-submission.v1'
    assignment_id: str
    reviewer_pseudonym: str
    origin: Literal['human_supplied','synthetic_test']
    authorship_reference: str = Field(min_length=1)
    started_at: datetime
    submitted_at: datetime
    blinded: StrictBool
    leakage_note: str | None = None
    label: ReferenceLabel

    @model_validator(mode='after')
    def chronology(self):
        if self.submitted_at<self.started_at: raise ValueError('submission predates review start')
        if not self.blinded and not self.leakage_note: raise ValueError('blinding loss requires disclosure')
        return self


class Adjudication(Timed):
    schema_version: Literal['talos.adjudication.v1'] = 'talos.adjudication.v1'
    sample_id: str
    adjudicator_pseudonym: str
    origin: Literal['human_supplied','synthetic_test']
    authorship_reference: str = Field(min_length=1)
    submission_sha256: tuple[str,str]
    adjudicated_at: datetime
    blinded: StrictBool
    leakage_note: str | None = None
    label: ReferenceLabel
    rationale: str = Field(min_length=1)

    @model_validator(mode='after')
    def disclosure(self):
        if not self.blinded and not self.leakage_note: raise ValueError('adjudicator blinding loss requires disclosure')
        return self


class Clearance(Model):
    schema_version: Literal['talos.review-clearance.v1'] = 'talos.review-clearance.v1'
    packet_sha256: str = Field(pattern=HASH)
    instructions_sha256: str = Field(pattern=HASH)
    reference: str = Field(min_length=1)
    scope: Literal['curator_declared_view_review_not_authenticated'] = 'curator_declared_view_review_not_authenticated'
