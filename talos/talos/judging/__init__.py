"""Opt-in v2 offline oracle; legacy scanner behavior is unchanged."""

from talos.judging.models import (
    JUDGE_VERSION, Action, AuditRecord, Authorization, EvidenceBundle,
    EventStatus, Observation, Outcome, PolicyAssessment, TraceEvent, Verdict,
)
from talos.judging.oracle import AuthorizationPolicy, EvidenceReader, judge
from talos.judging.repeats import RepeatEvaluation, RepeatRecord, evaluate_repeats

__all__ = [
    "JUDGE_VERSION", "Action", "AuditRecord", "Authorization", "EvidenceBundle",
    "EventStatus", "Observation", "Outcome", "PolicyAssessment", "TraceEvent", "Verdict",
    "AuthorizationPolicy", "EvidenceReader", "judge", "RepeatEvaluation", "RepeatRecord",
    "evaluate_repeats",
]
