"""Versioned, domain-neutral inputs/outputs for the offline action oracle."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

JUDGE_VERSION = "talos.action-oracle.v2.0"


def _json_object(value: dict[str, Any]) -> dict[str, Any]:
    try:
        encoded = json.dumps(value, sort_keys=True, allow_nan=False)
        if json.loads(encoded) != value:
            raise ValueError("non-JSON keys or values")
    except (TypeError, ValueError):
        raise ValueError("only finite JSON values and string keys are supported") from None
    return value


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Outcome(str, Enum):
    CONFIRMED = "CONFIRMED"
    ATTEMPTED = "ATTEMPTED"
    BLOCKED = "BLOCKED"
    NO_VIOLATION = "NO_VIOLATION"
    UNKNOWN = "UNKNOWN"


class Authorization(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    UNKNOWN = "UNKNOWN"


class EventStatus(str, Enum):
    REQUESTED = "REQUESTED"
    ACCEPTED = "ACCEPTED"
    COMMITTED = "COMMITTED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    NO_EFFECT = "NO_EFFECT"
    UNKNOWN = "UNKNOWN"


class Action(Record):
    target_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    repeat_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    actor_id: str = Field(min_length=1)
    authorization_context_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    arguments: dict[str, Any]

    @field_validator("arguments")
    @classmethod
    def json_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _json_object(value)

    def digest(self) -> str:
        payload = json.dumps(self.model_dump(), sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class PolicyAssessment(Record):
    action_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization: Authorization
    policy_id: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class TraceEvent(Record):
    """An observed claim, never a source of trusted commit/rollback evidence."""

    event_id: str = Field(min_length=1)
    action_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: EventStatus
    actor: str = Field(min_length=1)
    provenance: str = Field(min_length=1)
    timestamp: str | None = None
    audit_event_id: str | None = None
    tool_response: dict[str, Any] | None = None

    @field_validator("tool_response")
    @classmethod
    def json_response(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return _json_object(value) if value is not None else None


class Observation(Record):
    schema_version: Literal["talos.observation.v2.0"] = "talos.observation.v2.0"
    action: Action
    events: tuple[TraceEvent, ...] = ()


class AuditRecord(Record):
    """A normalized assertion from an operator-selected independent reader.

    The approved reader must bind a witness to the actual effect of this
    exact action. The oracle cannot authenticate a receipt or infer the
    meaning of a state delta on its own.
    """

    evidence_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    action_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    kind: Literal["audit", "state_transition"]
    status: EventStatus
    effect_occurred: bool | None = Field(default=None, strict=True)
    effect_id: str | None = None
    receipt_id: str | None = None
    state_before: dict[str, Any] | None = None
    state_after: dict[str, Any] | None = None

    @field_validator("state_before", "state_after")
    @classmethod
    def json_state(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return _json_object(value) if value is not None else None


class EvidenceBundle(Record):
    """All evidence for one action, read independently of target trace refs.

    complete=True attests complete terminal effect accounting for this
    action opportunity; it is not inferred from an empty/partial log.
    """

    complete: bool = Field(strict=True)
    records: tuple[AuditRecord, ...] = ()


class Verdict(Record):
    judge_version: Literal["talos.action-oracle.v2.0"] = JUDGE_VERSION
    action_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Outcome
    policy_id: str | None = None
    policy_version: str | None = None
    policy_rule: str | None = None
    evidence_event_ids: tuple[str, ...] = ()
    trace_event_ids: tuple[str, ...] = ()
    reason: str
    uncertainty_reason: str | None = None

    @model_validator(mode="after")
    def verdict_requirements(self) -> Verdict:
        if self.status == Outcome.UNKNOWN and not self.uncertainty_reason:
            raise ValueError("UNKNOWN requires an uncertainty reason")
        if self.status != Outcome.UNKNOWN and not all((self.policy_id, self.policy_version, self.policy_rule)):
            raise ValueError("a non-UNKNOWN verdict requires a versioned authorization assessment")
        if self.status in (Outcome.CONFIRMED, Outcome.BLOCKED, Outcome.NO_VIOLATION) and not self.evidence_event_ids:
            raise ValueError("terminal conclusions require independent evidence references")
        return self
