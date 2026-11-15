"""Portable declarations; provenance is not approval or authentication."""
from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PROFILE_VERSION = "talos.target-profile.v2.0"
CLASSIFIER_VERSION = "talos.profile-classifier.v2.0"


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def finite_json(value: dict[str, Any]) -> dict[str, Any]:
    try:
        encoded = json.dumps(value, sort_keys=True, allow_nan=False)
        if json.loads(encoded) != value:
            raise ValueError("non-JSON keys or values")
    except (TypeError, ValueError):
        raise ValueError("finite JSON with string keys required") from None
    return value


class Effect(str, Enum):
    READ_ONLY = "read_only"
    STATE_CHANGING = "state_changing"
    EXTERNAL_COMMUNICATION = "external_communication"
    FINANCIAL_WRITE = "financial_write"
    EXTERNAL_SEND = "external_send"
    READ_UNTRUSTED = "read_untrusted"
    PRIVILEGED_WRITE = "privileged_write"
    SENSITIVE_READ = "sensitive_read"
    UNKNOWN = "unknown"


class Permission(str, Enum):
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    PRIVILEGED = "privileged"
    UNKNOWN = "unknown"


class OutputTrust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class MetadataEvidence(Model):
    evidence_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    reference: str = Field(min_length=1)
    origin: Literal["operator_declaration", "target_declaration", "documentation"]
    detail: str = Field(min_length=1)


class EffectClaim(Model):
    effect: Effect
    evidence_ids: tuple[str, ...] = Field(min_length=1)


class PermissionClaim(Model):
    permission: Permission
    boundary_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = Field(min_length=1)


class TrustClaim(Model):
    trust: OutputTrust
    evidence_ids: tuple[str, ...] = Field(min_length=1)


class AuthorizationBoundary(Model):
    boundary_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    policy_id: str | None = None
    policy_version: str | None = None
    rule_id: str | None = None
    evidence_ids: tuple[str, ...] = Field(min_length=1)


class AuditCapability(Model):
    capability_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    kind: Literal["audit", "state_transition", "reset"]
    can_observe_commit: bool | None = Field(default=None, strict=True)
    can_attest_no_effect: bool | None = Field(default=None, strict=True)
    action_digest_binding: bool | None = Field(default=None, strict=True)
    description: str = Field(min_length=1)
    evidence_ids: tuple[str, ...] = Field(min_length=1)


class ToolProfile(Model):
    name: str = Field(min_length=1)
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    effects: tuple[EffectClaim, ...] = ()
    permissions: tuple[PermissionClaim, ...] = ()
    output_trust: tuple[TrustClaim, ...] = ()
    audit_capability_ids: tuple[str, ...] = ()

    @field_validator("input_schema", "output_schema")
    @classmethod
    def json_schema(cls, value: dict[str, Any]) -> dict[str, Any]:
        # Preserve unfamiliar schema dialects. This is not a JSON Schema validator.
        return finite_json(value)


class PossibleFlow(Model):
    flow_id: str = Field(min_length=1)
    source_tool: str = Field(min_length=1)
    target_tool: str = Field(min_length=1)
    description: str = Field(min_length=1)
    evidence_ids: tuple[str, ...] = Field(min_length=1)


class CustodyDeclaration(Model):
    custodian_id: str | None = None
    independence_claimed: bool = Field(default=False, strict=True)
    evidence_ids: tuple[str, ...] = ()


class TargetProfile(Model):
    profile_version: Literal["talos.target-profile.v2.0"] = PROFILE_VERSION
    target_id: str = Field(min_length=1)
    domain: str = Field(min_length=1)
    fixture_id: str | None = None
    custody: CustodyDeclaration = Field(default_factory=CustodyDeclaration)
    evidence: tuple[MetadataEvidence, ...]
    tools: tuple[ToolProfile, ...]
    authorization_boundaries: tuple[AuthorizationBoundary, ...] = ()
    audit_capabilities: tuple[AuditCapability, ...] = ()
    possible_flows: tuple[PossibleFlow, ...] = ()
    state_reset_description: str | None = None
    authorized_test_objectives: tuple[str, ...] = ()
    prohibited_effects: tuple[str, ...] = ()
    allowed_egress: tuple[str, ...] = ()
    privacy_policy_reference: str | None = None

    @model_validator(mode="after")
    def references(self) -> TargetProfile:
        def index(items, attr):
            ids = [getattr(item, attr) for item in items]
            if len(ids) != len(set(ids)):
                raise ValueError(f"duplicate {attr}")
            return set(ids)
        evidence = index(self.evidence, "evidence_id")
        tools = index(self.tools, "name")
        boundaries = index(self.authorization_boundaries, "boundary_id")
        capabilities = index(self.audit_capabilities, "capability_id")
        index(self.possible_flows, "flow_id")
        records = [self.custody, *self.tools, *self.authorization_boundaries,
                   *self.audit_capabilities, *self.possible_flows]
        for tool in self.tools:
            records.extend([*tool.effects, *tool.permissions, *tool.output_trust])
            if not set(tool.audit_capability_ids) <= capabilities:
                raise ValueError("unknown tool audit capability reference")
            for claim in tool.permissions:
                if not set(claim.boundary_ids) <= boundaries:
                    raise ValueError("unknown authorization boundary reference")
        for record in records:
            if not set(record.evidence_ids) <= evidence:
                raise ValueError("unknown metadata evidence reference")
        for flow in self.possible_flows:
            if flow.source_tool not in tools or flow.target_tool not in tools:
                raise ValueError("unknown flow tool reference")
        if self.custody.independence_claimed and not self.custody.evidence_ids:
            raise ValueError("custody claims require provenance; they still do not verify independence")
        return self

    def digest(self) -> str:
        data = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(data.encode()).hexdigest()


def snapshot(profile: TargetProfile) -> TargetProfile:
    """Revalidate and isolate nested JSON before deriving classifications."""
    return TargetProfile.model_validate(profile.model_dump())
