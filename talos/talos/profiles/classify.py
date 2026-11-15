"""Explicit semantic classification; no inference from tool names."""
from __future__ import annotations

from typing import Literal

from talos.profiles.models import (
    CLASSIFIER_VERSION, Effect, Model, OutputTrust, Permission, TargetProfile, ToolProfile, snapshot,
)


class ToolClassification(Model):
    classifier_version: Literal["talos.profile-classifier.v2.0"] = CLASSIFIER_VERSION
    tool_name: str
    side_effects: tuple[str, ...]
    roles: tuple[str, ...]
    permission: Permission
    output_trust: OutputTrust
    status: Literal["declared", "incomplete", "conflicted"]
    evidence_ids: tuple[str, ...]
    reasons: tuple[str, ...]


def _classify(profile: TargetProfile, tool: ToolProfile) -> ToolClassification:
    evidence = set(tool.evidence_ids)
    for claim in (*tool.effects, *tool.permissions, *tool.output_trust):
        evidence.update(claim.evidence_ids)
    effects = {claim.effect for claim in tool.effects}
    roles = effects & {Effect.FINANCIAL_WRITE, Effect.EXTERNAL_SEND, Effect.READ_UNTRUSTED,
                       Effect.PRIVILEGED_WRITE, Effect.SENSITIVE_READ}
    categories = set()
    if Effect.READ_ONLY in effects:
        categories.add("read_only")
    if effects & {Effect.STATE_CHANGING, Effect.FINANCIAL_WRITE, Effect.PRIVILEGED_WRITE}:
        categories.add("state_changing")
    if effects & {Effect.EXTERNAL_COMMUNICATION, Effect.EXTERNAL_SEND}:
        categories.add("external_communication")
    reasons = []
    conflicted = False
    if "read_only" in categories and len(categories) > 1:
        categories = {"unknown"}
        conflicted = True
        reasons.append("read_only conflicts with state-changing/external effect declarations")
    elif not categories or Effect.UNKNOWN in effects:
        categories = {"unknown"}
        reasons.append("side effects are missing or explicitly unresolved")

    permissions = {claim.permission for claim in tool.permissions}
    permission = next(iter(permissions)) if len(permissions) == 1 else Permission.UNKNOWN
    if len(permissions) > 1:
        conflicted = True
        reasons.append("conflicting permission declarations")
    boundary_map = {b.boundary_id: b for b in profile.authorization_boundaries}
    ids = {i for claim in tool.permissions for i in claim.boundary_ids}
    for i in ids:
        evidence.update(boundary_map[i].evidence_ids)
    if permission != Permission.UNKNOWN:
        if not ids or any(not all((boundary_map[i].policy_id, boundary_map[i].policy_version,
                                   boundary_map[i].rule_id)) for i in ids):
            permission = Permission.UNKNOWN
            reasons.append("permission lacks a complete versioned authorization boundary")
    if permission == Permission.UNKNOWN:
        reasons.append("permission unresolved; no safe/public default")
    trusts = {claim.trust for claim in tool.output_trust}
    trust = next(iter(trusts)) if len(trusts) == 1 else OutputTrust.UNKNOWN
    if len(trusts) > 1:
        conflicted = True
        reasons.append("conflicting output-trust declarations")
    if trust == OutputTrust.UNKNOWN:
        reasons.append("tool-output trust unresolved")
    if not tool.description or not tool.input_schema or not tool.output_schema:
        reasons.append("target description or input/output schema incomplete")
    return ToolClassification(
        tool_name=tool.name, side_effects=tuple(sorted(categories)),
        roles=tuple(sorted(role.value for role in roles)), permission=permission, output_trust=trust,
        status="conflicted" if conflicted else ("incomplete" if reasons else "declared"),
        evidence_ids=tuple(sorted(evidence)), reasons=tuple(reasons),
    )


def classify_profile(profile: TargetProfile) -> tuple[ToolClassification, ...]:
    validated = snapshot(profile)
    return tuple(_classify(validated, tool) for tool in sorted(validated.tools, key=lambda t: t.name))
