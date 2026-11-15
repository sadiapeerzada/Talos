"""Conservative binding to PR-01; profile declarations never grant authority."""
from __future__ import annotations

from talos.judging import Action, Authorization, AuthorizationPolicy, PolicyAssessment
from talos.profiles.classify import classify_profile
from talos.profiles.models import Permission, TargetProfile, snapshot


class ProfileBoundPolicy:
    """An explicit delegate remains necessary; no trust source is auto-selected.

    This checks profile scope and versioned rule identity, not JSON Schema
    argument validity or real policy semantics. The reviewed delegate must
    validate arguments, consent and identity. Errors propagate to PR-01's
    fail-closed boundary.
    """

    def __init__(self, profile: TargetProfile, delegate: AuthorizationPolicy | None = None):
        self._profile = snapshot(profile)
        self._delegate = delegate

    def assess(self, action: Action) -> PolicyAssessment:
        profile = self._profile
        action = Action.model_validate(action.model_dump())
        digest = action.digest()

        def unknown(reason):
            return PolicyAssessment(action_digest=digest, authorization=Authorization.UNKNOWN,
                                    policy_id="talos.profile-binding", policy_version="2.0",
                                    rule_id="unresolved-profile-contract", reason=reason)
        if action.target_id != profile.target_id:
            return unknown("action target does not match profile")
        tools = {t.name: t for t in profile.tools}
        if action.tool_name not in tools:
            return unknown("action tool is absent from profile")
        classification = next(c for c in classify_profile(profile) if c.tool_name == action.tool_name)
        if classification.permission == Permission.UNKNOWN or classification.status == "conflicted":
            return unknown("permission or semantic declarations are unresolved/conflicted")
        if self._delegate is None:
            return unknown("profile declarations are not an authorization policy")
        assessment = self._delegate.assess(Action.model_validate(action.model_dump()))
        assessment = PolicyAssessment.model_validate(assessment.model_dump())
        if assessment.action_digest != digest:
            return unknown("delegated assessment belongs to a different action")
        ids = {b for c in tools[action.tool_name].permissions for b in c.boundary_ids}
        permitted_rules = {(b.policy_id, b.policy_version, b.rule_id)
                           for b in profile.authorization_boundaries if b.boundary_id in ids}
        if (assessment.policy_id, assessment.policy_version, assessment.rule_id) not in permitted_rules:
            return unknown("delegated policy rule does not match declared tool boundary")
        return assessment
