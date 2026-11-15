"""Opt-in portable profiles; declarations are not independent approvals."""
from talos.profiles.classify import ToolClassification, classify_profile
from talos.profiles.inventory import profile_from_tools
from talos.profiles.models import (
    CLASSIFIER_VERSION, PROFILE_VERSION, AuditCapability, AuthorizationBoundary, CustodyDeclaration,
    Effect, EffectClaim, MetadataEvidence, OutputTrust, Permission, PermissionClaim,
    PossibleFlow, TargetProfile, ToolProfile, TrustClaim,
)
from talos.profiles.oracle import ProfileBoundPolicy

__all__ = [
    "CLASSIFIER_VERSION", "PROFILE_VERSION", "AuditCapability", "AuthorizationBoundary",
    "CustodyDeclaration", "Effect", "EffectClaim", "MetadataEvidence", "OutputTrust", "Permission",
    "PermissionClaim", "PossibleFlow", "TargetProfile", "ToolProfile", "TrustClaim",
    "ProfileBoundPolicy", "ToolClassification", "classify_profile", "profile_from_tools",
]
