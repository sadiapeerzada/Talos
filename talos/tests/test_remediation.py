"""Tests for auto-generated remediation patches (talos/remediation.py).

Includes a syntax-validity check on every generated patch -- a "drop-in
patch" that doesn't even parse as Python would be worse than no patch at
all, so this is the one property that must hold no matter what evidence
combination produced the patch.
"""

from __future__ import annotations

import ast

from talos.remediation import generate_remediation_patch


class _FakeVariant:
    def __init__(self, evidence: dict):
        self.evidence = evidence


def test_refund_finding_emits_amount_capping_guard():
    patch = generate_remediation_patch(
        exploit_class="direct_injection",
        target_tool="issue_refund",
        variants=[_FakeVariant({"refund_overage": {"order_id": "1001", "amount": 9999.0, "order_total": 79.99, "overage": 9919.01}})],
    )
    assert "def guarded_issue_refund" in patch
    assert "min(float(amount), order.total_amount)" in patch
    assert "79.99" in patch  # the actual observed order total, not a placeholder


def test_email_finding_emits_domain_allowlist_guard():
    patch = generate_remediation_patch(
        exploit_class="data_exfiltration",
        target_tool="send_email",
        variants=[_FakeVariant({"suspicious_email": {"to": "x@exfil-sink.example", "domain": "exfil-sink.example", "data_exposure": 3, "is_external": True}})],
    )
    assert "def guarded_send_email" in patch
    assert "ALLOWED_EMAIL_DOMAINS" in patch
    assert "exfil-sink.example" in patch  # the actual observed destination domain


def test_indirect_injection_emits_instruction_hierarchy_addendum():
    patch = generate_remediation_patch(
        exploit_class="indirect_injection",
        target_tool="lookup_order",
        variants=[],
    )
    assert "SYSTEM_PROMPT_ADDENDUM" in patch
    assert "untrusted DATA" in patch


def test_permission_escalation_emits_reauth_guard():
    patch = generate_remediation_patch(
        exploit_class="permission_escalation",
        target_tool="issue_refund",
        variants=[_FakeVariant({"unverified_action": {"tool": "issue_refund", "arguments": {}}})],
    )
    assert "def guarded_issue_refund" in patch
    assert "confirmed_by_user" in patch


def test_unknown_exploit_class_still_emits_something_actionable():
    """Never emit an empty patch -- always fall back to a reauth guard as
    a baseline concrete protection."""
    patch = generate_remediation_patch(exploit_class="some_future_class", target_tool="search_kb", variants=[])
    assert patch.strip()
    assert "def guarded_search_kb" in patch


def test_generated_patches_are_always_valid_python():
    """A drop-in patch that doesn't parse is worse than no patch. Exercise
    every exploit class x tool combination Talos actually produces and
    confirm every single output parses cleanly."""
    exploit_classes = [
        "direct_injection", "indirect_injection", "permission_escalation",
        "data_exfiltration", "goal_hijacking", "authority_spoofing", "policy_shadowing",
    ]
    tools = ["issue_refund", "send_email", "lookup_order", "search_kb"]
    evidence_variants = [
        [],
        [_FakeVariant({"refund_overage": {"order_id": "1", "amount": 500, "order_total": 100, "overage": 400}})],
        [_FakeVariant({"suspicious_email": {"to": "a@b.example", "domain": "b.example", "data_exposure": 2, "is_external": True}})],
        [_FakeVariant({"unverified_action": {"tool": "send_email", "arguments": {}}})],
    ]

    checked = 0
    for exploit_class in exploit_classes:
        for tool in tools:
            for variants in evidence_variants:
                patch = generate_remediation_patch(exploit_class=exploit_class, target_tool=tool, variants=variants)
                assert patch.strip(), f"empty patch for {exploit_class}/{tool}"
                # Strip the one non-code line (system-prompt string block is
                # still valid Python -- it's just a triple-quoted string
                # assignment) -- ast.parse should handle all generated output.
                ast.parse(patch)
                checked += 1
    assert checked == len(exploit_classes) * len(tools) * len(evidence_variants)
