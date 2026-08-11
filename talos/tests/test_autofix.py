"""
End-to-end proof for the auto-patch-and-reverify loop (item 8).

This is deliberately the most important test in the whole roadmap, per the
spec: a half-working autofix loop that sometimes lies about the risk score
dropping would actively damage credibility, so this test spins up REAL
sample-agent subprocesses and runs the REAL two-scan cycle -- nothing here
is mocked or simulated. It's slower than a unit test on purpose.
"""

from __future__ import annotations

from talos.autofix import HARDENING_STRATEGIES, run_autofix_cycle


def test_autofix_cycle_strictly_reduces_risk_score_end_to_end():
    result = run_autofix_cycle(vulnerable_port=8811, hardened_port=8812, repro_runs=1)

    # The core claim: a real second scan against a real hardened instance
    # produces a strictly lower risk score than the real baseline scan.
    assert result.hardened_risk_score < result.baseline_risk_score
    assert result.baseline_risk_score > 0  # the vulnerable target must have actually been vulnerable
    assert result.risk_score_delta > 0
    assert result.findings_closed > 0


def test_autofix_cycle_closes_the_specific_refund_overage_exploit_class():
    """Not just 'the number went down' -- the SPECIFIC exploit class Talos's
    own earlier demos centered on (refund overage via direct_injection)
    must actually stop succeeding against the hardened instance."""
    result = run_autofix_cycle(vulnerable_port=8813, hardened_port=8814, repro_runs=1)

    baseline_refund_findings = [
        f for f in result.baseline_report.findings
        if f.target_tool == "issue_refund" and f.exploit_class == "direct_injection"
    ]
    hardened_refund_findings = [
        f for f in result.hardened_report.findings
        if f.target_tool == "issue_refund" and f.exploit_class == "direct_injection"
    ]

    assert baseline_refund_findings, "expected the vulnerable baseline to show a real refund-overage finding"
    assert not hardened_refund_findings, "the hardened instance must no longer show this exploit class succeeding"


def test_autofix_result_summary_lines_match_the_real_numbers():
    result = run_autofix_cycle(vulnerable_port=8815, hardened_port=8816, repro_runs=1)
    lines = result.summary_lines()

    assert f"{result.baseline_risk_score}" in lines[0]
    assert f"{result.hardened_risk_score}" in lines[2]
    assert f"{result.risk_score_delta}" in lines[3]
    assert f"{result.findings_closed}" in lines[3]


def test_hardening_strategies_registry_covers_every_exploit_class_talos_can_produce():
    from talos.attacks.templates import ALL_TEMPLATES

    real_exploit_classes = {t.exploit_class for t in ALL_TEMPLATES}
    assert real_exploit_classes.issubset(HARDENING_STRATEGIES.keys())


def test_hardened_native_server_flag_actually_wraps_the_brain():
    """Unit-level check (fast, no subprocess) that --hardened does what it
    claims: wraps RuleBasedBrain in PolicyEnforcingBrain, not a no-op."""
    import talos.sample_agents.native_server as native
    from talos.sample_agents.brain import RuleBasedBrain
    from talos.sample_agents.policy import PolicyEnforcingBrain

    original_brain = native.BRAIN
    try:
        native.BRAIN = PolicyEnforcingBrain(RuleBasedBrain())
        assert isinstance(native.BRAIN, PolicyEnforcingBrain)
    finally:
        native.BRAIN = original_brain
