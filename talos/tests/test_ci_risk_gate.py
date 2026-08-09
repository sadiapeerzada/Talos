"""Tests for talos/scripts/ci_risk_gate.py.

The pure comparison logic (evaluate_regression) is tested directly with no
I/O, server, or scan required. A light end-to-end check that the script can
actually run a real scan and read the baseline file lives at the bottom.
"""

from __future__ import annotations

import json

from talos.scripts.ci_risk_gate import (
    BASELINE_PATH,
    RegressionResult,
    evaluate_regression,
    load_baseline,
)


def test_higher_score_is_a_regression():
    result = evaluate_regression(baseline_score=50, new_score=80)
    assert result.passed is False
    assert "REGRESSION" in result.message
    assert "50 to 80" in result.message


def test_lower_score_passes_and_reports_improvement():
    result = evaluate_regression(baseline_score=100, new_score=12)
    assert result.passed is True
    assert "improved" in result.message
    assert "100 to 12" in result.message


def test_equal_score_passes():
    result = evaluate_regression(baseline_score=42, new_score=42)
    assert result.passed is True
    assert "unchanged" in result.message


def test_one_point_regression_still_fails():
    """The gate is strict -- even a 1-point increase counts as a regression,
    since this is meant to catch any newly-introduced weakening."""
    result = evaluate_regression(baseline_score=10, new_score=11)
    assert result.passed is False


def test_result_is_a_plain_dataclass_with_expected_fields():
    result = evaluate_regression(baseline_score=1, new_score=1)
    assert isinstance(result, RegressionResult)
    assert result.baseline_score == 1
    assert result.new_score == 1


def test_committed_baseline_file_is_valid_and_loadable():
    """The actual committed .ci/baseline_risk_score.json must parse and
    contain a risk_score in the valid 0-100 range -- a malformed baseline
    would silently break the CI gate for everyone."""
    baseline = load_baseline(BASELINE_PATH)
    assert 0 <= baseline["risk_score"] <= 100
    assert "target" in baseline
    assert "adapter" in baseline


def test_ci_gate_end_to_end_against_a_real_scan(native_server_url):
    """Exercises the actual scan + comparison path (not just the pure
    function) against a live sample agent, using the existing
    native_server_url fixture rather than spawning a subprocess -- proves
    run_scan_and_get_risk_score() correctly extracts stats.risk_score from
    a real ScanReport."""
    from talos.scripts.ci_risk_gate import run_scan_and_get_risk_score

    score = run_scan_and_get_risk_score(native_server_url, "native")
    assert 0 <= score <= 100
    # The native sample agent is deliberately vulnerable -- a real scan
    # against it should never come back clean.
    assert score > 0
