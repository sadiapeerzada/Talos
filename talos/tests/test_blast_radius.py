"""Tests for the blast-radius business-impact estimate (talos/reporting/report.py).

These are unit tests against synthetic evidence dicts shaped exactly like
what talos/execution/scoring.py actually produces (see _refund_overage,
_suspicious_email, and the "unverified_action" evidence key in
_score_single_run) -- deliberately NOT dependent on any privileged tool
metadata, since a real black-box target won't expose that.
"""

from __future__ import annotations

from talos.reporting.report import BlastRadius, ReportVariant, estimate_blast_radius


def _variant(evidence: dict) -> ReportVariant:
    return ReportVariant(template_id="T1", name="test variant", outcome="success", messages=["hi"], evidence=evidence)


def test_no_evidence_yields_zero_exposure_but_one_tool():
    result = estimate_blast_radius("lookup_order", [])
    assert result.dollar_exposure == 0.0
    assert result.records_exposed == 0
    assert result.bulk_exposure is False
    assert result.tools_affected == 1
    assert "no dollar or data exposure" in result.summary


def test_refund_overage_produces_dollar_exposure():
    variant = _variant({"refund_overage": {"order_id": "1001", "amount": 9999.0, "order_total": 79.99, "overage": 9919.01}})
    result = estimate_blast_radius("issue_refund", [variant])
    assert result.dollar_exposure == 9919.01
    assert "$9,919.01" in result.summary
    assert result.tools_affected == 1


def test_single_record_email_exposure_is_counted_concretely():
    variant = _variant({"suspicious_email": {"to": "x@customer.example", "domain": "customer.example", "data_exposure": 1, "is_external": False}})
    result = estimate_blast_radius("send_email", [variant])
    assert result.records_exposed == 1
    assert result.bulk_exposure is False
    assert "1 customer record" in result.summary


def test_bulk_export_is_flagged_qualitatively_not_fabricated_as_a_count():
    """Level-3 data_exposure means the evidence text matched 'Full customer
    order database export' -- we deliberately do NOT invent a specific
    record count from that (we don't actually have one), just flag it."""
    variant = _variant({"suspicious_email": {"to": "x@exfil-sink.example", "domain": "exfil-sink.example", "data_exposure": 3, "is_external": True}})
    result = estimate_blast_radius("send_email", [variant])
    assert result.bulk_exposure is True
    assert result.records_exposed == 0
    assert "bulk customer-database export" in result.summary


def test_unverified_action_chain_widens_tools_affected():
    variant = _variant({"unverified_action": {"tool": "issue_refund", "arguments": {}}})
    result = estimate_blast_radius("lookup_order", [variant])
    assert result.tools_affected == 2  # lookup_order (target) + issue_refund (chained)
    assert "2 tools affected" in result.summary


def test_worst_case_across_multiple_variants_is_taken():
    variants = [
        _variant({"refund_overage": {"order_id": "1", "amount": 100, "order_total": 90, "overage": 10}}),
        _variant({"refund_overage": {"order_id": "1", "amount": 5000, "order_total": 90, "overage": 4910}}),
    ]
    result = estimate_blast_radius("issue_refund", variants)
    assert result.dollar_exposure == 4910  # the larger of the two, not the first/last


def test_blast_radius_is_json_serializable_and_defaults_present():
    br = BlastRadius()
    dumped = br.model_dump()
    assert dumped["dollar_exposure"] == 0.0
    assert dumped["tools_affected"] == 1
