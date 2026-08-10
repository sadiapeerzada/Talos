"""
Wiring/harness-integration tests for external_langchain_agent.py.

IMPORTANT SCOPE NOTE: these tests use LangChain's own real
FakeMessagesListChatModel test double (not a live model) to prove the
HTTP contract and Talos's LangChainAdapter can correctly discover and
drive this target end-to-end. This is a legitimate, valuable thing to
verify automatically in CI (no API key required, deterministic), but it
is explicitly NOT a security scan -- a scripted fake model isn't making
real security-relevant decisions, so nothing here should be read as "Talos
found a vulnerability." The actual live scan (which needs a real
GROQ_API_KEY or similar) is documented in
docs/external-target-validation.md with exact reproduction commands.
"""

from __future__ import annotations

import threading
import time

import pytest
import uvicorn
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage

import talos.sample_agents.external_langchain_agent as ext


class _ToolCallingFakeModel(FakeMessagesListChatModel):
    """FakeMessagesListChatModel doesn't implement bind_tools by default
    (real LangChain limitation for tool-calling agent graphs) -- this is
    the standard one-line override needed to test a tool-calling agent
    with a scripted model. Still LangChain's own real base class."""

    def bind_tools(self, tools, **kwargs):  # type: ignore[no-untyped-def]
        return self


@pytest.fixture()
def wired_fake_agent():
    """Wires the real create_agent graph to a scripted (not live) model
    that calls lookup_employee once, then gives a final answer -- repeated
    enough times to survive multiple exchanges/adapter discovery calls."""
    responses = [
        AIMessage(content="", tool_calls=[{"name": "lookup_employee", "args": {"employee_id": "E100"}, "id": "call_1"}]),
        AIMessage(content="Priya Nair works in Engineering, reporting to R. Alvarez."),
    ] * 10
    ext._AGENT = ext.build_agent(model=_ToolCallingFakeModel(responses=responses))
    yield
    ext._AGENT = None


def test_tools_endpoint_matches_langchain_adapter_contract(wired_fake_agent):
    from fastapi.testclient import TestClient

    client = TestClient(ext.app)
    r = client.get("/agent/tools")
    assert r.status_code == 200
    tools = r.json()["tools"]
    names = {t["name"] for t in tools}
    assert names == {"lookup_employee", "approve_expense_payment", "notify_manager", "search_it_kb"}
    for t in tools:
        assert "description" in t and t["description"].strip()
        assert "args_schema" in t and "properties" in t["args_schema"]


def test_agent_endpoint_round_trip_executes_a_real_tool_call(wired_fake_agent):
    from fastapi.testclient import TestClient

    client = TestClient(ext.app)
    r = client.post("/agent", json={"input": "who is E100?", "chat_history": []})
    assert r.status_code == 200
    body = r.json()
    assert body["output"]
    assert body["intermediate_steps"]
    step = body["intermediate_steps"][0]
    assert step["tool"] == "lookup_employee"
    assert step["tool_input"] == {"employee_id": "E100"}
    assert "Priya Nair" in step["observation"]  # the real EMPLOYEES data, not a placeholder


def test_talos_langchain_adapter_discovers_and_drives_this_target_end_to_end(wired_fake_agent):
    """The actual proof this matters: Talos's own LangChainAdapter (used
    unmodified, no special-casing) can connect to, discover tools from,
    and successfully drive a real exchange against this independent
    target over real HTTP -- not just that the FastAPI routes respond."""
    from talos.harness.langchain_adapter import LangChainAdapter

    config = uvicorn.Config(ext.app, host="127.0.0.1", port=8103, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 5
        adapter = LangChainAdapter("http://127.0.0.1:8103/agent")
        tools = None
        while time.time() < deadline:
            try:
                tools = adapter.list_tools()
                break
            except Exception:
                time.sleep(0.2)
        assert tools is not None, "server did not come up in time"
        assert {t.name for t in tools} == {"lookup_employee", "approve_expense_payment", "notify_manager", "search_it_kb"}

        result = adapter.send(message="who is E100?", history=[])
        assert result.response
        assert result.tool_calls_made
        assert result.tool_calls_made[0].tool_name == "lookup_employee"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_tool_graph_classifier_detects_financial_and_external_comm_and_free_text_on_this_independent_target():
    """Confirms Talos's black-box classifier (talos/graph/classify.py --
    pure keyword heuristics over name/description text, not hardcoded to
    this project's own fixture tool names) correctly recognizes this
    independent target's capabilities, which is what makes most of the 35
    attack templates actually applicable here rather than silently
    skipped for lack of a matching tool graph."""
    from talos.graph.classify import classify_side_effect, is_free_text_source
    from talos.harness.base import ToolSpec

    specs = {
        t.name: ToolSpec(name=t.name, description=t.description, parameters=[])
        for t in ext.ALL_TOOLS
    }
    assert classify_side_effect(specs["approve_expense_payment"]).value == "financial"
    assert classify_side_effect(specs["notify_manager"]).value == "external_comm"
    assert is_free_text_source(specs["lookup_employee"]) is True  # "notes on file"
    assert is_free_text_source(specs["search_it_kb"]) is True  # "articles"
