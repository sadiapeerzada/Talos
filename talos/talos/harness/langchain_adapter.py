"""
Adapter A -- LangChain agent adapter.

Talks to a LangChain agent exposed over HTTP using LangChain-native shapes:
tool parameters as a pydantic-generated `args_schema` JSON Schema, requests
as `{"input", "chat_history"}`, responses as `{"output", "intermediate_steps"}`
(roughly what LangServe would expose for an AgentExecutor-style agent). See
talos/sample_agents/langchain_server.py for the reference implementation
this was built against.

This is intentionally a different wire format from NativeAdapter -- the
translation work done here (args_schema -> ToolParameter,
intermediate_steps -> ToolCallRecord/trace) is what actually exercises the
TargetAgent abstraction rather than making it a no-op.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from talos.harness.base import (
    AgentTurnResult,
    HistoryMessage,
    TargetAgent,
    ToolCallRecord,
    ToolParameter,
    ToolSpec,
)


def _params_from_args_schema(schema: dict[str, Any]) -> list[ToolParameter]:
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    params = []
    for name, sub in props.items():
        json_type = sub.get("type", "string")
        params.append(ToolParameter(name=name, type=json_type, description=sub.get("description", ""), required=name in required))
    return params


class LangChainAdapter(TargetAgent):
    def __init__(self, target_url: str, timeout: float = 30.0):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self._client: Optional[httpx.Client] = None

    def connect(self) -> None:
        self._client = httpx.Client(timeout=self.timeout)
        resp = self._client.get(f"{self.target_url}/tools")
        resp.raise_for_status()

    def _ensure_connected(self) -> httpx.Client:
        if self._client is None:
            self.connect()
        assert self._client is not None
        return self._client

    def list_tools(self) -> list[ToolSpec]:
        client = self._ensure_connected()
        resp = client.get(f"{self.target_url}/tools")
        resp.raise_for_status()
        specs = []
        for t in resp.json()["tools"]:
            params = _params_from_args_schema(t.get("args_schema", {}))
            specs.append(ToolSpec(name=t["name"], description=t["description"], parameters=params))
        return specs

    def send(self, message: str, history: Optional[list[HistoryMessage]] = None) -> AgentTurnResult:
        client = self._ensure_connected()
        payload: dict[str, Any] = {"input": message}
        if history:
            payload["chat_history"] = [h.model_dump() for h in history]
        resp = client.post(self.target_url, json=payload)
        resp.raise_for_status()
        data = resp.json()

        tool_calls_made = [
            ToolCallRecord(tool_name=step["tool"], arguments=step["tool_input"], result=step["observation"])
            for step in data["intermediate_steps"]
        ]
        # Build a trace shape equivalent to NativeAdapter's, so downstream
        # code never has to know which adapter produced it.
        trace = [
            {"step": i, "action": "call_tool", "tool": step["tool"], "reason": ""}
            for i, step in enumerate(data["intermediate_steps"])
        ]
        trace.append({"step": len(trace), "action": "final", "tool": None, "reason": ""})

        return AgentTurnResult(response=data["output"], tool_calls_made=tool_calls_made, trace=trace)
