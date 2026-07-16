"""
Adapter B -- Plain function-calling adapter.

Talks to a target that speaks an Anthropic/OpenAI-style tool-use HTTP
contract directly (no agent framework): tool parameters as `input_schema`
JSON Schema, requests as a flat `messages` list. See
talos/sample_agents/native_server.py for the reference implementation this
was built against.
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


def _param_from_input_schema(name: str, schema: dict[str, Any], required: set[str]) -> ToolParameter:
    return ToolParameter(
        name=name,
        type=schema.get("type", "string"),
        description=schema.get("description", ""),
        required=name in required,
    )


class NativeAdapter(TargetAgent):
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
            schema = t.get("input_schema", {})
            props = schema.get("properties", {})
            required = set(schema.get("required", []))
            params = [_param_from_input_schema(name, sub, required) for name, sub in props.items()]
            specs.append(ToolSpec(name=t["name"], description=t["description"], parameters=params))
        return specs

    def send(self, message: str, history: Optional[list[HistoryMessage]] = None) -> AgentTurnResult:
        client = self._ensure_connected()
        payload: dict[str, Any] = {"messages": [{"role": "user", "content": message}]}
        if history:
            payload["history"] = [h.model_dump() for h in history]
        resp = client.post(self.target_url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return AgentTurnResult(
            response=data["response"],
            tool_calls_made=[
                ToolCallRecord(tool_name=tc["tool_name"], arguments=tc["arguments"], result=tc["result"])
                for tc in data["tool_calls_made"]
            ],
            trace=data["trace"],
        )
