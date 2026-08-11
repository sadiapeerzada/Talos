"""
Sample vulnerable customer-service agent -- "native" flavor.

No agent framework: this hand-rolls the tool-calling loop the way you would
directly against the Anthropic (or OpenAI) tool-use API, and exposes it
over HTTP using Anthropic Messages-API-flavored request/response shapes
(`input_schema` for tool parameters, a flat `messages` list on requests).

Run directly:
    python -m talos.sample_agents.native_server --port 8001

Endpoints:
    GET  /agent/tools   -> {"tools": [{"name","description","input_schema"}]}
    POST /agent         -> body {"messages": [{"role":"user","content": str}],
                                  "history": [{"role","content"}, ...]}
                           -> {"response", "tool_calls_made", "trace"}
"""

from __future__ import annotations

import argparse
from typing import Any, Optional

from fastapi import FastAPI
from pydantic import BaseModel

from talos.sample_agents.brain import RuleBasedBrain, Brain, Turn
from talos.sample_agents.data import AuditLog
from talos.sample_agents.exchange import run_exchange
from talos.sample_agents.tools import ToolDefinition, make_tool_definitions

AUDIT_LOG = AuditLog()
TOOL_DEFS: list[ToolDefinition] = make_tool_definitions(AUDIT_LOG)
BRAIN: Brain = RuleBasedBrain()

app = FastAPI(title="Talos sample agent (native)")


def _to_input_schema(t: ToolDefinition) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            p.name: {"type": p.type, "description": p.description} for p in t.parameters
        },
        "required": [p.name for p in t.parameters if p.required],
    }


@app.get("/agent/tools")
def list_tools() -> dict[str, Any]:
    return {
        "tools": [
            {"name": t.name, "description": t.description, "input_schema": _to_input_schema(t)}
            for t in TOOL_DEFS
        ]
    }


class HistoryMessage(BaseModel):
    role: str
    content: str


class NativeMessage(BaseModel):
    role: str
    content: str


class AgentRequest(BaseModel):
    messages: list[NativeMessage]
    history: Optional[list[HistoryMessage]] = None


@app.post("/agent")
def agent_turn(req: AgentRequest) -> dict[str, Any]:
    message = req.messages[-1].content if req.messages else ""
    history = [Turn(role=h.role, content=h.content) for h in (req.history or [])]
    response_text, tool_calls_made, trace = run_exchange(BRAIN, TOOL_DEFS, history, message)
    return {"response": response_text, "tool_calls_made": tool_calls_made, "trace": trace}


@app.get("/agent/_audit_log")
def _audit_log() -> dict[str, Any]:
    """Test-only introspection endpoint -- lets Talos's test suite confirm
    simulated side effects without needing a real backing store."""
    return {"entries": [{"kind": e.kind, **e.detail} for e in AUDIT_LOG.entries]}


@app.post("/agent/_reset")
def _reset() -> dict[str, Any]:
    AUDIT_LOG.reset()
    return {"status": "reset"}


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--hardened",
        action="store_true",
        help="Wrap the rule-based brain in PolicyEnforcingBrain (talos.sample_agents.policy) -- "
        "the same deterministic guardrails proven against the real/Groq-backed target, applied "
        "here to the deterministic vulnerable brain for the item-8 auto-patch-and-reverify loop.",
    )
    args = parser.parse_args()

    if args.hardened:
        global BRAIN
        from talos.sample_agents.policy import PolicyEnforcingBrain

        BRAIN = PolicyEnforcingBrain(RuleBasedBrain())

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
