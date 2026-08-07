"""
Sample "real" customer-service agent -- backed by an actual external LLM
(Groq's free API) instead of the deterministic rule-based fixture used by
native_server.py / langchain_server.py.

This exists to prove Talos generalizes: it wasn't written against this
agent's prompt or decision logic, so a scan finding something here is
evidence Talos works on targets it has never seen, not just on its own
fixtures.

Two modes:
  --hardened not set : vulnerable mode. Uses GroqBrain directly. Whatever
                        the model decides is executed as-is (same posture
                        as the built-in vulnerable sample agents).
  --hardened set      : hardened mode. Wraps GroqBrain in
                        PolicyEnforcingBrain (see policy.py), which adds a
                        hardened system prompt AND a deterministic
                        backstop: refund amounts are capped to the real
                        order total, emails to non-allow-listed domains are
                        never sent, and sensitive actions require a fresh,
                        explicit confirmation.

Setup:
    Get a free Groq API key at https://console.groq.com/keys
    export GROQ_API_KEY=your_key_here

Run:
    python -m talos.sample_agents.real_agent_server --port 8002
    python -m talos.sample_agents.real_agent_server --port 8003 --hardened

Endpoints (identical contract to native_server.py, so it plugs straight
into the existing NativeAdapter / scan_service.py / dashboard.py / CLI with
no changes -- use --adapter native when scanning this target):
    GET  /agent/tools   -> {"tools": [{"name","description","input_schema"}]}
    POST /agent         -> body {"messages": [{"role":"user","content": str}],
                                  "history": [{"role","content"}, ...]}
                           -> {"response", "tool_calls_made", "trace"}
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Optional

from fastapi import FastAPI
from pydantic import BaseModel

from talos.sample_agents.data import AuditLog
from talos.sample_agents.exchange import run_exchange
from talos.sample_agents.groq_brain import DEFAULT_GROQ_MODEL, GroqBrain
from talos.sample_agents.policy import PolicyEnforcingBrain
from talos.sample_agents.brain import Brain, Turn
from talos.sample_agents.tools import ToolDefinition, make_tool_definitions

AUDIT_LOG = AuditLog()
TOOL_DEFS: list[ToolDefinition] = make_tool_definitions(AUDIT_LOG)

app = FastAPI(title="Talos sample agent (real / Groq-backed)")

# Populated in main() once we know --hardened / --model from argv, but also
# built eagerly here with defaults so `uvicorn talos.sample_agents.real_agent_server:app`
# works directly too.
_BRAIN: Optional[Brain] = None


def _build_brain(hardened: bool, model: str) -> Brain:
    groq = GroqBrain(model=model, hardened=hardened, tool_defs=TOOL_DEFS)
    return PolicyEnforcingBrain(groq) if hardened else groq


def get_brain() -> Brain:
    global _BRAIN
    if _BRAIN is None:
        _BRAIN = _build_brain(hardened=False, model=DEFAULT_GROQ_MODEL)
    return _BRAIN


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
    brain = get_brain()
    try:
        response_text, tool_calls_made, trace = run_exchange(brain, TOOL_DEFS, history, message)
    except RuntimeError as exc:
        # Surfaces a clean error (e.g. missing GROQ_API_KEY, Groq API
        # failure) as a normal agent response instead of a 500, so a scan
        # against a misconfigured target fails obviously rather than
        # silently.
        return {"response": f"[agent error] {exc}", "tool_calls_made": [], "trace": [{"error": str(exc)}]}
    return {"response": response_text, "tool_calls_made": tool_calls_made, "trace": trace}


@app.get("/agent/_audit_log")
def _audit_log() -> dict[str, Any]:
    """Test-only introspection endpoint, matching native_server.py."""
    return {"entries": [{"kind": e.kind, **e.detail} for e in AUDIT_LOG.entries]}


@app.post("/agent/_reset")
def _reset() -> dict[str, Any]:
    AUDIT_LOG.reset()
    return {"status": "reset"}


@app.get("/agent/_meta")
def _meta() -> dict[str, Any]:
    """Small introspection endpoint for the dashboard/demo to show which
    mode this target is running in."""
    brain = get_brain()
    return {
        "hardened": isinstance(brain, PolicyEnforcingBrain),
        "backend": "groq",
    }


def main(argv: Optional[list[str]] = None) -> int:
    import uvicorn

    parser = argparse.ArgumentParser(
        description="Groq-backed Talos sample agent (real / hardened demo target)."
    )
    parser.add_argument("--port", type=int, default=8002)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--hardened", action="store_true", help="Enable the policy-enforcement backstop.")
    parser.add_argument("--model", default=DEFAULT_GROQ_MODEL, help="Groq model name.")
    args = parser.parse_args(argv)

    global _BRAIN
    try:
        _BRAIN = _build_brain(hardened=args.hardened, model=args.model)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    mode = "HARDENED" if args.hardened else "VULNERABLE"
    print(f"Starting real_agent_server in {mode} mode (model={args.model}) on {args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
