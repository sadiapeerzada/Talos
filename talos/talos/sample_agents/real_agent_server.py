"""
Sample "real" customer-service agent -- backed by an actual external LLM
instead of the deterministic rule-based fixture used by native_server.py /
langchain_server.py.

This exists to prove Talos generalizes: it wasn't written against this
agent's prompt or decision logic, so a scan finding something here is
evidence Talos works on targets it has never seen, not just on its own
fixtures. Because the brain talks to any OpenAI-compatible endpoint (see
groq_brain.py), the SAME scan can be repeated against Groq, OpenAI, or a
fully local Ollama model with nothing but a --provider flag change --
further evidence Talos isn't tuned to one vendor's quirks either.

Two modes:
  --hardened not set : vulnerable mode. Uses the raw LLM brain directly.
                        Whatever the model decides is executed as-is (same
                        posture as the built-in vulnerable sample agents).
  --hardened set      : hardened mode. Wraps the LLM brain in
                        PolicyEnforcingBrain (see policy.py), which adds a
                        hardened system prompt AND a deterministic
                        backstop: refund amounts are capped to the real
                        order total, emails to non-allow-listed domains are
                        never sent, and sensitive actions require a fresh,
                        explicit confirmation.

Setup (pick one provider):
    groq   (default, free, cloud) -- https://console.groq.com/keys
        export GROQ_API_KEY=your_key_here
    openai (paid, cloud)          -- https://platform.openai.com/api-keys
        export OPENAI_API_KEY=your_key_here
    ollama (free, fully local)    -- https://ollama.com/download
        ollama pull llama3.1 && ollama serve   # no API key needed

Run:
    python -m talos.sample_agents.real_agent_server --port 8002
    python -m talos.sample_agents.real_agent_server --port 8003 --hardened
    python -m talos.sample_agents.real_agent_server --port 8004 --provider openai
    python -m talos.sample_agents.real_agent_server --port 8005 --provider ollama --model llama3.1

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
from talos.sample_agents.groq_brain import DEFAULT_PROVIDER, PROVIDER_PRESETS, LLMBrain
from talos.sample_agents.policy import PolicyEnforcingBrain
from talos.sample_agents.brain import Brain, Turn
from talos.sample_agents.tools import ToolDefinition, make_tool_definitions

AUDIT_LOG = AuditLog()
TOOL_DEFS: list[ToolDefinition] = make_tool_definitions(AUDIT_LOG)

app = FastAPI(title="Talos sample agent (real / LLM-backed)")

# Populated in main() once we know --hardened / --provider / --model from
# argv, but also built eagerly here with defaults so
# `uvicorn talos.sample_agents.real_agent_server:app` works directly too.
_BRAIN: Optional[Brain] = None
_META: dict[str, Any] = {"provider": DEFAULT_PROVIDER, "model": None, "hardened": False}


def _build_brain(hardened: bool, provider: str, model: Optional[str]) -> Brain:
    llm = LLMBrain(provider=provider, model=model, hardened=hardened, tool_defs=TOOL_DEFS)
    return PolicyEnforcingBrain(llm) if hardened else llm


def get_brain() -> Brain:
    global _BRAIN
    if _BRAIN is None:
        _BRAIN = _build_brain(hardened=False, provider=DEFAULT_PROVIDER, model=None)
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
    mode and provider this target is running in."""
    brain = get_brain()
    return {
        "hardened": isinstance(brain, PolicyEnforcingBrain),
        "provider": _META["provider"],
        "model": _META["model"],
    }


def main(argv: Optional[list[str]] = None) -> int:
    import uvicorn

    parser = argparse.ArgumentParser(
        description="Real LLM-backed Talos sample agent (real / hardened demo target)."
    )
    parser.add_argument("--port", type=int, default=8002)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--hardened", action="store_true", help="Enable the policy-enforcement backstop.")
    parser.add_argument(
        "--provider",
        default=DEFAULT_PROVIDER,
        choices=list(PROVIDER_PRESETS),
        help="Which OpenAI-compatible provider to use.",
    )
    parser.add_argument("--model", default=None, help="Model name override (defaults to the provider's preset).")
    args = parser.parse_args(argv)

    global _BRAIN, _META
    try:
        _BRAIN = _build_brain(hardened=args.hardened, provider=args.provider, model=args.model)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    resolved_model = args.model or PROVIDER_PRESETS[args.provider].default_model
    _META = {"provider": args.provider, "model": resolved_model, "hardened": args.hardened}

    mode = "HARDENED" if args.hardened else "VULNERABLE"
    print(
        f"Starting real_agent_server in {mode} mode "
        f"(provider={args.provider}, model={resolved_model}) on {args.host}:{args.port}"
    )
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
