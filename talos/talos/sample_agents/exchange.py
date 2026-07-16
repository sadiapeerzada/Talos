"""Runs one (message -> final answer) exchange by repeatedly asking the
brain what to do next and executing whatever tool it picks, until it
returns a final answer or a safety step-cap is hit."""

from __future__ import annotations

from typing import Any

from talos.sample_agents.brain import Brain, Turn, ToolResult
from talos.sample_agents.tools import ToolDefinition

MAX_STEPS = 6


def run_exchange(
    brain: Brain,
    tool_defs: list[ToolDefinition],
    history: list[Turn],
    message: str,
    max_steps: int = MAX_STEPS,
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    """Returns (final_text, tool_calls_made, trace)."""
    tool_map = {t.name: t for t in tool_defs}
    available = list(tool_map.keys())
    scratch: list[ToolResult] = []
    tool_calls_made: list[dict[str, Any]] = []
    trace: list[dict[str, Any]] = []

    for step in range(max_steps):
        decision = brain.decide(history, message, scratch, available)
        trace.append({
            "step": step,
            "action": decision.action,
            "tool": decision.tool_name,
            "reason": decision.debug_reason,
        })
        if decision.action == "final":
            return decision.text or "", tool_calls_made, trace

        tool_def = tool_map.get(decision.tool_name)
        if tool_def is None:
            trace.append({"step": step, "error": f"unknown tool {decision.tool_name}"})
            return "Sorry, something went wrong.", tool_calls_made, trace

        try:
            result = tool_def.fn(**(decision.tool_args or {}))
        except Exception as exc:  # pragma: no cover - defensive only
            result = {"error": str(exc)}

        scratch.append(ToolResult(tool_name=decision.tool_name, result=result))
        tool_calls_made.append({
            "tool_name": decision.tool_name,
            "arguments": decision.tool_args or {},
            "result": result,
        })

    return "Sorry, I wasn't able to complete this request.", tool_calls_made, trace
