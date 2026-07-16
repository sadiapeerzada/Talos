"""Runs one AttackInstance against a TargetAgent (via any adapter) and
captures the full multi-turn trace."""

from __future__ import annotations

from pydantic import BaseModel, Field

from talos.attacks.models import AttackInstance
from talos.harness.base import AgentTurnResult, HistoryMessage, TargetAgent, ToolCallRecord


class ExecutionResult(BaseModel):
    attack: AttackInstance
    turns: list[AgentTurnResult] = Field(default_factory=list)

    def all_tool_calls(self) -> list[ToolCallRecord]:
        calls: list[ToolCallRecord] = []
        for turn in self.turns:
            calls.extend(turn.tool_calls_made)
        return calls


def execute_attack(agent: TargetAgent, attack: AttackInstance) -> ExecutionResult:
    turns: list[AgentTurnResult] = []
    history: list[HistoryMessage] = []
    for message in attack.messages:
        result = agent.send(message, history=history or None)
        turns.append(result)
        history.append(HistoryMessage(role="user", content=message))
        history.append(HistoryMessage(role="assistant", content=result.response))
    return ExecutionResult(attack=attack, turns=turns)
