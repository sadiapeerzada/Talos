"""
The common interface every adapter normalizes its target agent into.
Everything downstream of the harness (graph discovery, attack execution,
scoring, reporting) only ever talks to a `TargetAgent` -- it never knows or
cares whether the concrete agent underneath is a LangChain agent, a native
function-calling loop, or something else entirely.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from pydantic import BaseModel, Field


class ToolParameter(BaseModel):
    name: str
    type: str = "string"
    description: str = ""
    required: bool = True


class ToolSpec(BaseModel):
    name: str
    description: str
    parameters: list[ToolParameter] = Field(default_factory=list)


class ToolCallRecord(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: Any = None


class AgentTurnResult(BaseModel):
    response: str
    tool_calls_made: list[ToolCallRecord] = Field(default_factory=list)
    trace: list[dict[str, Any]] = Field(default_factory=list)


class HistoryMessage(BaseModel):
    role: str  # "user" | "assistant"
    content: str


class TargetAgent(ABC):
    """Abstract interface implemented by every adapter."""

    @abstractmethod
    def connect(self) -> None:
        """Establish/verify connectivity to the target. Should raise on
        failure rather than silently continuing."""

    @abstractmethod
    def list_tools(self) -> list[ToolSpec]:
        """Return the target's tool inventory, normalized to ToolSpec."""

    @abstractmethod
    def send(self, message: str, history: Optional[list[HistoryMessage]] = None) -> AgentTurnResult:
        """Send one user message (optionally with prior-turn history) and
        get back the final response plus every tool call the target made
        while producing it."""
