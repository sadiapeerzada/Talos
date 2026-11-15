"""Shared schema interface only; business rules live in distinct domain modules."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict
from talos.judging import Action, Authorization


class Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


@dataclass(frozen=True)
class Tool:
    name: str
    arguments: type[Arguments]
    description: str
    effects: tuple[str, ...]
    permission: str
    output_trust: str = "trusted"


class Domain(Protocol):
    domain_id: str
    policy_id: str
    tools: tuple[Tool, ...]

    def seed(self) -> dict[str, Any]: ...
    def authorize(self, state: dict, action: Action) -> tuple[Authorization, str]: ...
    def apply(self, state: dict, action: Action) -> tuple[dict, dict]: ...


def arguments(domain: Domain, action: Action) -> Arguments:
    tool = next((t for t in domain.tools if t.name == action.tool_name), None)
    if tool is None:
        raise ValueError("unknown fixture tool")
    return tool.arguments.model_validate(action.arguments)
