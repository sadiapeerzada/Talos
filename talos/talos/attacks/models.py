"""Data models for the attack-generation engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import networkx as nx
from pydantic import BaseModel, Field

EXPLOIT_CLASSES = (
    "direct_injection",
    "indirect_injection",
    "permission_escalation",
    "data_exfiltration",
    "goal_hijacking",
)


@dataclass
class AttackContext:
    """Everything a template needs to instantiate itself against a
    specific target: the discovered tool graph, plus a small set of
    known-valid test identifiers.

    In a real external engagement, `seed_order_ids` is exactly the kind of
    thing the tester supplies (the same way you'd hand a web-app scanner a
    valid logged-in session or a couple of known account IDs) -- Talos
    does not attempt to blindly guess valid order numbers in this phase.
    """

    graph: nx.DiGraph
    seed_order_ids: list[str] = field(default_factory=lambda: ["1001"])
    poisoned_order_ids: list[str] = field(default_factory=lambda: ["1002"])
    attacker_email: str = "collector@exfil-sink.example"


class AttackInstance(BaseModel):
    template_id: str
    exploit_class: str
    name: str
    target_tool: str
    messages: list[str] = Field(default_factory=list)  # sent in sequence; len 1 or 2
    notes: str = ""


@dataclass
class AttackTemplate:
    id: str
    exploit_class: str
    name: str
    description: str
    applies: Callable[[AttackContext], bool]
    instantiate: Callable[[AttackContext], list[AttackInstance]]
