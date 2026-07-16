"""
Static classifier: given only a ToolSpec (name, description, parameters --
exactly what `list_tools()` returns from a black-box target, no source code
required), infer:

  - side_effect: what category of consequence calling this tool has
  - permission_level: how much authority that implies
  - is_free_text_source: whether this tool's *output* plausibly contains
    free text that a careless agent might parse as instructions rather
    than data (the indirect-injection surface)
  - has_free_text_sink: whether this tool's *input* accepts a free-text
    parameter that could carry attacker content onward

These are heuristics over the tool's declared name/description/parameter
text -- exactly the information available to a real black-box scan, no
peeking at the target's source.
"""

from __future__ import annotations

from enum import Enum

from talos.harness.base import ToolSpec


class SideEffect(str, Enum):
    READ_ONLY = "read_only"
    FINANCIAL = "financial"
    EXTERNAL_COMM = "external_comm"


class PermissionLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


FINANCIAL_KEYWORDS = ("refund", "charge", "payment", "pay", "transfer", "credit", "debit", "billing")
EXTERNAL_COMM_KEYWORDS = ("email", "send", "notify", "post", "publish", "message", "sms", "webhook")
FREE_TEXT_SOURCE_HINTS = ("notes", "article", "articles", "body", "description", "content", "comment", "message", "history")
FREE_TEXT_PARAM_NAMES = ("body", "notes", "content", "message", "text", "description", "comment")


def classify_side_effect(tool: ToolSpec) -> SideEffect:
    text = f"{tool.name} {tool.description}".lower()
    if any(k in text for k in FINANCIAL_KEYWORDS):
        return SideEffect.FINANCIAL
    if any(k in text for k in EXTERNAL_COMM_KEYWORDS):
        return SideEffect.EXTERNAL_COMM
    return SideEffect.READ_ONLY


def classify_permission_level(side_effect: SideEffect) -> PermissionLevel:
    if side_effect == SideEffect.FINANCIAL:
        return PermissionLevel.HIGH
    if side_effect == SideEffect.EXTERNAL_COMM:
        return PermissionLevel.MEDIUM
    return PermissionLevel.LOW


def is_free_text_source(tool: ToolSpec) -> bool:
    """Does this tool's declared description suggest it returns free text
    an attacker could have influenced (order notes, KB article bodies,
    email threads, etc)?"""
    text = tool.description.lower()
    return any(h in text for h in FREE_TEXT_SOURCE_HINTS)


def has_free_text_sink(tool: ToolSpec) -> bool:
    """Does this tool accept a parameter that could carry attacker content
    onward (e.g. an email body)?"""
    return any(p.name.lower() in FREE_TEXT_PARAM_NAMES for p in tool.parameters)
