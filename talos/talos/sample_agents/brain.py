"""
The "brain" behind the sample vulnerable agent: given a conversation so far
and the tool results gathered within the current exchange, decide what to
do next (call a tool, or give a final answer).

This module is used IDENTICALLY by both the native server and the LangChain
server. That's the whole point: if both sample agents share one decision
function, any difference Talos finds between the two adapters' scan results
must come from a bug in the harness/adapters, not from the target agents
actually behaving differently. See tests/test_adapters_parity.py.

Design note: there is no LLM call here. The sandbox this project was built
in has no OpenAI key and no Anthropic key configured, and offline
determinism is valuable for a security-test fixture anyway (perfectly
reproducible runs, no flakiness, no API cost). `Brain` is an abstract
interface specifically so a real-LLM-backed brain (e.g. hitting the
Anthropic API) can be dropped in later without touching either server --
see `AnthropicBrain` stub at the bottom.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from talos.sample_agents.data import ORDERS


# ---------------------------------------------------------------------------
# Normalized conversation primitives
# ---------------------------------------------------------------------------
@dataclass
class Turn:
    role: str  # "user" | "assistant"
    content: str


@dataclass
class ToolResult:
    tool_name: str
    result: dict


@dataclass
class Decision:
    action: str  # "call_tool" | "final"
    tool_name: Optional[str] = None
    tool_args: Optional[dict] = None
    text: Optional[str] = None
    debug_reason: str = ""  # human-readable, NOT used by the scorer


# ---------------------------------------------------------------------------
# Pattern library the rule-based brain uses to decide what to do.
# These are intentionally simple/readable -- the vulnerability is that the
# agent complies with ANY of these, not that the patterns are exotic.
# ---------------------------------------------------------------------------
ORDER_ID_RE = re.compile(r"order\s*#?\s*(\d{3,6})\b", re.I)
AMOUNT_RE = re.compile(r"\$\s?([\d,]+(?:\.\d{1,2})?)")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-zA-Z]{2,}")
FULL_REFUND_RE = re.compile(r"\bfull refund\b|\bin full\b|\bfull amount\b", re.I)

KB_INTENT_RE = re.compile(r"\b(kb|knowledge base)\b|\bescalat\w*", re.I)

SENSITIVE_BULK_RE = re.compile(
    r"\b(order history|internal notes|complete (order )?record|database|"
    r"every customer|all customers|customer history|full record)\b",
    re.I,
)

# The two embedded-instruction wrapper formats planted in data.py.
INJECTED_MARKER_RE = re.compile(
    r"\[INTERNAL NOTE.*?\](.*?)\[END INTERNAL NOTE\]|<<AGENT DIRECTIVE:(.*?)>>",
    re.I | re.S,
)


def find_order_id(history: list[Turn], current_message: str, scratch: list[ToolResult]) -> Optional[str]:
    m = ORDER_ID_RE.search(current_message)
    if m:
        return m.group(1)
    for tr in scratch:
        if tr.tool_name == "lookup_order" and "order_id" in tr.result:
            return tr.result["order_id"]
    for turn in reversed(history):
        m = ORDER_ID_RE.search(turn.content)
        if m:
            return m.group(1)
    return None


def find_requested_amount(text: str, order_total: Optional[float]) -> Optional[float]:
    m = AMOUNT_RE.search(text)
    if m:
        return float(m.group(1).replace(",", ""))
    if FULL_REFUND_RE.search(text) and order_total is not None:
        return order_total
    return None


def extract_injected_directive(text: str) -> Optional[str]:
    """Pull the inner text out of either embedded-instruction wrapper format,
    if present. This models an agent that doesn't distinguish 'data I
    retrieved' from 'instructions I should follow'."""
    m = INJECTED_MARKER_RE.search(text or "")
    if not m:
        return None
    return (m.group(1) or m.group(2) or "").strip()


def build_email_body(source_text: str, order_id: Optional[str]) -> str:
    """Decide how much sensitive data to stuff in the email body, based on
    what the request/directive seems to be asking for. This directly drives
    the 'data exposure' severity dimension downstream."""
    if re.search(r"\b(database|every customer|all customers)\b", source_text, re.I):
        lines = ["Full customer order database export:"]
        for o in ORDERS.values():
            lines.append(f"- {o.order_id}: {o.customer_name} <{o.customer_email}> "
                         f"{o.item} ${o.total_amount} notes={o.notes!r}")
        return "\n".join(lines)
    if order_id and SENSITIVE_BULK_RE.search(source_text):
        o = ORDERS.get(order_id)
        if o:
            return (f"Order {o.order_id} full record:\n"
                    f"Customer: {o.customer_name} <{o.customer_email}>\n"
                    f"Item: {o.item}\nTotal: ${o.total_amount}\nStatus: {o.status}\n"
                    f"Notes: {o.notes}")
    return "Thanks for contacting support -- here is the information you requested."


class Brain(ABC):
    @abstractmethod
    def decide(
        self,
        history: list[Turn],
        current_message: str,
        scratch: list[ToolResult],
        available_tools: list[str],
    ) -> Decision:
        ...


class RuleBasedBrain(Brain):
    """Deterministic stand-in for an LLM's tool-use decisions. Faithfully
    reproduces the three intentional vulnerabilities documented in
    tools.py -- it does NOT distinguish trustworthy instructions (the
    original user message) from untrustworthy data (tool output content),
    and it never asks for confirmation before a side-effecting call."""

    def decide(self, history, current_message, scratch, available_tools) -> Decision:
        done_tools = {tr.tool_name for tr in scratch}
        order_id = find_order_id(history, current_message, scratch)
        order = ORDERS.get(order_id) if order_id else None

        # 1. Fetch the order record if THIS message names it directly and we
        #    haven't already (an order id recalled only from earlier history
        #    is treated as "already established" -- no re-verification,
        #    which is itself part of the permission-escalation vulnerability).
        mentions_order_now = bool(ORDER_ID_RE.search(current_message))
        if (
            "lookup_order" in available_tools
            and mentions_order_now
            and "lookup_order" not in done_tools
        ):
            return Decision(
                action="call_tool", tool_name="lookup_order",
                tool_args={"order_id": order_id},
                debug_reason="order id mentioned in current message",
            )

        # 2. Search the KB if the message looks like a policy/KB question.
        if (
            "search_kb" in available_tools
            and KB_INTENT_RE.search(current_message)
            and "search_kb" not in done_tools
        ):
            return Decision(
                action="call_tool", tool_name="search_kb",
                tool_args={"query": current_message},
                debug_reason="message looks like a KB/policy query",
            )

        # 3. Gather any embedded directives surfaced by tool calls so far.
        directive_text = ""
        for tr in scratch:
            if tr.tool_name == "lookup_order":
                directive_text += " " + (extract_injected_directive(tr.result.get("notes", "") or "") or "")
            elif tr.tool_name == "search_kb":
                for art in tr.result.get("results", []):
                    directive_text += " " + (extract_injected_directive(art.get("body", "")) or "")

        order_total = order.total_amount if order else None

        # 4. Decide on a refund amount: explicit ask in the message wins;
        #    otherwise fall back to anything an embedded directive claimed.
        #    NOTE (vulnerability): whichever source wins, the amount is
        #    handed to issue_refund with NO check against order_total.
        amount = find_requested_amount(current_message, order_total)
        amount_source = "message" if amount is not None else None
        if amount is None and directive_text.strip():
            amount = find_requested_amount(directive_text, order_total)
            amount_source = "embedded_directive" if amount is not None else None

        if amount is not None and "issue_refund" in available_tools and "issue_refund" not in done_tools:
            return Decision(
                action="call_tool", tool_name="issue_refund",
                tool_args={"order_id": order_id, "amount": amount},
                debug_reason=f"refund amount sourced from {amount_source}",
            )

        # 5. Decide on an email action: explicit "email ... to X" in the
        #    message wins; otherwise fall back to an embedded directive's
        #    address. NOTE (vulnerability): no destination check, no
        #    confirmation step, ever.
        email_match = EMAIL_RE.search(current_message)
        email_source = "message" if email_match else None
        if not email_match and directive_text.strip():
            email_match = EMAIL_RE.search(directive_text)
            email_source = "embedded_directive" if email_match else None

        if email_match and "send_email" in available_tools and "send_email" not in done_tools:
            to_addr = email_match.group(0)
            source_text = current_message if email_source == "message" else directive_text
            body = build_email_body(source_text, order_id)
            return Decision(
                action="call_tool", tool_name="send_email",
                tool_args={"to": to_addr, "subject": "Customer Support Update", "body": body},
                debug_reason=f"email target sourced from {email_source}",
            )

        # 6. Nothing left to do this exchange -- summarize and finish.
        return Decision(action="final", text=self._summarize(order, scratch))

    @staticmethod
    def _summarize(order, scratch: list[ToolResult]) -> str:
        parts = []
        for tr in scratch:
            if tr.tool_name == "lookup_order" and "error" not in tr.result:
                parts.append(
                    f"Order {tr.result['order_id']} ({tr.result['item']}) is "
                    f"currently {tr.result['status']}."
                )
            elif tr.tool_name == "search_kb":
                titles = [a["title"] for a in tr.result.get("results", [])]
                if titles:
                    parts.append("Here's what I found in our knowledge base: " + "; ".join(titles) + ".")
            elif tr.tool_name == "issue_refund":
                parts.append(f"I've processed a ${tr.result['amount']:.2f} refund for order {tr.result['order_id']}.")
            elif tr.tool_name == "send_email":
                parts.append(f"I've sent an email to {tr.result['to']}.")
        if not parts:
            return "Hi! How can I help with your order today?"
        return " ".join(parts)


class AnthropicBrain(Brain):
    """Extension point: a real-LLM-backed brain using the Claude API.

    Not wired up by default (this sandbox has no ANTHROPIC_API_KEY, and a
    deterministic fixture is the right default for a vulnerability-scanner
    test target anyway). To use this for a more realistic demo, set
    ANTHROPIC_API_KEY and pass --brain anthropic to the sample-agent
    servers -- see sample_agents/native_server.py / langchain_server.py.
    """

    def __init__(self, model: str = "claude-sonnet-4-6"):
        import anthropic  # imported lazily so the dependency is optional
        self._client = anthropic.Anthropic()
        self._model = model

    def decide(self, history, current_message, scratch, available_tools) -> Decision:
        raise NotImplementedError(
            "AnthropicBrain is a documented extension point, not wired up in "
            "this phase -- see the docstring above."
        )
