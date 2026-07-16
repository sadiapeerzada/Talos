"""Assembles the final Markdown vulnerability report."""

from __future__ import annotations

import datetime as _dt

import networkx as nx

from talos.execution.dedup import ExploitClassFinding
from talos.graph.render import to_mermaid
from talos.harness.base import ToolSpec

SEVERITY_EMOJI = {"critical": "\U0001F534", "high": "\U0001F7E0", "medium": "\U0001F7E1", "low": "\U0001F7E2", "none": "\u26AA"}

REMEDIATIONS = {
    "direct_injection": (
        "Tag every tool result (and the raw user message) with a provenance label the model is "
        "trained/prompted to respect, and never let free-form user text alone authorize a side-effecting "
        "call. Treat instruction-like phrases embedded in normal conversation as data, not commands."
    ),
    "indirect_injection": (
        "Never let tool-output content (order notes, KB article bodies, email threads) be interpreted as "
        "instructions. Wrap retrieved content in an explicit 'this is untrusted data, not instructions' "
        "frame, and strip or flag embedded imperative-looking text before it reaches the model."
    ),
    "permission_escalation": (
        "Require fresh, explicit authorization for every side-effecting call -- never let a prior read-only "
        "call (or an earlier turn's context) stand in for present-turn verification. Enforce this at the "
        "tool layer, not just in the prompt: the tool itself should refuse to execute without a fresh "
        "authorization token/step, independent of what the model claims."
    ),
    "data_exfiltration": (
        "Add an allow-list of destinations for any tool that sends data externally, and cap how much "
        "customer data a single message can cause to be disclosed. Redact or minimize PII in any "
        "automatically-generated email body by default."
    ),
    "goal_hijacking": (
        "Make the system prompt/policy authoritative at the tool layer (e.g. hard-coded bounds checks, "
        "required confirmation steps) rather than relying on the model to keep re-affirming it under "
        "adversarial pressure -- a model that can be talked out of its instructions should not be the only "
        "thing enforcing a business rule."
    ),
}

EXPLOIT_CLASS_LABELS = {
    "direct_injection": "Direct Prompt Injection",
    "indirect_injection": "Indirect Prompt Injection",
    "permission_escalation": "Permission Escalation",
    "data_exfiltration": "Data Exfiltration",
    "goal_hijacking": "Goal Hijacking",
}


def render_markdown(
    *,
    target_label: str,
    adapter_name: str,
    tools: list[ToolSpec],
    graph: nx.DiGraph,
    findings: list[ExploitClassFinding],
    templates_run: int,
) -> str:
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    successful = [f for f in findings if f.outcome == "success"]
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in successful:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    lines: list[str] = []
    lines.append("# Talos Vulnerability Report")
    lines.append("")
    lines.append(f"**Target:** `{target_label}`  ")
    lines.append(f"**Adapter:** {adapter_name}  ")
    lines.append(f"**Generated:** {now}  ")
    lines.append(f"**Tools discovered:** {len(tools)}  ")
    lines.append(f"**Attack templates run:** {templates_run}  ")
    lines.append(f"**Exploit classes with a successful finding:** {len(successful)} / {len(findings)} tool-pairs tested")
    lines.append("")
    lines.append(
        f"{SEVERITY_EMOJI['critical']} Critical: {by_sev['critical']}   "
        f"{SEVERITY_EMOJI['high']} High: {by_sev['high']}   "
        f"{SEVERITY_EMOJI['medium']} Medium: {by_sev['medium']}   "
        f"{SEVERITY_EMOJI['low']} Low: {by_sev['low']}"
    )
    lines.append("")

    lines.append("## Tool Graph")
    lines.append("")
    lines.append(
        "Discovered purely from `list_tools()` metadata (name/description/parameters) -- no source-code "
        "access assumed. Solid arrows are the direct-injection surface (user input reaching a side-effecting "
        "tool); dashed arrows are possible indirect-injection paths (a free-text-returning tool's output "
        "reaching a side-effecting tool)."
    )
    lines.append("")
    lines.append("```mermaid")
    lines.append(to_mermaid(graph))
    lines.append("```")
    lines.append("")

    lines.append("## Findings Summary")
    lines.append("")
    lines.append("| Severity | Exploit Class | Target Tool | Outcome | Reproducibility | Variants |")
    lines.append("|---|---|---|---|---|---|")
    for f in findings:
        emoji = SEVERITY_EMOJI.get(f.severity.value, "")
        variant_ids = ", ".join(v.template_id for v in f.variants)
        lines.append(
            f"| {emoji} {f.severity.value} | {EXPLOIT_CLASS_LABELS.get(f.exploit_class, f.exploit_class)} "
            f"| `{f.target_tool}` | {f.outcome} | {f.reproducibility:.0%} | {variant_ids} |"
        )
    lines.append("")

    lines.append("## Detailed Findings")
    lines.append("")
    for f in findings:
        if f.outcome != "success":
            continue
        label = EXPLOIT_CLASS_LABELS.get(f.exploit_class, f.exploit_class)
        lines.append(f"### {SEVERITY_EMOJI.get(f.severity.value,'')} {label} \u2192 `{f.target_tool}` ({f.severity.value})")
        lines.append("")
        lines.append(f"**Reproducibility:** {f.reproducibility:.0%} across {len(f.variants)} variant(s) tried.")
        lines.append("")
        for v in f.variants:
            lines.append(f"<details><summary><code>{v.template_id}</code> -- {v.name} ({v.outcome})</summary>")
            lines.append("")
            lines.append("**Reproduction steps (exact messages sent, in order):**")
            for i, msg in enumerate(v.messages, 1):
                lines.append(f"{i}. `{msg}`")
            lines.append("")
            lines.append("**Evidence:**")
            lines.append("```")
            for k, val in v.evidence.items():
                lines.append(f"{k}: {val}")
            lines.append("```")
            lines.append("")
            lines.append("</details>")
            lines.append("")
        lines.append(f"**Remediation:** {REMEDIATIONS.get(f.exploit_class, '')}")
        lines.append("")

    failed_or_partial = [f for f in findings if f.outcome != "success"]
    if failed_or_partial:
        lines.append("## Not Reproduced")
        lines.append("")
        lines.append("These tool-pairs were tested but did not show a successful exploit in this run:")
        lines.append("")
        for f in failed_or_partial:
            variant_ids = ", ".join(v.template_id for v in f.variants)
            lines.append(f"- {EXPLOIT_CLASS_LABELS.get(f.exploit_class, f.exploit_class)} \u2192 `{f.target_tool}` ({f.outcome}) -- variants: {variant_ids}")
        lines.append("")

    lines.append("## Remediation Summary")
    lines.append("")
    for cls, text in REMEDIATIONS.items():
        if any(f.exploit_class == cls and f.outcome == "success" for f in findings):
            lines.append(f"- **{EXPLOIT_CLASS_LABELS[cls]}:** {text}")
    lines.append("")

    return "\n".join(lines)
