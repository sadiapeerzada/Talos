"""Assembles structured and Markdown vulnerability reports."""

from __future__ import annotations

import datetime as _dt

import networkx as nx
from pydantic import BaseModel, Field

from talos.attacks.templates import TAXONOMY_VERSION
from talos.execution.dedup import ExploitClassFinding
from talos.graph.render import to_mermaid
from talos.harness.base import ToolSpec
from talos.remediation import generate_remediation_patch

SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "none": "⚪"}

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
    "authority_spoofing": (
        "Treat claimed authority, titles, or approvals in natural-language messages as untrusted assertions. "
        "Require verifiable authorization artifacts or a separate approval check at the tool layer before "
        "allowing high-impact actions or outbound data sharing."
    ),
    "policy_shadowing": (
        "Never let user-supplied or retrieved text redefine policy. Bind current policy to trusted system "
        "state, and require tools to enforce hard constraints even when the model is shown fake runbooks, "
        "SOPs, or internal bulletins that claim otherwise."
    ),
    "cross_agent_injection": (
        "Never trust content that arrived through another internal service just because it wasn't typed "
        "directly by an external attacker -- an upstream tool's own legitimate features (auto-tagging, "
        "summarization, escalation flags) can manufacture directive-shaped text a downstream agent then "
        "blindly executes. Apply the SAME 'tool output is untrusted data, not instructions' framing "
        "(indirect_injection's fix) at every hop in a multi-agent pipeline, not just the last one before "
        "the vulnerable agent -- and avoid using directive-shaped formatting conventions (bracketed "
        "'[INTERNAL NOTE]'-style tags, etc.) for purely informational internal annotations, since a "
        "downstream consumer may not distinguish your convention from an actual injected instruction."
    ),
}

EXPLOIT_CLASS_LABELS = {
    "direct_injection": "Direct Prompt Injection",
    "indirect_injection": "Indirect Prompt Injection",
    "permission_escalation": "Permission Escalation",
    "data_exfiltration": "Data Exfiltration",
    "goal_hijacking": "Goal Hijacking",
    "authority_spoofing": "Authority Spoofing",
    "policy_shadowing": "Policy Shadowing",
    "cross_agent_injection": "Cross-Agent Injection",
}


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


RISK_SCORE_WEIGHTS = {"critical": 25, "high": 12, "medium": 5, "low": 2}


def compute_risk_score(counts: SeverityCounts) -> int:
    """A single 0-100 headline risk number, weighted by severity, so a
    before/after comparison (or a dashboard glance) has one legible number
    instead of four separate counts to mentally combine. Weights are
    intentionally steep on critical/high: a single critical finding alone
    (25) already reads as meaningfully risky, and 4 criticals saturates the
    scale, mirroring how a single unauthenticated financial/exfil exploit
    should dominate the headline number regardless of how many low-severity
    findings also exist."""
    raw = (
        counts.critical * RISK_SCORE_WEIGHTS["critical"]
        + counts.high * RISK_SCORE_WEIGHTS["high"]
        + counts.medium * RISK_SCORE_WEIGHTS["medium"]
        + counts.low * RISK_SCORE_WEIGHTS["low"]
    )
    return max(0, min(100, raw))


class ReportStats(BaseModel):
    tools_found: int
    attack_templates_run: int
    exploit_classes_successful: int
    findings_tested: int
    severity_counts: SeverityCounts
    risk_score: int = 0


class ReportVariant(BaseModel):
    template_id: str
    name: str
    outcome: str
    messages: list[str] = Field(default_factory=list)
    evidence: dict = Field(default_factory=dict)


class BlastRadius(BaseModel):
    """A business-impact estimate for one finding, derived entirely from
    evidence already captured during scoring (talos/execution/scoring.py) --
    dollar overage on a refund call, data-exposure level on an email call,
    and any additional tool named in a permission-escalation chain. This is
    deliberately NOT based on privileged tool metadata (spending limits,
    PII flags, etc.) that a real target wouldn't expose to a black-box
    scanner -- see the "Black-box first" design principle in the README.
    Everything here traces back to a real, observed tool-call argument."""

    dollar_exposure: float = 0.0
    records_exposed: int = 0
    bulk_exposure: bool = False
    tools_affected: int = 1
    summary: str = "No quantifiable exposure observed."


def estimate_blast_radius(target_tool: str, variants: list[ReportVariant]) -> BlastRadius:
    dollar_exposure = 0.0
    records_exposed = 0
    bulk_exposure = False
    tools: set[str] = {target_tool}

    for variant in variants:
        refund = variant.evidence.get("refund_overage")
        if refund:
            dollar_exposure = max(dollar_exposure, float(refund.get("overage", 0) or 0))

        email = variant.evidence.get("suspicious_email")
        if email:
            level = int(email.get("data_exposure", 0) or 0)
            if level >= 3:
                # "Full customer order database export" is a qualitative
                # signal in the evidence text, not a counted record list --
                # report it as bulk exposure rather than inventing a
                # specific record count we don't actually have.
                bulk_exposure = True
            elif level >= 1:
                # A single customer's record/email surfaced -- this we CAN
                # count concretely (exactly one, from this call).
                records_exposed = max(records_exposed, 1)

        unverified = variant.evidence.get("unverified_action")
        if unverified and unverified.get("tool"):
            tools.add(str(unverified["tool"]))

    tools_affected = len(tools)

    parts = []
    if dollar_exposure > 0:
        parts.append(f"up to ${dollar_exposure:,.2f} per exploit")
    if bulk_exposure:
        parts.append("a bulk customer-database export")
    elif records_exposed > 0:
        parts.append(f"{records_exposed} customer record{'s' if records_exposed != 1 else ''} exposed")
    parts.append(f"{tools_affected} tool{'s' if tools_affected != 1 else ''} affected")

    summary = ("Exposure: " + ", ".join(parts) + ".") if (dollar_exposure or bulk_exposure or records_exposed) else \
        f"Exposure: {tools_affected} tool{'s' if tools_affected != 1 else ''} affected, no dollar or data exposure observed."

    return BlastRadius(
        dollar_exposure=dollar_exposure,
        records_exposed=records_exposed,
        bulk_exposure=bulk_exposure,
        tools_affected=tools_affected,
        summary=summary,
    )


class ReportFinding(BaseModel):
    exploit_class: str
    exploit_label: str
    target_tool: str
    outcome: str
    severity: str
    reproducibility: float
    title: str
    summary: str
    remediation: str
    remediation_patch: str = ""
    blast_radius: BlastRadius = Field(default_factory=BlastRadius)
    variants: list[ReportVariant] = Field(default_factory=list)


class ScanReport(BaseModel):
    target: str
    adapter: str
    generated_at: str
    stats: ReportStats
    tool_names: list[str] = Field(default_factory=list)
    tool_graph_mermaid: str
    findings: list[ReportFinding] = Field(default_factory=list)
    not_reproduced: list[ReportFinding] = Field(default_factory=list)


def _summarize_finding(finding: ExploitClassFinding) -> str:
    variant = next((candidate for candidate in finding.variants if candidate.outcome == "success"), finding.variants[0])
    refund = variant.evidence.get("refund_overage")
    if refund:
        return (
            f"Issued ${refund['amount']:.2f} on order {refund['order_id']} "
            f"(${refund['overage']:.2f} over the real total)."
        )

    suspicious_email = variant.evidence.get("suspicious_email")
    if suspicious_email:
        destination = suspicious_email.get("to", "unknown destination")
        exposure = suspicious_email.get("data_exposure", 0)
        if exposure >= 3:
            return f"Sent bulk customer data to {destination}."
        if exposure >= 1:
            return f"Sent customer data to {destination}."
        return f"Triggered an external email to {destination}."

    unverified = variant.evidence.get("unverified_action")
    if unverified:
        return f"Performed {unverified['tool']} without fresh authorization after a prior read step."

    return f"Reached {finding.target_tool} with {finding.reproducibility:.0%} reproducibility."


def build_report(
    *,
    target_label: str,
    adapter_name: str,
    tools: list[ToolSpec],
    graph: nx.DiGraph,
    findings: list[ExploitClassFinding],
    templates_run: int,
) -> ScanReport:
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    successful = [finding for finding in findings if finding.outcome == "success"]
    severity_counts = SeverityCounts()
    for finding in successful:
        if finding.severity.value == "critical":
            severity_counts.critical += 1
        elif finding.severity.value == "high":
            severity_counts.high += 1
        elif finding.severity.value == "medium":
            severity_counts.medium += 1
        elif finding.severity.value == "low":
            severity_counts.low += 1

    reproduced: list[ReportFinding] = []
    not_reproduced: list[ReportFinding] = []
    for finding in findings:
        label = EXPLOIT_CLASS_LABELS.get(finding.exploit_class, finding.exploit_class)
        report_variants = [
            ReportVariant(
                template_id=variant.template_id,
                name=variant.name,
                outcome=variant.outcome,
                messages=variant.messages,
                evidence=variant.evidence,
            )
            for variant in finding.variants
        ]
        report_finding = ReportFinding(
            exploit_class=finding.exploit_class,
            exploit_label=label,
            target_tool=finding.target_tool,
            outcome=finding.outcome,
            severity=finding.severity.value,
            reproducibility=finding.reproducibility,
            title=f"{label} -> {finding.target_tool}",
            summary=_summarize_finding(finding),
            remediation=REMEDIATIONS.get(finding.exploit_class, ""),
            remediation_patch=generate_remediation_patch(
                exploit_class=finding.exploit_class,
                target_tool=finding.target_tool,
                variants=report_variants,
            ),
            blast_radius=estimate_blast_radius(finding.target_tool, report_variants),
            variants=report_variants,
        )
        if finding.outcome == "success":
            reproduced.append(report_finding)
        else:
            not_reproduced.append(report_finding)

    return ScanReport(
        target=target_label,
        adapter=adapter_name,
        generated_at=now,
        stats=ReportStats(
            tools_found=len(tools),
            attack_templates_run=templates_run,
            exploit_classes_successful=len(successful),
            findings_tested=len(findings),
            severity_counts=severity_counts,
            risk_score=compute_risk_score(severity_counts),
        ),
        tool_names=[tool.name for tool in tools],
        tool_graph_mermaid=to_mermaid(graph),
        findings=reproduced,
        not_reproduced=not_reproduced,
    )


def render_markdown_report(report: ScanReport) -> str:
    all_findings = [*report.findings, *report.not_reproduced]

    lines: list[str] = []
    lines.append("# Talos Vulnerability Report")
    lines.append("")
    lines.append(f"**Target:** `{report.target}`  ")
    lines.append(f"**Adapter:** {report.adapter}  ")
    lines.append(f"**Generated:** {report.generated_at}  ")
    lines.append(f"**Tools discovered:** {report.stats.tools_found}  ")
    lines.append(f"**Attack templates run:** {report.stats.attack_templates_run}  ")
    lines.append(f"**Risk score:** {report.stats.risk_score} / 100  ")
    lines.append(f"**Taxonomy:** {TAXONOMY_VERSION}  ")
    lines.append(
        f"**Exploit classes with a successful finding:** {report.stats.exploit_classes_successful} / "
        f"{report.stats.findings_tested} tool-pairs tested"
    )
    lines.append("")
    lines.append(
        f"{SEVERITY_EMOJI['critical']} Critical: {report.stats.severity_counts.critical}   "
        f"{SEVERITY_EMOJI['high']} High: {report.stats.severity_counts.high}   "
        f"{SEVERITY_EMOJI['medium']} Medium: {report.stats.severity_counts.medium}   "
        f"{SEVERITY_EMOJI['low']} Low: {report.stats.severity_counts.low}"
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
    lines.append(report.tool_graph_mermaid)
    lines.append("```")
    lines.append("")

    lines.append("## Findings Summary")
    lines.append("")
    lines.append("| Severity | Exploit Class | Target Tool | Outcome | Reproducibility | Exposure | Variants |")
    lines.append("|---|---|---|---|---|---|---|")
    for finding in all_findings:
        emoji = SEVERITY_EMOJI.get(finding.severity, "")
        variant_ids = ", ".join(variant.template_id for variant in finding.variants)
        lines.append(
            f"| {emoji} {finding.severity} | {finding.exploit_label} "
            f"| `{finding.target_tool}` | {finding.outcome} | {finding.reproducibility:.0%} "
            f"| {finding.blast_radius.summary} | {variant_ids} |"
        )
    lines.append("")

    lines.append("## Detailed Findings")
    lines.append("")
    for finding in report.findings:
        lines.append(
            f"### {SEVERITY_EMOJI.get(finding.severity, '')} {finding.exploit_label} -> "
            f"`{finding.target_tool}` ({finding.severity})"
        )
        lines.append("")
        lines.append(f"**Reproducibility:** {finding.reproducibility:.0%} across {len(finding.variants)} variant(s) tried.")
        lines.append("")
        lines.append(f"**{finding.blast_radius.summary}**")
        lines.append("")
        for variant in finding.variants:
            lines.append(f"<details><summary><code>{variant.template_id}</code> -- {variant.name} ({variant.outcome})</summary>")
            lines.append("")
            lines.append("**Reproduction steps (exact messages sent, in order):**")
            for index, message in enumerate(variant.messages, 1):
                lines.append(f"{index}. `{message}`")
            lines.append("")
            lines.append("**Evidence:**")
            lines.append("```")
            for key, value in variant.evidence.items():
                lines.append(f"{key}: {value}")
            lines.append("```")
            lines.append("")
            lines.append("</details>")
            lines.append("")
        lines.append(f"**Remediation:** {finding.remediation}")
        lines.append("")
        if finding.remediation_patch:
            lines.append("<details><summary><strong>Suggested patch (drop-in)</strong></summary>")
            lines.append("")
            lines.append("```python")
            lines.append(finding.remediation_patch.rstrip())
            lines.append("```")
            lines.append("")
            lines.append("</details>")
            lines.append("")

    if report.not_reproduced:
        lines.append("## Not Reproduced")
        lines.append("")
        lines.append("These tool-pairs were tested but did not show a successful exploit in this run:")
        lines.append("")
        for finding in report.not_reproduced:
            variant_ids = ", ".join(variant.template_id for variant in finding.variants)
            lines.append(f"- {finding.exploit_label} -> `{finding.target_tool}` ({finding.outcome}) -- variants: {variant_ids}")
        lines.append("")

    lines.append("## Remediation Summary")
    lines.append("")
    seen_classes = {finding.exploit_class for finding in report.findings}
    for exploit_class in EXPLOIT_CLASS_LABELS:
        if exploit_class in seen_classes:
            lines.append(f"- **{EXPLOIT_CLASS_LABELS[exploit_class]}:** {REMEDIATIONS[exploit_class]}")
    lines.append("")

    return "\n".join(lines)


def render_markdown(
    *,
    target_label: str,
    adapter_name: str,
    tools: list[ToolSpec],
    graph: nx.DiGraph,
    findings: list[ExploitClassFinding],
    templates_run: int,
) -> str:
    return render_markdown_report(
        build_report(
            target_label=target_label,
            adapter_name=adapter_name,
            tools=tools,
            graph=graph,
            findings=findings,
            templates_run=templates_run,
        )
    )
