"""Shared scan execution flow for the CLI and dashboard."""

from __future__ import annotations

from typing import Iterator

from pydantic import BaseModel

from talos.attacks.engine import generate_all
from talos.attacks.models import AttackContext
from talos.execution.dedup import deduplicate
from talos.execution.scoring import ScoredFinding, score_attack
from talos.graph.discovery import build_tool_graph
from talos.harness.base import TargetAgent
from talos.harness.langchain_adapter import LangChainAdapter
from talos.harness.native_adapter import NativeAdapter
from talos.reporting.report import ScanReport, build_report

ADAPTERS = {"langchain": LangChainAdapter, "native": NativeAdapter}

DEFAULT_SEED_ORDER_IDS = ["1001", "1003"]
DEFAULT_POISONED_ORDER_IDS = ["1002"]
DEFAULT_ATTACKER_EMAIL = "collector@exfil-sink.example"


class ProgressStats(BaseModel):
    tools_found: int = 0
    attacks_run: int = 0
    attacks_total: int = 0
    critical: int = 0
    high: int = 0


class ScanProgressEvent(BaseModel):
    type: str
    message: str
    stats: ProgressStats
    report: ScanReport | None = None
    latest_finding: ScoredFinding | None = None
    tool_names: list[str] | None = None
    exploit_classes: list[str] | None = None


def build_agent(adapter_name: str, target: str) -> TargetAgent:
    if adapter_name not in ADAPTERS:
        raise ValueError(f"Unknown adapter '{adapter_name}'. Choices: {list(ADAPTERS)}")
    agent = ADAPTERS[adapter_name](target)
    agent.connect()
    return agent


def _stats(*, tools_found: int = 0, attacks_run: int = 0, attacks_total: int = 0, report: ScanReport | None = None) -> ProgressStats:
    if report is None:
        return ProgressStats(tools_found=tools_found, attacks_run=attacks_run, attacks_total=attacks_total)
    return ProgressStats(
        tools_found=tools_found,
        attacks_run=attacks_run,
        attacks_total=attacks_total,
        critical=report.stats.severity_counts.critical,
        high=report.stats.severity_counts.high,
    )


def iter_scan_progress(
    *,
    target: str,
    adapter_name: str,
    seed_order_ids: list[str] | None = None,
    poisoned_order_ids: list[str] | None = None,
    attacker_email: str | None = None,
    repro_runs: int = 3,
) -> Iterator[ScanProgressEvent]:
    agent = build_agent(adapter_name, target)
    yield ScanProgressEvent(
        type="connected",
        message=f"Connected to {target} via the {adapter_name} adapter.",
        stats=_stats(),
    )

    tools = agent.list_tools()
    yield ScanProgressEvent(
        type="tools_discovered",
        message=f"Discovered {len(tools)} tools.",
        stats=_stats(tools_found=len(tools)),
        tool_names=[tool.name for tool in tools],
    )

    graph = build_tool_graph(tools)
    ctx = AttackContext(
        graph=graph,
        seed_order_ids=seed_order_ids or DEFAULT_SEED_ORDER_IDS,
        poisoned_order_ids=poisoned_order_ids or DEFAULT_POISONED_ORDER_IDS,
        attacker_email=attacker_email or DEFAULT_ATTACKER_EMAIL,
    )
    attacks = generate_all(ctx)
    exploit_classes = sorted({attack.exploit_class for attack in attacks})
    yield ScanProgressEvent(
        type="attacks_generated",
        message=f"Generated {len(attacks)} attack templates across {len(exploit_classes)} exploit classes.",
        stats=_stats(tools_found=len(tools), attacks_total=len(attacks)),
        exploit_classes=exploit_classes,
    )

    scored_findings: list[ScoredFinding] = []
    final_report: ScanReport | None = None
    for index, attack in enumerate(attacks, 1):
        latest_finding = score_attack(agent, attack, repro_runs=repro_runs)
        scored_findings.append(latest_finding)
        deduped_findings = deduplicate(scored_findings)
        final_report = build_report(
            target_label=target,
            adapter_name=adapter_name,
            tools=tools,
            graph=graph,
            findings=deduped_findings,
            templates_run=len(attacks),
        )
        yield ScanProgressEvent(
            type="attack_scored",
            message=f"Ran attack {index}/{len(attacks)}: {attack.name}.",
            stats=_stats(
                tools_found=len(tools),
                attacks_run=index,
                attacks_total=len(attacks),
                report=final_report,
            ),
            report=final_report,
            latest_finding=latest_finding,
        )

    if final_report is None:
        final_report = build_report(
            target_label=target,
            adapter_name=adapter_name,
            tools=tools,
            graph=graph,
            findings=[],
            templates_run=0,
        )

    yield ScanProgressEvent(
        type="completed",
        message="Scan complete.",
        stats=_stats(
            tools_found=len(tools),
            attacks_run=len(attacks),
            attacks_total=len(attacks),
            report=final_report,
        ),
        report=final_report,
    )


def run_scan_pipeline(
    *,
    target: str,
    adapter_name: str,
    seed_order_ids: list[str] | None = None,
    poisoned_order_ids: list[str] | None = None,
    attacker_email: str | None = None,
    repro_runs: int = 3,
) -> tuple[ScanReport, list[ScanProgressEvent]]:
    events = list(
        iter_scan_progress(
            target=target,
            adapter_name=adapter_name,
            seed_order_ids=seed_order_ids,
            poisoned_order_ids=poisoned_order_ids,
            attacker_email=attacker_email,
            repro_runs=repro_runs,
        )
    )
    final_report = next(event.report for event in reversed(events) if event.report is not None)
    return final_report, events
