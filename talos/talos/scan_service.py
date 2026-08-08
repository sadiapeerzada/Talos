"""Shared scan execution flow for the CLI and dashboard."""

from __future__ import annotations

from typing import Iterator

from pydantic import BaseModel

from talos.attacks.engine import DEFAULT_BATCH_SIZE, generate_all, generate_next_round
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
DEFAULT_GENERATION_STRATEGY = "template"
GENERATION_STRATEGIES = ("template", "adaptive")


class ProgressStats(BaseModel):
    tools_found: int = 0
    attacks_run: int = 0
    attacks_total: int = 0
    critical: int = 0
    high: int = 0
    risk_score: int = 0


class ScanProgressEvent(BaseModel):
    type: str
    message: str
    stats: ProgressStats
    report: ScanReport | None = None
    latest_finding: ScoredFinding | None = None
    tool_names: list[str] | None = None
    exploit_classes: list[str] | None = None
    generation_strategy: str | None = None


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
        risk_score=report.stats.risk_score,
    )


def iter_scan_progress(
    *,
    target: str,
    adapter_name: str,
    seed_order_ids: list[str] | None = None,
    poisoned_order_ids: list[str] | None = None,
    attacker_email: str | None = None,
    repro_runs: int = 3,
    generation_strategy: str = DEFAULT_GENERATION_STRATEGY,
    attack_model: str = "claude-sonnet-4-5",
) -> Iterator[ScanProgressEvent]:
    if generation_strategy not in GENERATION_STRATEGIES:
        raise ValueError(f"Unknown generation strategy '{generation_strategy}'. Choices: {list(GENERATION_STRATEGIES)}")

    agent = build_agent(adapter_name, target)
    yield ScanProgressEvent(
        type="connected",
        message=f"Connected to {target} via the {adapter_name} adapter.",
        stats=_stats(),
        generation_strategy=generation_strategy,
    )

    tools = agent.list_tools()
    yield ScanProgressEvent(
        type="tools_discovered",
        message=f"Discovered {len(tools)} tools.",
        stats=_stats(tools_found=len(tools)),
        tool_names=[tool.name for tool in tools],
        generation_strategy=generation_strategy,
    )

    graph = build_tool_graph(tools)
    ctx = AttackContext(
        graph=graph,
        seed_order_ids=seed_order_ids or DEFAULT_SEED_ORDER_IDS,
        poisoned_order_ids=poisoned_order_ids or DEFAULT_POISONED_ORDER_IDS,
        attacker_email=attacker_email or DEFAULT_ATTACKER_EMAIL,
        generation_strategy=generation_strategy,
        attack_model=attack_model,
    )

    preview_attacks = generate_all(
        AttackContext(
            graph=graph,
            seed_order_ids=ctx.seed_order_ids,
            poisoned_order_ids=ctx.poisoned_order_ids,
            attacker_email=ctx.attacker_email,
            generation_strategy="template",
            attack_model=attack_model,
        )
    )
    exploit_classes = sorted({attack.exploit_class for attack in preview_attacks})
    yield ScanProgressEvent(
        type="attacks_generated",
        message=(
            f"Prepared {len(preview_attacks)} base attack templates across {len(exploit_classes)} exploit classes "
            f"using the {generation_strategy} strategy."
        ),
        stats=_stats(tools_found=len(tools), attacks_total=len(preview_attacks)),
        exploit_classes=exploit_classes,
        generation_strategy=generation_strategy,
    )

    scored_findings: list[ScoredFinding] = []
    final_report: ScanReport | None = None
    attacks_run = 0
    attacks_total = len(preview_attacks)
    while True:
        batch = generate_next_round(scored_findings, ctx, batch_size=DEFAULT_BATCH_SIZE)
        if not batch:
            break

        attacks_total = max(attacks_total, attacks_run + len(batch))
        for attack in batch:
            latest_finding = score_attack(agent, attack, repro_runs=repro_runs)
            scored_findings.append(latest_finding)
            attacks_run += 1
            attacks_total = max(attacks_total, attacks_run)
            deduped_findings = deduplicate(scored_findings)
            final_report = build_report(
                target_label=target,
                adapter_name=adapter_name,
                tools=tools,
                graph=graph,
                findings=deduped_findings,
                templates_run=attacks_run,
            )
            yield ScanProgressEvent(
                type="attack_scored",
                message=f"Ran attack {attacks_run}/{attacks_total}: {attack.name}.",
                stats=_stats(
                    tools_found=len(tools),
                    attacks_run=attacks_run,
                    attacks_total=attacks_total,
                    report=final_report,
                ),
                report=final_report,
                latest_finding=latest_finding,
                generation_strategy=generation_strategy,
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
            attacks_run=attacks_run,
            attacks_total=attacks_total,
            report=final_report,
        ),
        report=final_report,
        generation_strategy=generation_strategy,
    )


def run_scan_pipeline(
    *,
    target: str,
    adapter_name: str,
    seed_order_ids: list[str] | None = None,
    poisoned_order_ids: list[str] | None = None,
    attacker_email: str | None = None,
    repro_runs: int = 3,
    generation_strategy: str = DEFAULT_GENERATION_STRATEGY,
    attack_model: str = "claude-sonnet-4-5",
) -> tuple[ScanReport, list[ScanProgressEvent]]:
    events = list(
        iter_scan_progress(
            target=target,
            adapter_name=adapter_name,
            seed_order_ids=seed_order_ids,
            poisoned_order_ids=poisoned_order_ids,
            attacker_email=attacker_email,
            repro_runs=repro_runs,
            generation_strategy=generation_strategy,
            attack_model=attack_model,
        )
    )
    final_report = next(event.report for event in reversed(events) if event.report is not None)
    return final_report, events
