"""talos-scan CLI: wires the full pipeline end to end.

    talos-scan --target http://localhost:8000/agent --adapter langchain
    talos-scan --target http://localhost:8001/agent --adapter native
"""

from __future__ import annotations

import argparse
import sys

from talos.attacks.engine import generate_all
from talos.attacks.models import AttackContext
from talos.execution.dedup import deduplicate
from talos.execution.scoring import score_attack
from talos.graph.discovery import build_tool_graph
from talos.harness.base import TargetAgent
from talos.harness.langchain_adapter import LangChainAdapter
from talos.harness.native_adapter import NativeAdapter
from talos.reporting.report import render_markdown

ADAPTERS = {"langchain": LangChainAdapter, "native": NativeAdapter}

DEFAULT_SEED_ORDER_IDS = ["1001", "1003"]
DEFAULT_POISONED_ORDER_IDS = ["1002"]
DEFAULT_ATTACKER_EMAIL = "collector@exfil-sink.example"


def build_agent(adapter_name: str, target: str) -> TargetAgent:
    if adapter_name not in ADAPTERS:
        raise ValueError(f"Unknown adapter '{adapter_name}'. Choices: {list(ADAPTERS)}")
    agent = ADAPTERS[adapter_name](target)
    agent.connect()
    return agent


def run_scan(
    target: str,
    adapter_name: str,
    out_path: str,
    seed_order_ids: list[str] | None = None,
    poisoned_order_ids: list[str] | None = None,
    attacker_email: str | None = None,
    repro_runs: int = 3,
    verbose: bool = True,
) -> str:
    agent = build_agent(adapter_name, target)

    if verbose:
        print(f"[1/5] Connected to target via {adapter_name} adapter: {target}")

    tools = agent.list_tools()
    if verbose:
        print(f"[2/5] Discovered {len(tools)} tools: {[t.name for t in tools]}")

    graph = build_tool_graph(tools)
    ctx = AttackContext(
        graph=graph,
        seed_order_ids=seed_order_ids or DEFAULT_SEED_ORDER_IDS,
        poisoned_order_ids=poisoned_order_ids or DEFAULT_POISONED_ORDER_IDS,
        attacker_email=attacker_email or DEFAULT_ATTACKER_EMAIL,
    )

    attacks = generate_all(ctx)
    if verbose:
        classes = sorted({a.exploit_class for a in attacks})
        print(f"[3/5] Generated {len(attacks)} attack instances across {len(classes)} exploit classes")

    findings = [score_attack(agent, a, repro_runs=repro_runs) for a in attacks]
    deduped = deduplicate(findings)
    if verbose:
        n_success = sum(1 for f in deduped if f.outcome == "success")
        print(f"[4/5] Executed & scored -> {n_success}/{len(deduped)} tool-pairs show a successful exploit")

    report_md = render_markdown(
        target_label=target,
        adapter_name=adapter_name,
        tools=tools,
        graph=graph,
        findings=deduped,
        templates_run=len(attacks),
    )
    with open(out_path, "w") as f:
        f.write(report_md)
    if verbose:
        print(f"[5/5] Report written to {out_path}")

    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="talos-scan", description="Automated red-teamer for tool-using LLM agents.")
    parser.add_argument("--target", required=True, help="Base agent URL, e.g. http://localhost:8001/agent")
    parser.add_argument("--adapter", required=True, choices=list(ADAPTERS.keys()))
    parser.add_argument("--out", default=None, help="Output path for the Markdown report")
    parser.add_argument("--repro-runs", type=int, default=3, help="Times to repeat each attack for reproducibility scoring")
    parser.add_argument("--seed-order-id", action="append", dest="seed_order_ids", help="Known-valid order id to test with (repeatable)")
    parser.add_argument("--poisoned-order-id", action="append", dest="poisoned_order_ids", help="Known-poisoned order id for indirect-injection templates (repeatable)")
    parser.add_argument("--attacker-email", default=None, help="Destination address used by exfiltration/injection templates")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    out_path = args.out or f"report_{args.adapter}.md"
    run_scan(
        target=args.target,
        adapter_name=args.adapter,
        out_path=out_path,
        seed_order_ids=args.seed_order_ids,
        poisoned_order_ids=args.poisoned_order_ids,
        attacker_email=args.attacker_email,
        repro_runs=args.repro_runs,
        verbose=not args.quiet,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
