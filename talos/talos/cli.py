"""talos-scan CLI: wires the full pipeline end to end.

    talos-scan --target http://localhost:8000/agent --adapter langchain
    talos-scan --target http://localhost:8001/agent --adapter native
"""

from __future__ import annotations

import argparse
import sys

from talos.reporting.report import render_markdown_report
from talos.scan_service import (
    ADAPTERS,
    build_agent,
    run_scan_pipeline,
)


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
    report, events = run_scan_pipeline(
        target=target,
        adapter_name=adapter_name,
        seed_order_ids=seed_order_ids,
        poisoned_order_ids=poisoned_order_ids,
        attacker_email=attacker_email,
        repro_runs=repro_runs,
    )
    if verbose:
        for event in events:
            if event.type == "connected":
                print(f"[1/5] Connected to target via {adapter_name} adapter: {target}")
            elif event.type == "tools_discovered":
                print(f"[2/5] Discovered {event.stats.tools_found} tools: {event.tool_names}")
            elif event.type == "attacks_generated":
                classes = event.exploit_classes or []
                print(f"[3/5] Generated {event.stats.attacks_total} attack instances across {len(classes)} exploit classes")
            elif event.type == "completed":
                successful = len(report.findings)
                tested = report.stats.findings_tested
                print(f"[4/5] Executed & scored -> {successful}/{tested} tool-pairs show a successful exploit")

    report_md = render_markdown_report(report)
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
