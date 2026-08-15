"""
Research evaluation script for the Talos paper (Sections VII/VIII).

Runs the full Talos-35 template sweep against a live target, repeated
`repro_runs` times per template, and reports:
  - per-class attack success rate (ASR) with 95% Wilson score intervals
    (Eq. 4 in the paper),
  - per-template (k successes, n attempts) for paired significance
    testing between two target variants,
  - a before/after severity-count table and risk-score delta when run
    against a vulnerable and a hardened instance of the same target,
  - McNemar's test on paired per-template outcomes (same template,
    byte-for-byte, replayed against both variants) when a paired
    before/after run is requested.

This is a real measurement tool, not a demo -- every number it prints
comes from an actual live scan against an actual running target. No
number here should ever be pasted into the paper without having been
produced by an actual run of this script.

Usage:
    python -m talos.scripts.research_eval --target http://127.0.0.1:8001/agent --adapter native --repro-runs 5
    python -m talos.scripts.research_eval --before http://127.0.0.1:8001/agent --after http://127.0.0.1:8002/agent --adapter native --repro-runs 5
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from talos.attacks.models import AttackContext
from talos.attacks.templates import ALL_TEMPLATES, TAXONOMY_VERSION
from talos.execution.scoring import score_attack
from talos.graph.discovery import build_tool_graph
from talos.harness.base import TargetAgent
from talos.reporting.report import EXPLOIT_CLASS_LABELS, compute_risk_score, SeverityCounts
from talos.scan_service import (
    ADAPTERS,
    DEFAULT_ATTACKER_EMAIL,
    DEFAULT_POISONED_ORDER_IDS,
    DEFAULT_SEED_ORDER_IDS,
)


def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion -- Eq. 4 in the paper."""
    if n == 0:
        return (0.0, 0.0)
    phat = k / n
    denom = 1 + (z**2) / n
    center = phat + (z**2) / (2 * n)
    margin = z * math.sqrt((phat * (1 - phat)) / n + (z**2) / (4 * n**2))
    lo = (center - margin) / denom
    hi = (center + margin) / denom
    return (max(0.0, lo), min(1.0, hi))


@dataclass
class TemplateAttempt:
    template_id: str
    exploit_class: str
    target_tool: str
    k: int
    n: int
    outcome: str
    severity: str


@dataclass
class SweepResult:
    target: str
    adapter: str
    repro_runs: int
    attempts: list[TemplateAttempt] = field(default_factory=list)

    def class_asr_table(self) -> list[dict]:
        by_class: dict[str, list[TemplateAttempt]] = defaultdict(list)
        for a in self.attempts:
            by_class[a.exploit_class].append(a)

        rows = []
        for exploit_class in EXPLOIT_CLASS_LABELS:
            if exploit_class == "cross_agent_injection":
                continue  # not part of the automated Talos-35 corpus -- see README
            items = by_class.get(exploit_class, [])
            total_k = sum(a.k for a in items)
            total_n = sum(a.n for a in items)
            asr = (total_k / total_n) if total_n else 0.0
            lo, hi = wilson_interval(total_k, total_n)
            rows.append(
                {
                    "class": EXPLOIT_CLASS_LABELS[exploit_class],
                    "exploit_class": exploit_class,
                    "mean_asr": round(asr, 4),
                    "ci_95_low": round(lo, 4),
                    "ci_95_high": round(hi, 4),
                    "n": total_n,
                    "k": total_k,
                    "templates_applicable": len(items),
                }
            )
        return rows

    def severity_counts(self) -> SeverityCounts:
        counts = SeverityCounts()
        for a in self.attempts:
            if a.outcome == "success" and a.k > 0:
                if a.severity == "critical":
                    counts.critical += 1
                elif a.severity == "high":
                    counts.high += 1
                elif a.severity == "medium":
                    counts.medium += 1
                elif a.severity == "low":
                    counts.low += 1
        return counts

    def risk_score(self) -> int:
        return compute_risk_score(self.severity_counts())


def run_sweep(agent: TargetAgent, adapter_name: str, target: str, repro_runs: int) -> SweepResult:
    tools = agent.list_tools()
    graph = build_tool_graph(tools)
    ctx = AttackContext(
        graph=graph,
        seed_order_ids=DEFAULT_SEED_ORDER_IDS,
        poisoned_order_ids=DEFAULT_POISONED_ORDER_IDS,
        attacker_email=DEFAULT_ATTACKER_EMAIL,
    )

    result = SweepResult(target=target, adapter=adapter_name, repro_runs=repro_runs)
    for template in ALL_TEMPLATES:
        if not template.applies(ctx):
            continue
        for instance in template.instantiate(ctx):
            finding = score_attack(agent, instance, repro_runs=repro_runs)
            k = round(finding.reproducibility * repro_runs)
            result.attempts.append(
                TemplateAttempt(
                    template_id=finding.template_id,
                    exploit_class=finding.exploit_class,
                    target_tool=finding.target_tool,
                    k=k,
                    n=repro_runs,
                    outcome=finding.outcome,
                    severity=finding.severity.value,
                )
            )
    return result


def mcnemar_test(before: SweepResult, after: SweepResult) -> dict:
    """Paired McNemar's test on per-template binary outcomes (success/fail
    at the majority-vote level per template) between two variants of the
    SAME target scanned with the SAME template set -- Section IV-E."""
    before_by_id = {a.template_id: a for a in before.attempts}
    after_by_id = {a.template_id: a for a in after.attempts}
    shared_ids = sorted(set(before_by_id) & set(after_by_id))

    b = 0  # success before, fail after
    c = 0  # fail before, success after
    both_success = 0
    both_fail = 0
    for tid in shared_ids:
        before_success = before_by_id[tid].k > 0
        after_success = after_by_id[tid].k > 0
        if before_success and not after_success:
            b += 1
        elif not before_success and after_success:
            c += 1
        elif before_success and after_success:
            both_success += 1
        else:
            both_fail += 1

    n_discordant = b + c
    if n_discordant == 0:
        chi2 = 0.0
        note = "No discordant pairs -- McNemar's test is undefined (both variants agree on every shared template)."
    else:
        chi2 = ((abs(b - c) - 1) ** 2) / n_discordant  # continuity-corrected
        note = ""

    return {
        "paired_templates": len(shared_ids),
        "both_success": both_success,
        "both_fail": both_fail,
        "success_before_fail_after": b,
        "fail_before_success_after": c,
        "chi2_continuity_corrected": round(chi2, 4),
        "note": note,
    }


def print_report(before: SweepResult, after: Optional[SweepResult] = None) -> None:
    print(f"Taxonomy: {TAXONOMY_VERSION}")
    print(f"Target: {before.target} (adapter: {before.adapter}, repro_runs: {before.repro_runs})")
    print()
    print("=== Attack Success Rate by Exploit Class (95% Wilson CI) ===")
    print(f"{'Class':<24}{'Mean ASR':>10}{'95% CI':>18}{'n':>6}{'k':>6}")
    for row in before.class_asr_table():
        ci = f"[{row['ci_95_low']:.3f}, {row['ci_95_high']:.3f}]"
        print(f"{row['class']:<24}{row['mean_asr']:>10.4f}{ci:>18}{row['n']:>6}{row['k']:>6}")
    print()
    print(f"Risk score: {before.risk_score()}/100")
    print(f"Severity counts: {before.severity_counts().model_dump()}")

    if after is not None:
        print()
        print("=== Before / After Comparison ===")
        b_counts = before.severity_counts()
        a_counts = after.severity_counts()
        print(f"{'Severity':<12}{'Before':>10}{'After':>10}{'Delta':>10}")
        for sev in ("critical", "high", "medium", "low"):
            bv = getattr(b_counts, sev)
            av = getattr(a_counts, sev)
            print(f"{sev.capitalize():<12}{bv:>10}{av:>10}{bv - av:>10}")
        print()
        r_before, r_after = before.risk_score(), after.risk_score()
        print(f"Risk score before: {r_before}/100")
        print(f"Risk score after:  {r_after}/100")
        print(f"Delta R: {r_before - r_after}")
        print()
        print("=== McNemar's Test (paired per-template outcomes) ===")
        mc = mcnemar_test(before, after)
        for k, v in mc.items():
            print(f"  {k}: {v}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", help="Single target to sweep (no before/after comparison).")
    parser.add_argument("--before", help="Vulnerable-variant target URL for a paired before/after run.")
    parser.add_argument("--after", help="Hardened-variant target URL for a paired before/after run.")
    parser.add_argument("--adapter", default="native", choices=list(ADAPTERS.keys()))
    parser.add_argument("--repro-runs", type=int, default=5)
    parser.add_argument("--json-out", default=None, help="Optional path to write raw results as JSON.")
    args = parser.parse_args(argv)

    from talos.scan_service import build_agent

    if args.before and args.after:
        before_agent = build_agent(args.adapter, args.before)
        before_result = run_sweep(before_agent, args.adapter, args.before, args.repro_runs)
        after_agent = build_agent(args.adapter, args.after)
        after_result = run_sweep(after_agent, args.adapter, args.after, args.repro_runs)
        print_report(before_result, after_result)
        if args.json_out:
            with open(args.json_out, "w") as f:
                json.dump(
                    {
                        "before": {"target": before_result.target, "attempts": [vars(a) for a in before_result.attempts]},
                        "after": {"target": after_result.target, "attempts": [vars(a) for a in after_result.attempts]},
                        "mcnemar": mcnemar_test(before_result, after_result),
                    },
                    f,
                    indent=2,
                )
    elif args.target:
        agent = build_agent(args.adapter, args.target)
        result = run_sweep(agent, args.adapter, args.target, args.repro_runs)
        print_report(result)
        if args.json_out:
            with open(args.json_out, "w") as f:
                json.dump({"target": result.target, "attempts": [vars(a) for a in result.attempts]}, f, indent=2)
    else:
        parser.error("must supply either --target, or both --before and --after")

    return 0


if __name__ == "__main__":
    sys.exit(main())
