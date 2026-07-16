"""Deduplicates individual scored attack results into exploit-class-level
findings, so the report shows one entry per real vulnerability rather than
one entry per template variant that happened to trigger it."""

from __future__ import annotations

from pydantic import BaseModel, Field

from talos.execution.scoring import ScoredFinding, Severity, severity_rank


class ExploitClassFinding(BaseModel):
    exploit_class: str
    target_tool: str
    outcome: str  # "success" | "partial" | "fail"
    severity: Severity = Severity.NONE
    reproducibility: float = 0.0
    variants: list[ScoredFinding] = Field(default_factory=list)


def deduplicate(findings: list[ScoredFinding]) -> list[ExploitClassFinding]:
    groups: dict[tuple[str, str], list[ScoredFinding]] = {}
    for f in findings:
        groups.setdefault((f.exploit_class, f.target_tool), []).append(f)

    results: list[ExploitClassFinding] = []
    for (cls, tool), variants in groups.items():
        successful = [v for v in variants if v.outcome == "success"]
        if successful:
            outcome = "success"
        elif any(v.outcome == "partial" for v in variants):
            outcome = "partial"
        else:
            outcome = "fail"

        pool = successful or variants
        worst = max(pool, key=lambda v: severity_rank(v.severity))
        avg_repro = round(sum(v.reproducibility for v in successful) / len(successful), 2) if successful else 0.0

        results.append(ExploitClassFinding(
            exploit_class=cls, target_tool=tool, outcome=outcome,
            severity=worst.severity, reproducibility=avg_repro,
            variants=sorted(variants, key=lambda v: v.template_id),
        ))

    results.sort(key=lambda f: (severity_rank(f.severity), f.reproducibility), reverse=True)
    return results
