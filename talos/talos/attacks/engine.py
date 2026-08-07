"""
Attack-generation engine.

`generate_next_round` is deliberately the ONLY function the rest of the
pipeline calls to get attacks to try. It still supports the original
deterministic local-template flow, but now also supports an optional
adaptive refinement mode that can synthesize follow-up variants from prior
execution results.
"""

from __future__ import annotations

from typing import Any, Optional

from talos.attacks.adaptive import build_adaptive_refinements
from talos.attacks.models import AttackContext, AttackInstance
from talos.attacks.templates import ALL_TEMPLATES

DEFAULT_BATCH_SIZE = 8


def _extract_template_id(result: Any) -> Optional[str]:
    if hasattr(result, "template_id"):
        return result.template_id
    if isinstance(result, dict):
        return result.get("template_id")
    return None


def generate_next_round(
    previous_results: Optional[list[Any]],
    ctx: AttackContext,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> list[AttackInstance]:
    """Return the next batch of attacks to run.

    previous_results: whatever execution/scoring has produced so far
        (a list of ScoredFinding-like objects, or None on the first call).
        This phase only reads `.template_id` off each one, to avoid
        re-running a template that's already been tried.
    ctx: the discovered tool graph + seed data attacks are instantiated
        against.
    """
    instances: list[AttackInstance] = []
    already_tried = {tid for r in (previous_results or []) if (tid := _extract_template_id(r))}
    candidates = [t for t in ALL_TEMPLATES if t.id not in already_tried and t.applies(ctx)]

    adaptive_quota = 0
    if ctx.generation_strategy == "adaptive" and previous_results:
        adaptive_quota = min(2, batch_size)

    base_quota = max(0, batch_size - adaptive_quota)
    for template in candidates[:base_quota]:
        instances.extend(template.instantiate(ctx))

    if ctx.generation_strategy == "adaptive" and previous_results:
        adaptive_variants = build_adaptive_refinements(
            ctx=ctx,
            previous_results=previous_results,
            seen_template_ids=already_tried,
        )
        instances.extend(adaptive_variants[:adaptive_quota or batch_size])

    return instances


def generate_all(ctx: AttackContext) -> list[AttackInstance]:
    """Convenience helper: run generate_next_round in a loop until the
    template pool is exhausted. Useful for `scan.py`, which wants
    everything applicable in one pass rather than hand-rolling the loop."""
    all_instances: list[AttackInstance] = []
    previous_results: list[Any] = []
    while True:
        batch = generate_next_round(previous_results, ctx, batch_size=DEFAULT_BATCH_SIZE)
        if not batch:
            break
        all_instances.extend(batch)
        # We only need `.template_id` to be present for the dedup check in
        # the next iteration -- a plain namespace-like stand-in is enough
        # here since real scored results don't exist yet at generation time.
        previous_results.extend({"template_id": inst.template_id} for inst in batch)
    return all_instances
