"""
Attack-generation engine.

`generate_next_round` is deliberately the ONLY function the rest of the
pipeline calls to get attacks to try. In this phase it just walks the local
template library (talos/attacks/templates.py) and pulls the next untried,
applicable batch -- no network calls, no LLM, fully offline and
deterministic.

THE EXTENSION SEAM: a later phase can replace the body of this function
with something that calls the Anthropic API to mutate/refine payloads
based on `previous_results` (e.g. "this direct-injection phrasing got
refused, try a variant that frames it as a system message instead", or
"class B succeeded on lookup_order -- try the same directive style against
search_kb too") -- as long as the new implementation still returns
`list[AttackInstance]` given `(previous_results, ctx)`, nothing in
execution/scoring/reporting needs to change. That's the whole point of
routing everything through this one function.
"""

from __future__ import annotations

from typing import Any, Optional

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
    already_tried = {tid for r in (previous_results or []) if (tid := _extract_template_id(r))}

    candidates = [t for t in ALL_TEMPLATES if t.id not in already_tried and t.applies(ctx)]
    batch = candidates[:batch_size]

    instances: list[AttackInstance] = []
    for template in batch:
        instances.extend(template.instantiate(ctx))
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
