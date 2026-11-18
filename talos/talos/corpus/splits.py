"""Conservative structural leakage diagnostics, never cohort certification."""
from __future__ import annotations

from difflib import SequenceMatcher
from itertools import combinations
import re
import unicodedata
from typing import Literal

from pydantic import Field
from talos.corpus.models import Corpus, Model, content_hash
from talos.corpus.planning import BindingSet
from talos.profiles import TargetProfile
from talos.profiles.models import snapshot


class SplitManifest(Model):
    schema_version: Literal["talos.split.v1"] = "talos.split.v1"
    corpus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assignments: dict[str, Literal["UNASSIGNED", "DEV", "TEST"]]
    review_status: Literal["pending_researcher_approval"] = "pending_researcher_approval"
    independent_validity: Literal["not_established"] = "not_established"


class Leakage(Model):
    left: str
    right: str
    axis: str
    detail: str


class LeakageReport(Model):
    issues: tuple[Leakage, ...]
    unassigned_case_ids: tuple[str, ...]
    semantic_review_required: Literal[True] = True
    independent_validity: Literal["not_established"] = "not_established"
    approved_for_evaluation: Literal[False] = False


def normalized_text(text: str):
    return " ".join(re.findall(r"\w+", unicodedata.normalize("NFKC", text).casefold()))


def schema_fingerprint(schema: dict) -> str:
    """Renaming-insensitive conservative structural signature, not schema equivalence.

    Drop cosmetic fields; preserve constraints, normalize property identifiers and
    required membership. $ref names are collapsed to flag shared schema structure;
    referenced definitions still contribute. Possible false positives need review.
    """
    def shape(value):
        if isinstance(value, list):
            return [shape(x) for x in value]
        if not isinstance(value, dict):
            return value
        out = {}
        for key, val in value.items():
            if key in ("title", "description", "examples", "$id", "default", "required"):
                continue
            if key == "properties":
                required = set(value.get("required", []))
                entries = [{"required": n in required, "shape": shape(v)} for n, v in val.items()]
                out[key] = sorted(entries, key=content_hash)
            elif key in ("$defs", "definitions"):
                out[key] = sorted([shape(v) for v in val.values()], key=content_hash)
            elif key == "$ref":
                out[key] = "reference-present"
            else:
                out[key] = shape(val)
        return out
    return content_hash(shape(schema))


def check_leakage(corpus: Corpus, manifest: SplitManifest, bindings: BindingSet,
                  profiles: dict[str, TargetProfile], *, similarity_threshold: float = 0.85) -> LeakageReport:
    """profiles maps every binding ID to its passive target description.

    Complete identity/schema context is required, even if cases are unassigned.
    No result establishes a held-out cohort or independent target provenance.
    """
    corpus = Corpus.model_validate(corpus.model_dump())
    manifest = SplitManifest.model_validate(manifest.model_dump())
    bindings = BindingSet.model_validate(bindings.model_dump())
    bindings.validate_against(corpus)
    if not 0 <= similarity_threshold <= 1:
        raise ValueError("invalid similarity threshold")
    cases = {r.case.case_id: r.case for r in corpus.records}
    if manifest.corpus_sha256 != content_hash(corpus) or set(manifest.assignments) != set(cases):
        raise ValueError("split corpus identity or assignment coverage mismatch")
    if set(profiles) != {b.binding_id for b in bindings.bindings}:
        raise ValueError("complete binding profile coverage required")
    profiles = {k: snapshot(p) for k, p in profiles.items()}
    context = {ident: {"target_identity": set(), "tool_schema": set(), "scenario_ancestry": set()} for ident in cases}
    by_identity = {r.identity: r.case.case_id for r in corpus.records}
    if {b.case_identity for b in bindings.bindings} != set(by_identity):
        raise ValueError("complete case-to-target binding coverage required for leakage review")
    for b in bindings.bindings:
        p = profiles[b.binding_id]
        if p.domain != b.domain or not set(b.tool_bindings.values()) <= {t.name for t in p.tools}:
            raise ValueError("binding target/domain/tools mismatch")
        ctx = context[by_identity[b.case_identity]]
        ctx["target_identity"].update((p.target_id, b.target_family_id, b.fixture_family_id))
        ctx["scenario_ancestry"].update(b.scenario_ancestry)
        for tool in p.tools:
            ctx["tool_schema"].add(content_hash({"input": schema_fingerprint(tool.input_schema),
                                                   "output": schema_fingerprint(tool.output_schema)}))
    def parents(ident):
        return {ident} | {a for parent in cases[ident].parent_case_ids for a in parents(parent)}
    issues = []
    for left, right in combinations(sorted(cases), 2):
        if {manifest.assignments[left], manifest.assignments[right]} != {"DEV", "TEST"}:
            continue
        a, b = cases[left], cases[right]
        axes = {
            "family": a.family_id == b.family_id,
            "template": a.template_family_id == b.template_family_id,
            "paraphrase": a.paraphrase_family_id == b.paraphrase_family_id,
            "case_ancestry": bool(parents(left) & parents(right)),
            "scenario_ancestry": bool((set(a.scenario_ancestry) | context[left]["scenario_ancestry"]) &
                                      (set(b.scenario_ancestry) | context[right]["scenario_ancestry"])),
            "target_identity": bool(context[left]["target_identity"] & context[right]["target_identity"]),
            "tool_schema": bool(context[left]["tool_schema"] & context[right]["tool_schema"]),
        }
        text_a = normalized_text(" ".join(s.text for s in a.stimuli))
        text_b = normalized_text(" ".join(s.text for s in b.stimuli))
        axes["text_similarity"] = SequenceMatcher(None, text_a, text_b, autojunk=False).ratio() >= similarity_threshold
        for axis, overlapping in axes.items():
            if overlapping:
                issues.append(Leakage(left=left, right=right, axis=axis,
                                      detail="Potential cross-split overlap; block freeze pending researcher resolution."))
    return LeakageReport(issues=tuple(issues), unassigned_case_ids=tuple(sorted(
        ident for ident, split in manifest.assignments.items() if split == "UNASSIGNED")))
