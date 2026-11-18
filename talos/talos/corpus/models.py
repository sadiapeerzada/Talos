"""Versioned passive dataset contracts; no outcomes are measured here."""
from __future__ import annotations

from datetime import date
from enum import Enum
import hashlib
import json
import re
from string import Formatter
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from talos.judging import Outcome
from talos.profiles import Effect

CORPUS_VERSION = "Talos-Portable-1.0"


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def content_hash(value) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


class Family(str, Enum):
    DIRECT = "direct_prompt_injection"
    INDIRECT = "indirect_prompt_injection"
    AUTHORIZATION = "authorization_confusion"
    TOOL_ACTION = "unauthorized_tool_action"
    WORKFLOW = "multi_step_workflow"
    DISCLOSURE = "unauthorized_disclosure"
    CONTROL = "control"


class Surface(str, Enum):
    USER = "user_message"
    TOOL = "tool_output"
    DOCUMENT = "retrieved_document"
    WORKFLOW = "workflow_context"
    TASK = "authorized_task"


class Provenance(Model):
    origin: Literal["authored_synthetic", "derived_synthetic", "independently_supplied"]
    creation_method: str = Field(min_length=1)
    created_on: date
    source_refs: tuple[str, ...] = Field(min_length=1)
    custodian_declaration: str = Field(min_length=1)
    review_status: Literal["unreviewed", "review_reference_supplied"] = "unreviewed"
    review_reference: str | None = None
    independent_validity: Literal["not_established"] = "not_established"

    @model_validator(mode="after")
    def review(self):
        if self.review_status == "review_reference_supplied" and not self.review_reference:
            raise ValueError("review reference required; reference is not verified approval")
        return self


class ToolRequirement(Model):
    slot: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    any_roles: tuple[Effect, ...] = Field(min_length=1)
    needs_untrusted_output: bool = Field(default=False, strict=True)
    needs_commit_evidence: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def roles(self):
        if Effect.UNKNOWN in self.any_roles:
            raise ValueError("unknown cannot satisfy an admissible role")
        return self


class Stimulus(Model):
    surface: Surface
    text: str = Field(min_length=1)

    def fields(self):
        names = set()
        for _, name, spec, conversion in Formatter().parse(self.text):
            if name is not None:
                if not re.fullmatch(r"[a-z][a-z0-9_]*", name) or spec or conversion:
                    raise ValueError("only simple named placeholders permitted")
                names.add(name)
        return names

    @model_validator(mode="after")
    def placeholders(self):
        self.fields()
        return self


class TaxonomyMapping(Model):
    system: str = Field(min_length=1)
    edition: str = Field(min_length=1)
    category_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    relation: Literal["exact_mechanism", "conceptual"]
    rationale: str = Field(min_length=1)


class ExpectedBehavior(Model):
    condition: str = Field(min_length=1)
    admissible_outcomes: tuple[Outcome, ...] = Field(min_length=1)
    status: Literal["declared_test_expectation_not_observed"] = "declared_test_expectation_not_observed"


class AttackCase(Model):
    schema_version: Literal["talos.attack-case.v1"] = "talos.attack-case.v1"
    corpus_version: Literal["Talos-Portable-1.0"] = CORPUS_VERSION
    case_id: str = Field(pattern=r"^TP1-[A-Z0-9-]+$")
    revision: int = Field(ge=1, strict=True)
    family: Family
    family_id: str = Field(min_length=1)
    template_family_id: str = Field(min_length=1)
    paraphrase_family_id: str = Field(min_length=1)
    parent_case_ids: tuple[str, ...] = ()
    scenario_ancestry: tuple[str, ...] = Field(min_length=1)
    kind: Literal["attack", "negative_control", "authorized_task", "blocked_action", "unknown_evidence"]
    entry_surface: Surface
    objective: str = Field(min_length=1)
    intended_policy_boundary: str = Field(min_length=1)
    prerequisites: tuple[str, ...] = Field(min_length=1)
    tool_requirements: tuple[ToolRequirement, ...] = Field(min_length=1)
    public_parameter_names: tuple[str, ...] = ()
    stimuli: tuple[Stimulus, ...] = Field(min_length=1)
    expected_observable_evidence: tuple[str, ...] = Field(min_length=1)
    expectations: tuple[ExpectedBehavior, ...] = Field(min_length=1)
    mappings: tuple[TaxonomyMapping, ...] = ()
    provenance: Provenance

    @model_validator(mode="after")
    def coherent(self):
        names = [r.slot for r in self.tool_requirements] + list(self.public_parameter_names)
        if len(set(names)) != len(names) or any(not re.fullmatch(r"[a-z][a-z0-9_]*", n) for n in names):
            raise ValueError("duplicate or invalid placeholder names")
        if any(not s.fields() <= set(names) for s in self.stimuli):
            raise ValueError("undeclared placeholder")
        if self.entry_surface not in {s.surface for s in self.stimuli}:
            raise ValueError("missing entry surface")
        if self.family == Family.DIRECT and self.entry_surface != Surface.USER:
            raise ValueError("direct injection requires user entry")
        if self.family == Family.INDIRECT and self.entry_surface not in (Surface.TOOL, Surface.DOCUMENT):
            raise ValueError("indirect injection requires data entry")
        if self.family == Family.WORKFLOW and len(self.stimuli) < 2:
            raise ValueError("workflow requires multiple steps")
        if self.family == Family.CONTROL and self.kind == "attack":
            raise ValueError("controls are not attacks")
        if self.case_id in self.parent_case_ids:
            raise ValueError("self ancestry")
        if self.provenance.origin == "derived_synthetic" and not self.parent_case_ids:
            raise ValueError("derived case requires parent identity")
        if self.kind == "unknown_evidence" and not any(Outcome.UNKNOWN in e.admissible_outcomes for e in self.expectations):
            raise ValueError("missing UNKNOWN contract")
        return self


class CaseRecord(Model):
    case: AttackCase
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def identity_check(self):
        if content_hash(self.case) != self.sha256:
            raise ValueError("case hash mismatch")
        return self

    @property
    def identity(self):
        return f"{self.case.case_id}@{self.case.revision}#{self.sha256}"


class Corpus(Model):
    schema_version: Literal["talos.corpus.v1"] = "talos.corpus.v1"
    corpus_version: Literal["Talos-Portable-1.0"] = CORPUS_VERSION
    records: tuple[CaseRecord, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def identities(self):
        cases = {r.case.case_id: r.case for r in self.records}
        if len(cases) != len(self.records):
            raise ValueError("duplicate case ID")
        visiting, visited = set(), set()
        def visit(ident):
            if ident not in cases:
                raise ValueError("unknown parent case")
            if ident in visiting:
                raise ValueError("case ancestry cycle")
            if ident in visited:
                return
            visiting.add(ident)
            for parent in cases[ident].parent_case_ids:
                visit(parent)
            visiting.remove(ident)
            visited.add(ident)
        for ident in cases:
            visit(ident)
        return self


def validate_identity_continuity(previous: Corpus, current: Corpus):
    old = {r.case.case_id: r for r in previous.records}
    for record in current.records:
        before = old.get(record.case.case_id)
        if before and (record.case.revision < before.case.revision or (
            record.case.revision == before.case.revision and record.sha256 != before.sha256)):
            raise ValueError("case revision cannot be reused or move backwards")
