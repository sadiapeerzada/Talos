"""Passive compatibility and public projections; never execute a target."""
from __future__ import annotations

from typing import Literal
from pydantic import Field, field_validator, model_validator
from talos.corpus.models import CaseRecord, Corpus, Model, Surface, content_hash
from talos.profiles import TargetProfile, classify_profile
from talos.profiles.models import finite_json, snapshot


class FixtureBinding(Model):
    binding_id: str = Field(min_length=1)
    case_identity: str = Field(min_length=1)
    domain: str = Field(min_length=1)
    target_family_id: str = Field(min_length=1)
    fixture_family_id: str = Field(min_length=1)
    tool_bindings: dict[str, str]
    public_parameters: dict[str, str]
    scenario_ancestry: tuple[str, ...] = Field(min_length=1)
    proposed_actor_id: str = Field(min_length=1)
    proposed_tool_arguments: dict[str, dict]
    policy_assumption: str = Field(min_length=1)
    delivery_status: Literal["unimplemented_prompt_adapter"] = "unimplemented_prompt_adapter"
    origin: Literal["repository_authored_synthetic"] = "repository_authored_synthetic"

    @field_validator("proposed_tool_arguments")
    @classmethod
    def json_arguments(cls, value):
        return finite_json(value)


class BindingSet(Model):
    schema_version: Literal["talos.bindings.v1"] = "talos.bindings.v1"
    corpus_sha256: str
    bindings: tuple[FixtureBinding, ...]

    @model_validator(mode="after")
    def unique(self):
        if len({b.binding_id for b in self.bindings}) != len(self.bindings):
            raise ValueError("duplicate binding ID")
        return self

    def validate_against(self, corpus: Corpus):
        if self.corpus_sha256 != content_hash(corpus):
            raise ValueError("binding corpus mismatch")
        records = {r.identity: r for r in corpus.records}
        for b in self.bindings:
            if b.case_identity not in records:
                raise ValueError("unknown binding case identity")
            case = records[b.case_identity].case
            if set(b.tool_bindings) != {r.slot for r in case.tool_requirements} or set(b.proposed_tool_arguments) != set(b.tool_bindings):
                raise ValueError("binding slots mismatch")
            if set(b.public_parameters) != set(case.public_parameter_names):
                raise ValueError("binding parameters mismatch")


class RenderedStimulus(Model):
    surface: Surface
    text: str


class Compatibility(Model):
    status: Literal["APPLICABLE", "INAPPLICABLE", "UNKNOWN"]
    reasons: tuple[str, ...]
    candidates: dict[str, tuple[str, ...]]
    stimuli: tuple[RenderedStimulus, ...] = ()
    scope: Literal["declared_profile_compatibility_only"] = "declared_profile_compatibility_only"


def plan_case(record: CaseRecord, profile: TargetProfile, binding: FixtureBinding,
              *, available_surfaces: frozenset[Surface] = frozenset()) -> Compatibility:
    """Explicit surfaces describe a proposed adapter contract, never proof of delivery.

    Authorization and evidence trust must be checked by the unchanged oracle later.
    Graph edges are deliberately absent from this interface.
    """
    record = CaseRecord.model_validate(record.model_dump())
    profile = snapshot(profile)
    binding = FixtureBinding.model_validate(binding.model_dump())
    case = record.case
    if binding.case_identity != record.identity or profile.domain != binding.domain:
        raise ValueError("case/domain binding mismatch")
    slots = {r.slot for r in case.tool_requirements}
    if (set(binding.tool_bindings) != slots or set(binding.proposed_tool_arguments) != slots
            or set(binding.public_parameters) != set(case.public_parameter_names)):
        raise ValueError("incomplete or extra template bindings")
    classes = {c.tool_name: c for c in classify_profile(profile)}
    tools = {t.name: t for t in profile.tools}
    caps = {a.capability_id: a for a in profile.audit_capabilities}
    reasons, candidates = [], {}
    impossible = False
    for req in case.tool_requirements:
        roles = {e.value for e in req.any_roles}
        matches = []
        for c in classes.values():
            if roles & (set(c.roles) | set(c.side_effects)):
                matches.append(c.tool_name)
        candidates[req.slot] = tuple(sorted(matches))
        name = binding.tool_bindings[req.slot]
        if name not in tools:
            reasons.append(f"{req.slot}: bound tool absent")
            impossible = True
            continue
        c, tool = classes[name], tools[name]
        if c.status != "declared":
            reasons.append(f"{req.slot}: incomplete/conflicting metadata; permission/trust not established")
            continue
        if name not in matches:
            reasons.append(f"{req.slot}: known role mismatch")
            impossible = True
        if req.needs_untrusted_output and c.output_trust not in ("untrusted", "mixed"):
            reasons.append(f"{req.slot}: no declared untrusted output")
            impossible = True
        if req.needs_commit_evidence and not any(
            caps[i].kind in ("audit", "state_transition") and caps[i].can_observe_commit is True
            and caps[i].action_digest_binding is True for i in tool.audit_capability_ids
        ):
            reasons.append(f"{req.slot}: committed effect evidence capability missing")
    needed = {s.surface for s in case.stimuli}
    if not needed <= set(available_surfaces):
        reasons.append("surface delivery contract unavailable; PR-03 has no prompt adapter")
    status = "INAPPLICABLE" if impossible else ("UNKNOWN" if reasons else "APPLICABLE")
    stimuli = ()
    if status == "APPLICABLE":
        params = {**binding.tool_bindings, **binding.public_parameters}
        stimuli = tuple(RenderedStimulus(surface=s.surface, text=s.text.format_map(params)) for s in case.stimuli)
    return Compatibility(status=status, reasons=tuple(reasons), candidates=candidates, stimuli=stimuli)


class PublicTool(Model):
    name: str
    description: str
    input_schema: dict
    output_schema: dict


class PublicOpportunity(Model):
    opportunity_id: str
    tools: tuple[PublicTool, ...]
    stimuli: tuple[RenderedStimulus, ...]


def public_opportunity(record: CaseRecord, profile: TargetProfile, binding: FixtureBinding,
                       compatibility: Compatibility) -> PublicOpportunity:
    """Recompute compatibility: caller cannot forge prepared private-label content."""
    if compatibility.status != "APPLICABLE":
        raise ValueError("unresolved/inapplicable cases cannot enter the opportunity pool")
    prepared = plan_case(record, profile, binding, available_surfaces=frozenset(Surface))
    if prepared != compatibility:
        raise ValueError("prepared compatibility mismatch")
    # Full common inventory, not the role-selected subset or private profile annotations.
    return PublicOpportunity(
        opportunity_id=content_hash({"case": record.identity, "binding": content_hash(binding), "profile": profile.digest()}),
        tools=tuple(PublicTool(name=t.name, description=t.description, input_schema=t.input_schema,
                              output_schema=t.output_schema) for t in sorted(profile.tools, key=lambda t: t.name)),
        stimuli=prepared.stimuli,
    )


class CommonPool(Model):
    schema_version: Literal["talos.common-opportunities.v1"] = "talos.common-opportunities.v1"
    opportunities: tuple[PublicOpportunity, ...]

    @model_validator(mode="after")
    def unique(self):
        if len({o.opportunity_id for o in self.opportunities}) != len(self.opportunities):
            raise ValueError("duplicate public opportunity")
        return self

    def digest(self):
        return content_hash(self)


class PublicGraphEdge(Model):
    source: str
    target: str
    relation: Literal["possible_invocation", "possible_data_flow"]


class PublicGraph(Model):
    schema_version: Literal["talos.public-graph.v1"] = "talos.public-graph.v1"
    nodes: tuple[str, ...]
    edges: tuple[PublicGraphEdge, ...]

    @model_validator(mode="after")
    def endpoints(self):
        if len(set(self.nodes)) != len(self.nodes):
            raise ValueError("duplicate public graph node")
        if any(e.source not in self.nodes or e.target not in self.nodes for e in self.edges):
            raise ValueError("unknown public graph endpoint")
        return self


def project_possible_graph(graph) -> PublicGraph:
    """Project PR-02 graph topology only; observed paths/private evidence excluded.

    The supplied profile graph itself still requires researcher review before study
    use. No graph truth, permission or independent target validity is established.
    """
    edges = set()
    nodes = set()
    for source, target, attrs in graph.edges(data=True):
        relation = attrs.get("relation")
        if relation in ("possible_invocation", "possible_data_flow"):
            nodes.update((source, target))
            edges.add((source, target, relation))
    return PublicGraph(nodes=tuple(sorted(nodes)), edges=tuple(PublicGraphEdge(
        source=a, target=b, relation=r) for a,b,r in sorted(edges)))


def arm_inputs(pool: CommonPool, *, graph_annotations: PublicGraph | dict | None = None) -> dict:
    """PR-07 hook only: no selector, scheduler, budget runner or feedback loop."""
    pool = CommonPool.model_validate(pool.model_dump())
    graph = None
    if graph_annotations is not None:
        raw = graph_annotations.model_dump() if isinstance(graph_annotations, PublicGraph) else graph_annotations
        projected = PublicGraph.model_validate(raw)
        inventory = {"input:user"} | {"tool:" + t.name for o in pool.opportunities for t in o.tools}
        if not set(projected.nodes) <= inventory:
            raise ValueError("graph contains nodes outside common public inventory")
        graph = projected.model_dump(mode="json")
    return {"common_pool_sha256": pool.digest(), "opportunities": pool.model_dump(mode="json")["opportunities"],
            "graph_annotations": graph}
