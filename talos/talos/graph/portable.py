"""Offline, evidence-bearing graphs for v2 profiles; legacy graph is untouched."""
from __future__ import annotations

import hashlib
import json
from typing import Literal

import networkx as nx
from pydantic import Field, model_validator

from talos.judging import EventStatus, Observation
from talos.profiles.classify import classify_profile
from talos.profiles.models import CLASSIFIER_VERSION, Model, TargetProfile, snapshot

GRAPH_VERSION = "talos.profile-graph.v2.0"


class ExecutionStep(Model):
    sequence: int = Field(ge=0, strict=True)
    observation: Observation


class ExecutionPath(Model):
    """A supplied trace sequence, not authenticated data flow or impact."""
    path_version: Literal["talos.execution-path.v2.0"] = "talos.execution-path.v2.0"
    path_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    reference: str = Field(min_length=1)
    steps: tuple[ExecutionStep, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def consistent_scope(self) -> ExecutionPath:
        if len({s.sequence for s in self.steps}) != len(self.steps):
            raise ValueError("duplicate sequence positions")
        actions = [s.observation.action for s in self.steps]
        if len({(a.target_id, a.scenario_id, a.run_id, a.repeat_id) for a in actions}) != 1:
            raise ValueError("path must share one target/scenario/run/repeat")
        if len({a.action_id for a in actions}) != len(actions):
            raise ValueError("duplicate path action IDs")
        event_ids = []
        for step in self.steps:
            for event in step.observation.events:
                if event.action_digest != step.observation.action.digest():
                    raise ValueError("trace event/action digest mismatch")
                event_ids.append(event.event_id)
        if len(set(event_ids)) != len(event_ids):
            raise ValueError("duplicate path trace event IDs")
        return self


def _text(schema: dict) -> bool:
    """Positive evidence of string-bearing schema only; no refs/network lookup."""
    kind = schema.get("type")
    if kind == "string" or isinstance(kind, list) and "string" in kind:
        return True
    properties = schema.get("properties", {})
    children = list(properties.values()) if isinstance(properties, dict) else []
    for keyword in ("anyOf", "oneOf", "allOf", "prefixItems"):
        if isinstance(schema.get(keyword), list):
            children.extend(schema[keyword])
    for keyword in ("items", "additionalProperties"):
        if isinstance(schema.get(keyword), dict):
            children.append(schema[keyword])
    return any(_text(child) for child in children if isinstance(child, dict))


def tool_node(name: str) -> str:
    return "tool:" + name


def build_profile_graph(profile: TargetProfile, *, paths: tuple[ExecutionPath, ...] = ()) -> nx.MultiDiGraph:
    """No target contact: static candidates and supplied call sequences coexist.

    Parallel edge types prevent an observed call order from overwriting or
    upgrading possible data flow. No edge asserts authorization or impact.
    """
    profile = snapshot(profile)
    paths = tuple(ExecutionPath.model_validate(p.model_dump()) for p in paths)
    if len({p.path_id for p in paths}) != len(paths):
        raise ValueError("duplicate path IDs")
    graph = nx.MultiDiGraph(
        graph_version=GRAPH_VERSION, classifier_version=CLASSIFIER_VERSION,
        target_id=profile.target_id, profile_version=profile.profile_version, profile_digest=profile.digest(),
        metadata_evidence=[e.model_dump(mode="json") for e in sorted(profile.evidence, key=lambda e: e.evidence_id)],
        omitted_observed_pairs=[], execution_paths=[],
    )
    graph.add_node("input:user", kind="input_surface", evidence="profile tool exposure declaration")
    tools = {t.name: t for t in profile.tools}
    classifications = {c.tool_name: c for c in classify_profile(profile)}
    for name in sorted(tools):
        tool = tools[name]
        graph.add_node(tool_node(name), kind="tool", name=name,
                       classification=classifications[name].model_dump(mode="json"),
                       input_schema=tool.input_schema, output_schema=tool.output_schema,
                       audit_capability_ids=list(tool.audit_capability_ids))
        graph.add_edge("input:user", tool_node(name), key=f"exposure:{name}",
                       relation="possible_invocation", evidence_ids=list(tool.evidence_ids),
                       basis="declared tool exposure; executable reachability unproven",
                       committed_impact="not_assessed")
    for flow in sorted(profile.possible_flows, key=lambda f: f.flow_id):
        graph.add_edge(tool_node(flow.source_tool), tool_node(flow.target_tool),
                       key=f"declared:{flow.flow_id}", relation="possible_data_flow",
                       evidence_ids=list(flow.evidence_ids), basis=flow.description,
                       committed_impact="not_assessed")
    for src in sorted(tools):
        for dst in sorted(tools):
            if src == dst:
                continue
            source, target = tools[src], tools[dst]
            sc, tc = classifications[src], classifications[dst]
            if (sc.output_trust.value != "trusted" and tc.side_effects != ("read_only",)
                    and _text(source.output_schema) and _text(target.input_schema)):
                graph.add_edge(tool_node(src), tool_node(dst), key=f"candidate:{src}:{dst}",
                               relation="possible_data_flow", evidence_ids=sorted(set(sc.evidence_ids + tc.evidence_ids)),
                               basis="string-bearing schemas; source trust untrusted/mixed/unknown; destination may have effects",
                               committed_impact="not_assessed")
    executed = {EventStatus.ACCEPTED, EventStatus.COMMITTED, EventStatus.FAILED,
                EventStatus.ROLLED_BACK, EventStatus.NO_EFFECT}
    for path in sorted(paths, key=lambda p: p.path_id):
        steps = sorted(path.steps, key=lambda s: s.sequence)
        path_data = path.model_dump(mode="json")
        path_data["steps"] = sorted(path_data["steps"], key=lambda s: s["sequence"])
        path_digest = hashlib.sha256(json.dumps(path_data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        graph.graph["execution_paths"].append({"path_id": path.path_id, "source_id": path.source_id,
                                               "reference": path.reference, "sha256": path_digest})
        for step in steps:
            a = step.observation.action
            if a.target_id != profile.target_id or a.tool_name not in tools:
                raise ValueError("observed path target/tool outside profile")
        for left, right in zip(steps, steps[1:]):
            def recorded_call(step):
                statuses = {e.status for e in step.observation.events}
                return bool(statuses & executed) and not statuses & {EventStatus.BLOCKED, EventStatus.UNKNOWN}
            if right.sequence != left.sequence + 1 or not (recorded_call(left) and recorded_call(right)):
                graph.graph["omitted_observed_pairs"].append({
                    "path_id": path.path_id, "sequences": [left.sequence, right.sequence],
                    "reason": "sequence gap, request-only, blocked, unknown or absent recorded execution; no gap bridging",
                })
                continue
            a, b = left.observation.action, right.observation.action
            graph.add_edge(tool_node(a.tool_name), tool_node(b.tool_name),
                           key=f"observed:{path.path_id}:{left.sequence}:{right.sequence}",
                           relation="observed_call_order", basis="caller-supplied sequence positions, not proven data dependency",
                           source_id=path.source_id, reference=path.reference,
                           scope={"target_id": a.target_id, "scenario_id": a.scenario_id,
                                  "run_id": a.run_id, "repeat_id": a.repeat_id},
                           action_digests=[a.digest(), b.digest()],
                           evidence_event_ids=sorted(e.event_id for s in (left, right) for e in s.observation.events),
                           committed_impact="not_assessed")
    return graph


def graph_json(graph: nx.MultiDiGraph) -> str:
    """Deterministic JSON export of this graph's evidence, not a signed artifact."""
    data = {"metadata": dict(graph.graph),
            "nodes": [{"id": n, **attrs} for n, attrs in sorted(graph.nodes(data=True))],
            "edges": [{"source": src, "target": dst, "key": key, **attrs}
                      for src, dst, key, attrs in sorted(graph.edges(keys=True, data=True), key=lambda x: x[:3])]}
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False)
