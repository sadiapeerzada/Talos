"""Synthetic schema/graph controls; no independent targets or attack runs."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest
from pydantic import ValidationError

from talos.graph.portable import ExecutionPath, ExecutionStep, build_profile_graph, graph_json, tool_node
from talos.harness.base import ToolParameter, ToolSpec
from talos.judging import (
    Action, AuditRecord, Authorization, EvidenceBundle, EventStatus, Observation,
    Outcome, PolicyAssessment, TraceEvent, judge,
)
from talos.profiles import ProfileBoundPolicy, TargetProfile, classify_profile, profile_from_tools

FIXTURE = Path(__file__).parent / "fixtures" / "portable_profiles.json"
DATA = json.loads(FIXTURE.read_text())


def profile(target="documents"):
    return TargetProfile.model_validate(next(p for p in DATA["profiles"] if p["target_id"] == target))


def action(name="copper_02", **changes):
    return Action(**(dict(target_id="documents", scenario_id="synthetic-case", run_id="test-run",
                         repeat_id="1", action_id=name, actor_id="test-actor", tool_name=name,
                         authorization_context_id="synthetic-context", arguments={"payload":"test"}) | changes))


def observation(a, status=EventStatus.ACCEPTED):
    return Observation(action=a, events=(TraceEvent(event_id="trace-"+a.action_id, action_digest=a.digest(),
        actor="synthetic-agent", provenance="synthetic-test-only", status=status),))


def path(statuses=(EventStatus.ACCEPTED, EventStatus.COMMITTED), **changes):
    steps = tuple(ExecutionStep(sequence=i, observation=observation(action(name), status))
                  for i, (name,status) in enumerate(zip(("copper_01", "copper_02"), statuses)))
    return ExecutionPath(**(dict(path_id="test-path", source_id="synthetic-trace",
                                reference="test-only-memory", steps=steps) | changes))


@pytest.mark.parametrize("target", ["documents", "operations", "ambiguous"])
def test_fixture_semantic_classification_and_exact_toy_counts(target):
    results = {c.tool_name: c for c in classify_profile(profile(target))}
    expected = DATA["expected_classifications"][target]
    for name, labels in expected.items():
        actual = results[name].model_dump(mode="json")
        assert {key: actual[key] for key in labels} == labels
    # These counts are toy-control correctness/abstention checks, not empirical accuracy.
    correct_permissions = sum(c.permission.value == expected[name]["permission"] for name,c in results.items())
    assert correct_permissions == len(expected)
    assert sum(c.permission.value == "unknown" for c in results.values()) == (3 if target == "ambiguous" else 0)


def test_unknown_tools_never_default_to_readonly_or_public():
    tools = [ToolSpec(name="search_safe_readonly", description="This sounds safe.",
                      parameters=[ToolParameter(name="unusual_param", type="string")])]
    p = profile_from_tools(tools, target_id="unfamiliar", domain="synthetic", source_id="test", reference="memory")
    result = classify_profile(p)[0]
    assert result.side_effects == ("unknown",) and result.permission.value == "unknown"
    assert result.output_trust.value == "unknown" and result.status == "incomplete"
    assert p.tools[0].input_schema["properties"]["unusual_param"]["type"] == "string"
    assert p.tools[0].output_schema == {}


def test_renamed_tools_and_parameters_do_not_change_semantics_or_edges():
    original = profile()
    renamed = original.model_dump(mode="json")
    names = {t.name: f"opaque_{i}" for i,t in enumerate(original.tools)}
    for t in renamed["tools"]:
        t["name"] = names[t["name"]]
        t["description"] = "Entirely different tool description."
        t["input_schema"] = json.loads(json.dumps(t["input_schema"]).replace('"selector"','"handle"').replace('"share"','"envelope"'))
    for f in renamed["possible_flows"]:
        f["source_tool"],f["target_tool"] = names[f["source_tool"]],names[f["target_tool"]]
    updated = TargetProfile.model_validate(renamed)
    before = {c.tool_name:c for c in classify_profile(original)}
    after = {c.tool_name:c for c in classify_profile(updated)}
    for name,new in names.items():
        assert before[name].side_effects == after[new].side_effects
        assert before[name].permission == after[new].permission
        assert before[name].roles == after[new].roles
    def relationships(graph, reverse):
        return {(reverse.get(graph.nodes[u].get("name"),graph.nodes[u].get("name",u)),reverse.get(graph.nodes[v].get("name"),graph.nodes[v].get("name",v)),d["relation"])
                for u,v,d in graph.edges(data=True)}
    assert relationships(build_profile_graph(original),{}) == relationships(build_profile_graph(updated),{v:k for k,v in names.items()})


def test_conflicting_metadata_abstains_and_preserves_reasons_and_provenance():
    classified = {c.tool_name:c for c in classify_profile(profile("ambiguous"))}
    c = classified["odd"]
    assert c.status == "conflicted"
    assert c.side_effects == ("unknown",) and c.permission.value == c.output_trust.value == "unknown"
    assert any("conflict" in r for r in c.reasons) and c.evidence_ids == ("metadata",)
    assert any("boundary" in r for r in classified["boundary_missing_version"].reasons)


def test_versions_json_roundtrip_and_nested_schema_preservation():
    p = profile("operations")
    assert TargetProfile.model_validate_json(p.model_dump_json()).model_dump_json() == p.model_dump_json()
    assert p.tools[0].output_schema["oneOf"][1]["properties"]["entries"]["items"]["type"] == "string"
    assert p.digest() == TargetProfile.model_validate_json(p.model_dump_json()).digest()
    payload = p.model_dump()
    payload["profile_version"] = "unrecognized"
    with pytest.raises(ValidationError):
        TargetProfile.model_validate(payload)


@pytest.mark.parametrize("mutation", ["unknown_evidence", "unknown_boundary", "unknown_capability", "unknown_flow_tool",
                                     "duplicate_tool", "duplicate_evidence", "false_independence", "nonfinite_schema"])
def test_invalid_metadata_references_are_rejected(mutation):
    payload = profile().model_dump(mode="json")
    if mutation == "unknown_evidence": payload["tools"][0]["evidence_ids"] = ["missing"]
    if mutation == "unknown_boundary": payload["tools"][0]["permissions"][0]["boundary_ids"] = ["missing"]
    if mutation == "unknown_capability": payload["tools"][0]["audit_capability_ids"] = ["missing"]
    if mutation == "unknown_flow_tool": payload["possible_flows"][0]["target_tool"] = "missing"
    if mutation == "duplicate_tool": payload["tools"].append(payload["tools"][0])
    if mutation == "duplicate_evidence": payload["evidence"].append(payload["evidence"][0])
    if mutation == "false_independence": payload["custody"]["independence_claimed"] = True
    if mutation == "nonfinite_schema": payload["tools"][0]["input_schema"] = {"minimum":float("nan")}
    with pytest.raises(ValidationError):
        TargetProfile.model_validate(payload)


def test_empty_inventory_is_explicit_and_does_not_imply_security():
    p = profile_from_tools([], target_id="empty", domain="unknown", source_id="test", reference="memory")
    assert classify_profile(p) == ()
    graph = build_profile_graph(p)
    assert graph.number_of_edges() == 0 and len(graph) == 1


def test_parallel_possible_and_observed_edges_preserve_sources():
    p = profile()
    graph = build_profile_graph(p, paths=(path(),))
    edges = graph[tool_node("copper_01")][tool_node("copper_02")]
    assert {d["relation"] for d in edges.values()} == {"possible_data_flow", "observed_call_order"}
    assert len(edges) == 3  # declared flow, schema candidate, supplied observed order
    for key, edge in edges.items():
        assert edge["basis"] and edge["committed_impact"] == "not_assessed"
        if key.startswith("observed:"):
            assert edge["source_id"] == "synthetic-trace" and len(edge["evidence_event_ids"]) == 2
            assert edge["scope"]["run_id"] == "test-run" and len(edge["action_digests"]) == 2
        else:
            assert edge["evidence_ids"] == ["metadata"]


def test_static_graph_contains_no_observed_relationships():
    graph = build_profile_graph(profile())
    assert not any(d["relation"].startswith("observed") for *_,d in graph.edges(data=True))
    assert graph.graph["metadata_evidence"][0]["origin"] == "operator_declaration"


@pytest.mark.parametrize("status", [EventStatus.REQUESTED,EventStatus.BLOCKED,EventStatus.UNKNOWN])
def test_requests_blocks_and_ambiguity_do_not_become_execution_paths(status):
    graph = build_profile_graph(profile(), paths=(path((status,EventStatus.COMMITTED)),))
    assert not any(d["relation"] == "observed_call_order" for *_,d in graph.edges(data=True))
    assert len(graph.graph["omitted_observed_pairs"]) == 1


def test_sequence_gaps_do_not_create_observed_edges():
    p = path().model_dump()
    p["steps"][1]["sequence"] = 3
    graph = build_profile_graph(profile(), paths=(ExecutionPath.model_validate(p),))
    assert len(graph.graph["omitted_observed_pairs"]) == 1
    assert not any(d["relation"] == "observed_call_order" for *_,d in graph.edges(data=True))


def test_graph_export_is_stable_and_observed_step_input_order_is_irrelevant():
    p = path()
    reverse = p.model_copy(update={"steps":tuple(reversed(p.steps))})
    first = graph_json(build_profile_graph(profile(),paths=(p,)))
    assert first == graph_json(build_profile_graph(profile(),paths=(reverse,)))
    assert json.loads(first)["metadata"]["profile_digest"] == profile().digest()


@pytest.mark.parametrize("field,value", [("target_id","other"),("run_id","other"),("repeat_id","2"),("scenario_id","other")])
def test_cross_context_trace_paths_are_rejected(field,value):
    first = action("copper_01")
    second = action("copper_02", **{field:value})
    with pytest.raises(ValidationError):
        path(steps=(ExecutionStep(sequence=0,observation=observation(first)),
                    ExecutionStep(sequence=1,observation=observation(second))))


def test_forged_trace_bindings_and_duplicate_ids_are_rejected():
    data = path().model_dump()
    data["steps"][1]["observation"]["events"][0]["action_digest"] = "0"*64
    with pytest.raises(ValidationError): ExecutionPath.model_validate(data)
    data = path().model_dump()
    data["steps"][1]["sequence"] = 0
    with pytest.raises(ValidationError): ExecutionPath.model_validate(data)
    with pytest.raises(ValueError): build_profile_graph(profile(),paths=(path(),path()))
    unknown = action("unlisted")
    with pytest.raises(ValueError):
        build_profile_graph(profile(),paths=(path(steps=(ExecutionStep(sequence=0,observation=observation(unknown)),)),))


class TestPolicy:
    __test__ = False
    def __init__(self, authorization=Authorization.DENIED, rule_id="test-rule"):
        self.authorization,self.rule_id=authorization,rule_id
    def assess(self,a):
        return PolicyAssessment(action_digest=a.digest(),authorization=self.authorization,
            policy_id="test-policy",policy_version="1",rule_id=self.rule_id,reason="Synthetic policy control only.")


class TestReader:
    __test__ = False
    def read(self,a):
        record = AuditRecord(evidence_id="synthetic-event",source_id="synthetic-test-audit",action_digest=a.digest(),
            kind="audit",status=EventStatus.COMMITTED,effect_occurred=True,effect_id="test-effect",receipt_id="test-receipt")
        return EvidenceBundle(complete=True,records=(record,))


def test_profile_and_oracle_interoperate_without_auto_trusting_audit_capability():
    obs = observation(action())
    bound = ProfileBoundPolicy(profile(), TestPolicy())
    assert judge(obs,policy=bound,evidence_reader=TestReader()).status == Outcome.UNKNOWN
    assert judge(obs,policy=bound,evidence_reader=TestReader(),
                 trusted_source_ids=frozenset({"synthetic-test-audit"})).status == Outcome.CONFIRMED
    assert judge(obs,policy=ProfileBoundPolicy(profile()),evidence_reader=TestReader(),
                 trusted_source_ids=frozenset({"synthetic-test-audit"})).status == Outcome.UNKNOWN


@pytest.mark.parametrize("a", [action(target_id="wrong-target"),action(name="missing")])
def test_profile_policy_refuses_out_of_scope_action(a):
    assert ProfileBoundPolicy(profile(),TestPolicy(Authorization.ALLOWED)).assess(a).authorization == Authorization.UNKNOWN


def test_missing_conflicting_permissions_and_mismatched_policy_do_not_grant_authority():
    for name in ("lookup_safe_readonly","odd","boundary_missing_version"):
        a = action(name,target_id="ambiguous")
        assert ProfileBoundPolicy(profile("ambiguous"),TestPolicy(Authorization.ALLOWED)).assess(a).authorization == Authorization.UNKNOWN
    assert ProfileBoundPolicy(profile(),TestPolicy(rule_id="different-rule")).assess(action()).authorization == Authorization.UNKNOWN


def test_profile_snapshots_and_portable_import_have_no_fixture_dependency():
    p = profile()
    bound = ProfileBoundPolicy(p,TestPolicy())
    p.tools[1].input_schema["changed_after_binding"] = True
    assert bound.assess(action()).authorization == Authorization.DENIED
    script = "import sys; import talos.profiles; import talos.graph.portable; assert not any(n.startswith('talos.sample_agents') for n in sys.modules)"
    subprocess.run([sys.executable,"-c",script],check=True,capture_output=True,text=True)


@pytest.mark.parametrize("target,expected", [
    ("documents", {("copper_01","copper_02")}),
    ("operations", {("lumen_alpha","lumen_beta"),("lumen_alpha","lumen_gamma"),("lumen_alpha","lumen_delta")}),
])
def test_schema_candidate_edge_precision_recall_against_toy_expectations(target, expected):
    graph = build_profile_graph(profile(target))
    actual = {(graph.nodes[u]["name"],graph.nodes[v]["name"])
              for u,v,k,d in graph.edges(keys=True,data=True) if k.startswith("candidate:")}
    # Exact fixture-only numerators/denominators, not held-out empirical accuracy.
    assert len(actual & expected) == len(expected)
    assert len(actual - expected) == 0 and len(expected - actual) == 0
    assert actual == expected


def test_schema_refs_are_preserved_but_never_fetched_or_assumed_safe():
    payload = profile().model_dump(mode="json")
    payload["possible_flows"] = []
    payload["tools"][0]["output_schema"] = {"$ref":"https://unresolved.invalid/test-schema"}
    payload["tools"][0]["output_trust"] = []
    p = TargetProfile.model_validate(payload)
    graph = build_profile_graph(p)
    assert not any(k.startswith("candidate:") for *_,k in graph.edges(keys=True))
    source = graph.nodes[tool_node("copper_01")]
    assert source["classification"]["output_trust"] == "unknown"
    assert source["output_schema"]["$ref"] == "https://unresolved.invalid/test-schema"


def test_profile_cannot_self_declare_trusted_or_approved_integration():
    payload = profile().model_dump(mode="json")
    payload["audit_capabilities"][0]["trusted"] = True
    with pytest.raises(ValidationError):
        TargetProfile.model_validate(payload)


def test_public_declaration_still_requires_an_explicit_policy_delegate():
    payload = profile().model_dump(mode="json")
    payload["tools"][0]["permissions"][0]["permission"] = "public"
    p = TargetProfile.model_validate(payload)
    assert next(c for c in classify_profile(p) if c.tool_name == "copper_01").permission.value == "public"
    assert ProfileBoundPolicy(p).assess(action("copper_01")).authorization == Authorization.UNKNOWN


def test_unchecked_profile_copy_is_revalidated():
    with pytest.raises(ValidationError):
        build_profile_graph(profile().model_copy(update={"profile_version":"invalid"}))


def test_unknown_tool_mentioned_in_a_single_target_path_is_rejected():
    steps = (ExecutionStep(sequence=0,observation=observation(action("unlisted"))),)
    with pytest.raises(ValueError):
        build_profile_graph(profile(),paths=(path(steps=steps),))


def test_policy_delegate_must_bind_the_exact_action_and_rule_version():
    class WrongDigest(TestPolicy):
        def assess(self,a):
            return super().assess(action("copper_02",repeat_id="other"))
    class WrongVersion(TestPolicy):
        def assess(self,a):
            return super().assess(a).model_copy(update={"policy_version":"other"})
    assert ProfileBoundPolicy(profile(),WrongDigest()).assess(action()).authorization == Authorization.UNKNOWN
    assert ProfileBoundPolicy(profile(),WrongVersion()).assess(action()).authorization == Authorization.UNKNOWN


def test_empty_inventory_parameters_remain_empty_and_duplicates_are_rejected():
    duplicate = ToolSpec(name="test-tool",description="test-only",
                         parameters=[ToolParameter(name="x"),ToolParameter(name="x")])
    with pytest.raises(ValueError):
        profile_from_tools([duplicate],target_id="test",domain="test",source_id="test",reference="memory")


def test_graph_snapshot_is_unchanged_when_caller_mutates_profile_schemas():
    p = profile()
    graph = build_profile_graph(p)
    before = graph_json(graph)
    p.tools[0].output_schema.clear()
    assert graph_json(graph) == before
    assert graph.graph["profile_digest"] != p.digest()


def test_observed_trace_content_is_hash_bound_without_becoming_impact_evidence():
    first = path()
    data = first.model_dump()
    data["steps"][1]["observation"]["events"][0]["status"] = "FAILED"
    changed = ExecutionPath.model_validate(data)
    graphs = [build_profile_graph(profile(),paths=(p,)) for p in (first,changed)]
    assert graphs[0].graph["execution_paths"][0]["sha256"] != graphs[1].graph["execution_paths"][0]["sha256"]
    for graph in graphs:
        observed = [d for *_,d in graph.edges(data=True) if d["relation"] == "observed_call_order"]
        assert len(observed) == 1 and observed[0]["committed_impact"] == "not_assessed"


def test_absent_permission_does_not_become_low_privilege_from_known_effect():
    data = profile().model_dump(mode="json")
    data["tools"][0]["permissions"] = []
    result = next(c for c in classify_profile(TargetProfile.model_validate(data)) if c.tool_name == "copper_01")
    assert result.side_effects == ("read_only",)  # explicit declaration only; not a safety verdict
    assert result.permission.value == "unknown" and result.status == "incomplete"


def test_conflicted_permissions_retain_boundary_provenance_for_review():
    data = profile("ambiguous").model_dump(mode="json")
    evidence = dict(data["evidence"][0])
    evidence.update(evidence_id="boundary-metadata",reference="test-only-boundary-source")
    data["evidence"].append(evidence)
    data["authorization_boundaries"][0]["evidence_ids"] = ["boundary-metadata"]
    result = next(c for c in classify_profile(TargetProfile.model_validate(data)) if c.tool_name == "odd")
    assert result.permission.value == "unknown" and result.status == "conflicted"
    assert result.evidence_ids == ("boundary-metadata", "metadata")
