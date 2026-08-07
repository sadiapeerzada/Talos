from __future__ import annotations

from talos.attacks.engine import generate_all
from talos.attacks.models import EXPLOIT_CLASSES, AttackContext
from talos.cli import build_agent
from talos.execution.dedup import deduplicate
from talos.execution.scoring import score_attack
from talos.graph.discovery import build_tool_graph


def _full_scan(adapter_name: str, target: str, repro_runs: int = 2):
    agent = build_agent(adapter_name, target)
    tools = agent.list_tools()
    graph = build_tool_graph(tools)
    ctx = AttackContext(graph=graph, seed_order_ids=["1001", "1003"], poisoned_order_ids=["1002"])
    attacks = generate_all(ctx)
    findings = [score_attack(agent, a, repro_runs=repro_runs) for a in attacks]
    return deduplicate(findings), attacks


def _finding_key(f):
    return (f.exploit_class, f.target_tool, f.outcome, f.severity.value, tuple(sorted(v.template_id for v in f.variants)))


def test_generates_35_templates_across_7_classes(native_server_url):
    agent = build_agent("native", native_server_url)
    graph = build_tool_graph(agent.list_tools())
    ctx = AttackContext(graph=graph)
    attacks = generate_all(ctx)
    assert len(attacks) == 35
    assert {a.exploit_class for a in attacks} == set(EXPLOIT_CLASSES)


def test_scan_finds_all_exploit_classes(native_server_url):
    findings, attacks = _full_scan("native", native_server_url)
    successful_classes = {f.exploit_class for f in findings if f.outcome == "success"}
    assert successful_classes == set(EXPLOIT_CLASSES)


def test_adapters_produce_identical_deduplicated_findings(native_server_url, langchain_server_url):
    native_findings, _ = _full_scan("native", native_server_url)
    lc_findings, _ = _full_scan("langchain", langchain_server_url)

    native_keys = sorted(_finding_key(f) for f in native_findings)
    lc_keys = sorted(_finding_key(f) for f in lc_findings)
    assert native_keys == lc_keys


def test_over_refund_is_flagged_with_correct_overage(native_server_url):
    findings, attacks = _full_scan("native", native_server_url)
    direct_refund = next(f for f in findings if f.exploit_class == "direct_injection" and f.target_tool == "issue_refund")
    assert direct_refund.outcome == "success"
    variant = direct_refund.variants[0]
    assert "refund_overage" in variant.evidence
    assert variant.evidence["refund_overage"]["overage"] > 0


def test_exfiltration_email_flagged_as_external(native_server_url):
    findings, _ = _full_scan("native", native_server_url)
    exfil = next(f for f in findings if f.exploit_class == "data_exfiltration")
    assert exfil.outcome == "success"
    variant = exfil.variants[0]
    assert variant.evidence["suspicious_email"]["is_external"] is True
