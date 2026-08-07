from __future__ import annotations

from talos.attacks.engine import generate_next_round
from talos.attacks.models import AttackContext
from talos.cli import build_agent
from talos.execution.scoring import score_attack
from talos.graph.discovery import build_tool_graph
from talos.scan_service import run_scan_pipeline


def test_adaptive_generation_emits_refinement_variants(native_server_url):
    agent = build_agent("native", native_server_url)
    ctx = AttackContext(graph=build_tool_graph(agent.list_tools()), generation_strategy="adaptive")

    first_batch = generate_next_round([], ctx, batch_size=4)
    assert first_batch
    assert all(attack.origin == "template" for attack in first_batch)

    first_results = [score_attack(agent, attack, repro_runs=1) for attack in first_batch[:2]]
    second_batch = generate_next_round(first_results, ctx, batch_size=4)

    assert any(attack.origin == "adaptive" for attack in second_batch)
    assert any("-R1" in attack.template_id for attack in second_batch)


def test_adaptive_scan_runs_more_than_base_template_count(native_server_url):
    report, events = run_scan_pipeline(
        target=native_server_url,
        adapter_name="native",
        repro_runs=1,
        generation_strategy="adaptive",
    )

    final_event = events[-1]
    assert final_event.type == "completed"
    assert final_event.stats.attacks_run > 35
    assert report.stats.attack_templates_run == final_event.stats.attacks_run
