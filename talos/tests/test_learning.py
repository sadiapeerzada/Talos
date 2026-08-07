from __future__ import annotations

from pathlib import Path

from talos.attacks.engine import generate_next_round
from talos.attacks.models import AttackContext
from talos.cli import build_agent
from talos.execution.scoring import ScoredFinding, Severity
from talos.graph.discovery import build_tool_graph
from talos.learning import LearningStore


def test_learning_store_summarizes_and_ranks_findings(tmp_path: Path):
    store = LearningStore(db_path=tmp_path / "learning.db")
    store.record_scan(
        target="http://example.test/agent",
        adapter="native",
        strategy="template",
        findings=[
            ScoredFinding(
                template_id="A1",
                exploit_class="direct_injection",
                name="A1",
                target_tool="issue_refund",
                outcome="success",
                severity=Severity.HIGH,
                reproducibility=1.0,
                evidence={},
                messages=["x"],
            ),
            ScoredFinding(
                template_id="A1",
                exploit_class="direct_injection",
                name="A1",
                target_tool="issue_refund",
                outcome="success",
                severity=Severity.HIGH,
                reproducibility=0.8,
                evidence={},
                messages=["x"],
            ),
            ScoredFinding(
                template_id="B1",
                exploit_class="indirect_injection",
                name="B1",
                target_tool="lookup_order",
                outcome="fail",
                severity=Severity.NONE,
                reproducibility=0.0,
                evidence={},
                messages=["y"],
            ),
        ],
    )

    hints = store.get_hints()
    assert hints.template_scores["A1"] > hints.template_scores["B1"]
    assert hints.exploit_class_scores["direct_injection"] > hints.exploit_class_scores["indirect_injection"]

    summary = store.get_summary()
    assert summary.total_findings == 3
    assert summary.successful_findings == 2
    assert summary.template_stats[0].key == "A1"


def test_learning_hints_prioritize_future_batches(native_server_url, tmp_path: Path):
    store = LearningStore(db_path=tmp_path / "learning.db")
    store.record_scan(
        target=native_server_url,
        adapter="native",
        strategy="template",
        findings=[
            ScoredFinding(
                template_id="E5",
                exploit_class="goal_hijacking",
                name="E5",
                target_tool="issue_refund",
                outcome="success",
                severity=Severity.CRITICAL,
                reproducibility=1.0,
                evidence={},
                messages=["x"],
            )
        ],
    )

    agent = build_agent("native", native_server_url)
    graph = build_tool_graph(agent.list_tools())
    hints = store.get_hints()
    ctx = AttackContext(
        graph=graph,
        template_success_scores=hints.template_scores,
        exploit_class_success_scores=hints.exploit_class_scores,
    )

    next_batch = generate_next_round([], ctx, batch_size=1)
    assert next_batch[0].template_id == "E5"
