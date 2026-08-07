"""Cross-engagement learning persistence and summarization."""

from __future__ import annotations

import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, Field

from talos.execution.scoring import ScoredFinding
from talos.storage import default_db_path


class RankedStat(BaseModel):
    key: str
    attempts: int
    successes: int
    avg_reproducibility: float
    success_rate: float
    weighted_score: float


class LearningSummary(BaseModel):
    total_findings: int
    successful_findings: int
    exploit_class_stats: list[RankedStat] = Field(default_factory=list)
    template_stats: list[RankedStat] = Field(default_factory=list)
    target_tool_stats: list[RankedStat] = Field(default_factory=list)


@dataclass
class LearningHints:
    template_scores: dict[str, float] = field(default_factory=dict)
    exploit_class_scores: dict[str, float] = field(default_factory=dict)


class LearningStore:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path is not None else default_db_path()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS learning_findings (
                    learning_id TEXT PRIMARY KEY,
                    recorded_at REAL NOT NULL,
                    target TEXT NOT NULL,
                    adapter TEXT NOT NULL,
                    strategy TEXT NOT NULL,
                    template_id TEXT NOT NULL,
                    exploit_class TEXT NOT NULL,
                    target_tool TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    reproducibility REAL NOT NULL,
                    origin TEXT NOT NULL
                )
                """
            )

    def record_scan(
        self,
        *,
        target: str,
        adapter: str,
        strategy: str,
        findings: list[ScoredFinding],
    ) -> None:
        recorded_at = time.time()
        rows = [
            (
                uuid.uuid4().hex,
                recorded_at,
                target,
                adapter,
                strategy,
                finding.template_id,
                finding.exploit_class,
                finding.target_tool,
                finding.outcome,
                finding.severity.value,
                finding.reproducibility,
                getattr(finding, "origin", "template"),
            )
            for finding in findings
        ]
        with sqlite3.connect(self._db_path) as conn:
            conn.executemany(
                """
                INSERT INTO learning_findings (
                    learning_id, recorded_at, target, adapter, strategy,
                    template_id, exploit_class, target_tool, outcome,
                    severity, reproducibility, origin
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def get_hints(self) -> LearningHints:
        return LearningHints(
            template_scores=self._aggregate_scores("template_id"),
            exploit_class_scores=self._aggregate_scores("exploit_class"),
        )

    def get_summary(self, limit: int = 5) -> LearningSummary:
        total_findings = self._scalar("SELECT COUNT(*) FROM learning_findings")
        successful_findings = self._scalar("SELECT COUNT(*) FROM learning_findings WHERE outcome = 'success'")
        return LearningSummary(
            total_findings=total_findings,
            successful_findings=successful_findings,
            exploit_class_stats=self._ranked_stats("exploit_class", limit),
            template_stats=self._ranked_stats("template_id", limit),
            target_tool_stats=self._ranked_stats("target_tool", limit),
        )

    def _scalar(self, query: str) -> int:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(query).fetchone()
        return int(row[0] or 0)

    def _aggregate_scores(self, column: str) -> dict[str, float]:
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                f"""
                SELECT {column},
                       COUNT(*) AS attempts,
                       SUM(CASE WHEN outcome = 'success' THEN 1 ELSE 0 END) AS successes,
                       AVG(reproducibility) AS avg_repro
                FROM learning_findings
                GROUP BY {column}
                """
            ).fetchall()

        scores: dict[str, float] = {}
        for key, attempts, successes, avg_repro in rows:
            if not key:
                continue
            success_rate = (successes or 0) / max(1, attempts or 0)
            score = round((success_rate * 0.7) + ((avg_repro or 0.0) * 0.3), 4)
            scores[str(key)] = score
        return scores

    def _ranked_stats(self, column: str, limit: int) -> list[RankedStat]:
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                f"""
                SELECT {column},
                       COUNT(*) AS attempts,
                       SUM(CASE WHEN outcome = 'success' THEN 1 ELSE 0 END) AS successes,
                       AVG(reproducibility) AS avg_repro
                FROM learning_findings
                GROUP BY {column}
                ORDER BY ((SUM(CASE WHEN outcome = 'success' THEN 1 ELSE 0 END) * 1.0 / COUNT(*)) * 0.7)
                       + (AVG(reproducibility) * 0.3) DESC,
                         attempts DESC,
                         {column} ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        ranked: list[RankedStat] = []
        for key, attempts, successes, avg_repro in rows:
            attempts = int(attempts or 0)
            successes = int(successes or 0)
            avg_repro = round(float(avg_repro or 0.0), 2)
            success_rate = round(successes / max(1, attempts), 2)
            weighted_score = round((success_rate * 0.7) + (avg_repro * 0.3), 2)
            ranked.append(
                RankedStat(
                    key=str(key),
                    attempts=attempts,
                    successes=successes,
                    avg_reproducibility=avg_repro,
                    success_rate=success_rate,
                    weighted_score=weighted_score,
                )
            )
        return ranked
