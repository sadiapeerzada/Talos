"""Recurring scan monitoring with persistent local storage for the dashboard."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, Field

from talos.reporting.report import ScanReport
from talos.scan_service import (
    DEFAULT_GENERATION_STRATEGY,
    DEFAULT_POISONED_ORDER_IDS,
    DEFAULT_SEED_ORDER_IDS,
    run_scan_pipeline,
)


def _default_db_path() -> Path:
    base = Path.home() / ".talos"
    base.mkdir(parents=True, exist_ok=True)
    return base / "dashboard.db"


class MonitorConfig(BaseModel):
    target: str
    adapter: str
    attacker_email: str
    seed_order_ids: list[str] = Field(default_factory=lambda: list(DEFAULT_SEED_ORDER_IDS))
    poisoned_order_ids: list[str] = Field(default_factory=lambda: list(DEFAULT_POISONED_ORDER_IDS))
    repro_runs: int = 3
    strategy: str = DEFAULT_GENERATION_STRATEGY
    attack_model: str = "claude-sonnet-4-5"
    interval_seconds: float = 60.0
    max_runs: int | None = None


class MonitorRunSummary(BaseModel):
    run_id: str
    started_at: float
    finished_at: float | None = None
    duration_seconds: float | None = None
    status: str
    message: str
    report: ScanReport | None = None
    error: str | None = None


class AlertRecord(BaseModel):
    alert_id: str
    monitor_id: str
    run_id: str | None = None
    created_at: float
    severity: str
    kind: str
    title: str
    message: str


class MonitorSnapshot(BaseModel):
    monitor_id: str
    config: MonitorConfig
    status: str
    active: bool
    created_at: float
    started_at: float | None = None
    last_finished_at: float | None = None
    next_run_at: float | None = None
    run_count: int = 0
    latest_report: ScanReport | None = None
    last_error: str | None = None
    history: list[MonitorRunSummary] = Field(default_factory=list)


@dataclass
class _MonitorRecord:
    monitor_id: str
    config: MonitorConfig
    created_at: float
    stop_event: threading.Event
    thread: threading.Thread | None = None
    status: str = "scheduled"
    active: bool = True
    started_at: float | None = None
    last_finished_at: float | None = None
    next_run_at: float | None = None
    run_count: int = 0
    latest_report: ScanReport | None = None
    last_error: str | None = None
    history: list[MonitorRunSummary] = field(default_factory=list)

    def snapshot(self) -> MonitorSnapshot:
        return MonitorSnapshot(
            monitor_id=self.monitor_id,
            config=self.config,
            status=self.status,
            active=self.active,
            created_at=self.created_at,
            started_at=self.started_at,
            last_finished_at=self.last_finished_at,
            next_run_at=self.next_run_at,
            run_count=self.run_count,
            latest_report=self.latest_report,
            last_error=self.last_error,
            history=list(self.history),
        )


class MonitoringManager:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self._lock = threading.Lock()
        self._db_path = Path(db_path) if db_path is not None else _default_db_path()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._monitors: dict[str, _MonitorRecord] = {}
        self._ensure_schema()
        self._load_monitors_from_db()

    @property
    def db_path(self) -> Path:
        return self._db_path

    def create_monitor(self, config: MonitorConfig) -> MonitorSnapshot:
        if config.interval_seconds <= 0:
            raise ValueError("interval_seconds must be greater than 0")
        if config.max_runs is not None and config.max_runs <= 0:
            raise ValueError("max_runs must be greater than 0 when provided")

        monitor_id = uuid.uuid4().hex
        record = _MonitorRecord(
            monitor_id=monitor_id,
            config=config,
            created_at=time.time(),
            stop_event=threading.Event(),
        )
        worker = threading.Thread(target=self._run_monitor, args=(monitor_id,), daemon=True)
        record.thread = worker
        with self._lock:
            self._monitors[monitor_id] = record
            self._save_monitor(record)
        worker.start()
        return record.snapshot()

    def list_monitors(self) -> list[MonitorSnapshot]:
        with self._lock:
            return [record.snapshot() for record in sorted(self._monitors.values(), key=lambda item: item.created_at, reverse=True)]

    def get_monitor(self, monitor_id: str) -> MonitorSnapshot:
        with self._lock:
            record = self._monitors.get(monitor_id)
            if record is None:
                raise KeyError(monitor_id)
            return record.snapshot()

    def stop_monitor(self, monitor_id: str) -> MonitorSnapshot:
        with self._lock:
            record = self._monitors.get(monitor_id)
            if record is None:
                raise KeyError(monitor_id)
            record.stop_event.set()
            record.active = False
            if record.status not in {"completed", "failed"}:
                record.status = "stopping"
                record.next_run_at = None
            self._save_monitor(record)
            return record.snapshot()

    def list_alerts(self, limit: int = 50, monitor_id: str | None = None) -> list[AlertRecord]:
        query = (
            "SELECT alert_id, monitor_id, run_id, created_at, severity, kind, title, message "
            "FROM alerts "
        )
        params: list[object] = []
        if monitor_id is not None:
            query += "WHERE monitor_id = ? "
            params.append(monitor_id)
        query += "ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(query, params).fetchall()

        return [
            AlertRecord(
                alert_id=row[0],
                monitor_id=row[1],
                run_id=row[2],
                created_at=row[3],
                severity=row[4],
                kind=row[5],
                title=row[6],
                message=row[7],
            )
            for row in rows
        ]

    def _ensure_schema(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitors (
                    monitor_id TEXT PRIMARY KEY,
                    config_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    active INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    started_at REAL,
                    last_finished_at REAL,
                    next_run_at REAL,
                    run_count INTEGER NOT NULL,
                    latest_report_json TEXT,
                    last_error TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitor_runs (
                    run_id TEXT PRIMARY KEY,
                    monitor_id TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    finished_at REAL,
                    duration_seconds REAL,
                    status TEXT NOT NULL,
                    message TEXT NOT NULL,
                    report_json TEXT,
                    error TEXT,
                    FOREIGN KEY(monitor_id) REFERENCES monitors(monitor_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    monitor_id TEXT NOT NULL,
                    run_id TEXT,
                    created_at REAL NOT NULL,
                    severity TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    FOREIGN KEY(monitor_id) REFERENCES monitors(monitor_id),
                    FOREIGN KEY(run_id) REFERENCES monitor_runs(run_id)
                )
                """
            )

    def _load_monitors_from_db(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                """
                SELECT monitor_id, config_json, status, active, created_at, started_at,
                       last_finished_at, next_run_at, run_count, latest_report_json, last_error
                FROM monitors
                ORDER BY created_at DESC
                """
            ).fetchall()

        for row in rows:
            config = MonitorConfig.model_validate_json(row[1])
            latest_report = ScanReport.model_validate_json(row[9]) if row[9] else None
            status = row[2]
            active = bool(row[3])
            if active:
                active = False
                status = "stopped"
            record = _MonitorRecord(
                monitor_id=row[0],
                config=config,
                created_at=row[4],
                stop_event=threading.Event(),
                status=status,
                active=active,
                started_at=row[5],
                last_finished_at=row[6],
                next_run_at=None if not active else row[7],
                run_count=row[8],
                latest_report=latest_report,
                last_error=row[10],
                history=self._load_history(row[0]),
            )
            self._monitors[row[0]] = record
            self._save_monitor(record)

    def _load_history(self, monitor_id: str, limit: int = 20) -> list[MonitorRunSummary]:
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                """
                SELECT run_id, started_at, finished_at, duration_seconds, status, message, report_json, error
                FROM monitor_runs
                WHERE monitor_id = ?
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (monitor_id, limit),
            ).fetchall()

        return [
            MonitorRunSummary(
                run_id=row[0],
                started_at=row[1],
                finished_at=row[2],
                duration_seconds=row[3],
                status=row[4],
                message=row[5],
                report=ScanReport.model_validate_json(row[6]) if row[6] else None,
                error=row[7],
            )
            for row in rows
        ]

    def _save_monitor(self, record: _MonitorRecord) -> None:
        latest_report_json = record.latest_report.model_dump_json() if record.latest_report is not None else None
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT INTO monitors (
                    monitor_id, config_json, status, active, created_at, started_at,
                    last_finished_at, next_run_at, run_count, latest_report_json, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(monitor_id) DO UPDATE SET
                    config_json = excluded.config_json,
                    status = excluded.status,
                    active = excluded.active,
                    created_at = excluded.created_at,
                    started_at = excluded.started_at,
                    last_finished_at = excluded.last_finished_at,
                    next_run_at = excluded.next_run_at,
                    run_count = excluded.run_count,
                    latest_report_json = excluded.latest_report_json,
                    last_error = excluded.last_error
                """,
                (
                    record.monitor_id,
                    record.config.model_dump_json(),
                    record.status,
                    int(record.active),
                    record.created_at,
                    record.started_at,
                    record.last_finished_at,
                    record.next_run_at,
                    record.run_count,
                    latest_report_json,
                    record.last_error,
                ),
            )

    def _save_run(self, monitor_id: str, run: MonitorRunSummary) -> None:
        report_json = run.report.model_dump_json() if run.report is not None else None
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO monitor_runs (
                    run_id, monitor_id, started_at, finished_at, duration_seconds,
                    status, message, report_json, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    monitor_id,
                    run.started_at,
                    run.finished_at,
                    run.duration_seconds,
                    run.status,
                    run.message,
                    report_json,
                    run.error,
                ),
            )

    def _save_alert(self, alert: AlertRecord) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, monitor_id, run_id, created_at, severity, kind, title, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.monitor_id,
                    alert.run_id,
                    alert.created_at,
                    alert.severity,
                    alert.kind,
                    alert.title,
                    alert.message,
                ),
            )

    @staticmethod
    def _make_alert(
        *,
        monitor_id: str,
        run_id: str | None,
        severity: str,
        kind: str,
        title: str,
        message: str,
    ) -> AlertRecord:
        return AlertRecord(
            alert_id=uuid.uuid4().hex,
            monitor_id=monitor_id,
            run_id=run_id,
            created_at=time.time(),
            severity=severity,
            kind=kind,
            title=title,
            message=message,
        )

    def _alerts_for_report(
        self,
        *,
        record: _MonitorRecord,
        run_id: str,
        previous_report: ScanReport | None,
        current_report: ScanReport | None,
        run_error: str | None,
    ) -> list[AlertRecord]:
        alerts: list[AlertRecord] = []
        if run_error is not None:
            alerts.append(
                self._make_alert(
                    monitor_id=record.monitor_id,
                    run_id=run_id,
                    severity="high",
                    kind="monitor_run_failed",
                    title="Recurring scan failed",
                    message=f"Monitor for {record.config.target} failed with error: {run_error}",
                )
            )
            return alerts

        if current_report is None:
            return alerts

        current_counts = current_report.stats.severity_counts
        previous_counts = previous_report.stats.severity_counts if previous_report is not None else None
        previous_critical = previous_counts.critical if previous_counts is not None else 0
        previous_high = previous_counts.high if previous_counts is not None else 0
        previous_findings = len(previous_report.findings) if previous_report is not None else 0
        current_findings = len(current_report.findings)

        if current_counts.critical > previous_critical:
            alerts.append(
                self._make_alert(
                    monitor_id=record.monitor_id,
                    run_id=run_id,
                    severity="critical",
                    kind="critical_findings_increased",
                    title="Critical findings increased",
                    message=(
                        f"{record.config.target} now has {current_counts.critical} critical finding(s), "
                        f"up from {previous_critical}."
                    ),
                )
            )

        if current_counts.high > previous_high:
            alerts.append(
                self._make_alert(
                    monitor_id=record.monitor_id,
                    run_id=run_id,
                    severity="high",
                    kind="high_findings_increased",
                    title="High-severity findings increased",
                    message=(
                        f"{record.config.target} now has {current_counts.high} high finding(s), "
                        f"up from {previous_high}."
                    ),
                )
            )

        if current_findings > previous_findings:
            alerts.append(
                self._make_alert(
                    monitor_id=record.monitor_id,
                    run_id=run_id,
                    severity="medium",
                    kind="findings_increased",
                    title="Total findings increased",
                    message=(
                        f"{record.config.target} now has {current_findings} reproduced finding(s), "
                        f"up from {previous_findings}."
                    ),
                )
            )

        return alerts

    def _run_monitor(self, monitor_id: str) -> None:
        while True:
            with self._lock:
                record = self._monitors[monitor_id]
                if record.stop_event.is_set():
                    record.active = False
                    if record.status not in {"completed", "failed"}:
                        record.status = "stopped"
                    record.next_run_at = None
                    self._save_monitor(record)
                    return
                if record.config.max_runs is not None and record.run_count >= record.config.max_runs:
                    record.active = False
                    record.status = "completed"
                    record.next_run_at = None
                    self._save_monitor(record)
                    return

                previous_report = record.latest_report
                run_id = uuid.uuid4().hex
                started_at = time.time()
                record.status = "running"
                record.started_at = started_at
                record.next_run_at = None
                run_summary = MonitorRunSummary(
                    run_id=run_id,
                    started_at=started_at,
                    status="running",
                    message="Scan in progress.",
                )
                record.history.insert(0, run_summary)
                record.history = record.history[:20]
                self._save_monitor(record)
                self._save_run(record.monitor_id, run_summary)

            try:
                report, _ = run_scan_pipeline(
                    target=record.config.target,
                    adapter_name=record.config.adapter,
                    seed_order_ids=record.config.seed_order_ids,
                    poisoned_order_ids=record.config.poisoned_order_ids,
                    attacker_email=record.config.attacker_email,
                    repro_runs=record.config.repro_runs,
                    generation_strategy=record.config.strategy,
                    attack_model=record.config.attack_model,
                )
                finished_at = time.time()
                with self._lock:
                    record = self._monitors[monitor_id]
                    record.run_count += 1
                    record.latest_report = report
                    record.last_finished_at = finished_at
                    record.last_error = None
                    completed_run = MonitorRunSummary(
                        run_id=run_id,
                        started_at=started_at,
                        finished_at=finished_at,
                        duration_seconds=round(finished_at - started_at, 2),
                        status="succeeded",
                        message="Recurring scan completed.",
                        report=report,
                    )
                    record.history[0] = completed_run
                    self._save_run(record.monitor_id, completed_run)
                    for alert in self._alerts_for_report(
                        record=record,
                        run_id=run_id,
                        previous_report=previous_report,
                        current_report=report,
                        run_error=None,
                    ):
                        self._save_alert(alert)
                    if record.config.max_runs is not None and record.run_count >= record.config.max_runs:
                        record.active = False
                        record.status = "completed"
                        record.next_run_at = None
                        self._save_monitor(record)
                        return
                    record.status = "scheduled"
                    record.next_run_at = finished_at + record.config.interval_seconds
                    self._save_monitor(record)
            except Exception as exc:
                finished_at = time.time()
                with self._lock:
                    record = self._monitors[monitor_id]
                    record.run_count += 1
                    record.last_finished_at = finished_at
                    record.last_error = str(exc)
                    failed_run = MonitorRunSummary(
                        run_id=run_id,
                        started_at=started_at,
                        finished_at=finished_at,
                        duration_seconds=round(finished_at - started_at, 2),
                        status="failed",
                        message="Recurring scan failed.",
                        error=str(exc),
                    )
                    record.history[0] = failed_run
                    self._save_run(record.monitor_id, failed_run)
                    for alert in self._alerts_for_report(
                        record=record,
                        run_id=run_id,
                        previous_report=previous_report,
                        current_report=None,
                        run_error=str(exc),
                    ):
                        self._save_alert(alert)
                    if record.config.max_runs is not None and record.run_count >= record.config.max_runs:
                        record.active = False
                        record.status = "failed"
                        record.next_run_at = None
                        self._save_monitor(record)
                        return
                    record.status = "scheduled"
                    record.next_run_at = finished_at + record.config.interval_seconds
                    self._save_monitor(record)

            while True:
                with self._lock:
                    record = self._monitors[monitor_id]
                    next_run_at = record.next_run_at
                    should_stop = record.stop_event.is_set()
                if should_stop:
                    with self._lock:
                        record = self._monitors[monitor_id]
                        record.active = False
                        if record.status not in {"completed", "failed"}:
                            record.status = "stopped"
                        record.next_run_at = None
                        self._save_monitor(record)
                    return
                if next_run_at is None or time.time() >= next_run_at:
                    break
                time.sleep(min(0.25, max(0.0, next_run_at - time.time())))
