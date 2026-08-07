"""Recurring scan monitoring for the Talos dashboard."""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

from pydantic import BaseModel, Field

from talos.reporting.report import ScanReport
from talos.scan_service import DEFAULT_GENERATION_STRATEGY, DEFAULT_POISONED_ORDER_IDS, DEFAULT_SEED_ORDER_IDS, run_scan_pipeline


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
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._monitors: dict[str, _MonitorRecord] = {}

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
            return record.snapshot()

    def _run_monitor(self, monitor_id: str) -> None:
        while True:
            with self._lock:
                record = self._monitors[monitor_id]
                if record.stop_event.is_set():
                    record.active = False
                    if record.status not in {"completed", "failed"}:
                        record.status = "stopped"
                    record.next_run_at = None
                    return
                if record.config.max_runs is not None and record.run_count >= record.config.max_runs:
                    record.active = False
                    record.status = "completed"
                    record.next_run_at = None
                    return

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

            finished_at = time.time()
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
                    record.history[0] = MonitorRunSummary(
                        run_id=run_id,
                        started_at=started_at,
                        finished_at=finished_at,
                        duration_seconds=round(finished_at - started_at, 2),
                        status="succeeded",
                        message="Recurring scan completed.",
                        report=report,
                    )
                    if record.config.max_runs is not None and record.run_count >= record.config.max_runs:
                        record.active = False
                        record.status = "completed"
                        record.next_run_at = None
                        return
                    record.status = "scheduled"
                    record.next_run_at = finished_at + record.config.interval_seconds
            except Exception as exc:
                finished_at = time.time()
                with self._lock:
                    record = self._monitors[monitor_id]
                    record.run_count += 1
                    record.last_finished_at = finished_at
                    record.last_error = str(exc)
                    record.history[0] = MonitorRunSummary(
                        run_id=run_id,
                        started_at=started_at,
                        finished_at=finished_at,
                        duration_seconds=round(finished_at - started_at, 2),
                        status="failed",
                        message="Recurring scan failed.",
                        error=str(exc),
                    )
                    if record.config.max_runs is not None and record.run_count >= record.config.max_runs:
                        record.active = False
                        record.status = "failed"
                        record.next_run_at = None
                        return
                    record.status = "scheduled"
                    record.next_run_at = finished_at + record.config.interval_seconds

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
                    return
                if next_run_at is None or time.time() >= next_run_at:
                    break
                time.sleep(min(0.25, max(0.0, next_run_at - time.time())))
