"""Lossless offline evaluation of already captured repeat observations."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictInt, model_validator

from talos.judging.models import JUDGE_VERSION, Observation, Outcome, Record, Verdict
from talos.judging.oracle import AuthorizationPolicy, EvidenceReader, judge


class RepeatRecord(Record):
    observation: Observation
    verdict: Verdict

    @model_validator(mode="after")
    def bound_verdict(self) -> RepeatRecord:
        if self.verdict.action_digest != self.observation.action.digest():
            raise ValueError("verdict must refer to the stored observation")
        return self


class RepeatEvaluation(Record):
    judge_version: Literal["talos.action-oracle.v2.0"] = JUDGE_VERSION
    repeats: tuple[RepeatRecord, ...]
    n: int = Field(ge=1, strict=True)
    k: int = Field(ge=0, strict=True)
    counts: dict[str, StrictInt]

    @model_validator(mode="after")
    def coherent_repeats(self) -> RepeatEvaluation:
        if not self.repeats:
            raise ValueError("at least one repeat is required; empty evidence is not a clean evaluation")
        actions = [r.observation.action for r in self.repeats]
        if len({a.repeat_id for a in actions}) != len(actions):
            raise ValueError("duplicate repeat IDs")
        if len({(a.target_id, a.scenario_id, a.run_id) for a in actions}) != 1:
            raise ValueError("repeats must share one target, scenario and run")
        if any(r.verdict.judge_version != self.judge_version for r in self.repeats):
            raise ValueError("mixed judge versions")
        expected = {status.value: sum(r.verdict.status == status for r in self.repeats) for status in Outcome}
        if (self.n != len(self.repeats) or self.k != expected[Outcome.CONFIRMED.value]
                or self.counts != expected or any(type(v) is not int for v in self.counts.values())):
            raise ValueError("counts must exactly match stored per-repeat verdicts")
        return self


def evaluate_repeats(
    observations: tuple[Observation, ...],
    *,
    policy: AuthorizationPolicy | None = None,
    evidence_reader: EvidenceReader | None = None,
    trusted_source_ids: frozenset[str] = frozenset(),
) -> RepeatEvaluation:
    """Adjudicate stored observations only. Never execute/retry an attack.

    Counts describe action opportunities, not root causes, complete
    multi-action attempts, calibrated risk, or independent human labels.
    """
    records = []
    for observation in observations:
        # Capture independent JSON-compatible snapshots, not caller-owned mutable dicts.
        snapshot = Observation.model_validate(observation.model_dump())
        result = judge(snapshot, policy=policy, evidence_reader=evidence_reader,
                       trusted_source_ids=trusted_source_ids)
        records.append(RepeatRecord(observation=snapshot, verdict=result))
    counts = {status.value: sum(r.verdict.status == status for r in records) for status in Outcome}
    return RepeatEvaluation(repeats=tuple(records), n=len(records), k=counts[Outcome.CONFIRMED.value], counts=counts)
