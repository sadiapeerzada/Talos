"""Separate research contracts; absent measurements remain absent."""
from __future__ import annotations

import importlib.metadata
from pathlib import Path
import platform
import subprocess
from typing import Literal

from pydantic import Field, StrictInt, field_validator, model_validator
from talos.corpus.models import Model, content_hash
from talos.judging import EvidenceBundle, Observation, Outcome, PolicyAssessment, Verdict
from talos.profiles import TargetProfile
from talos.profiles.models import finite_json

RUN_VERSION = "talos.research-run.v1"
DIMENSIONS = frozenset(('attempts','target_calls','attacker_calls','target_model_calls','retries',
                        'input_tokens','output_tokens','cost_microunits','elapsed_ms'))


class Limits(Model):
    amounts: dict[str, StrictInt]

    @model_validator(mode='after')
    def dimensions(self):
        if set(self.amounts) != DIMENSIONS or any(n < 0 for n in self.amounts.values()):
            raise ValueError('all exact nonnegative budget dimensions required')
        return self


class Provenance(Model):
    source_commit: str = Field(pattern=r'^[0-9a-f]{40}$')
    source_dirty: bool = Field(strict=True)
    source_tree_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    python: str
    platform: str
    dependency_versions: dict[str, str]
    dependency_lock_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    attacker_model_id: str | None = None
    target_model_id: str | None = None


def capture_provenance(repository: Path, dependency_lock: Path) -> Provenance:
    import hashlib
    commit = subprocess.check_output(['git','rev-parse','HEAD'], cwd=repository, text=True).strip()
    dirty = bool(subprocess.check_output(['git','status','--porcelain'],cwd=repository,text=True).strip())
    paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard'],cwd=repository,text=True).splitlines()
    tree={name:hashlib.sha256((repository/name).read_bytes()).hexdigest() if (repository/name).is_file() else 'missing' for name in sorted(set(paths))}
    versions = {d.metadata['Name']: d.version for d in importlib.metadata.distributions() if d.metadata['Name']}
    return Provenance(source_commit=commit,source_dirty=dirty,source_tree_sha256=content_hash(tree),python=platform.python_version(),platform=platform.platform(),
                      dependency_versions=dict(sorted(versions.items())),
                      dependency_lock_sha256=hashlib.sha256(dependency_lock.read_bytes()).hexdigest())


class LearningSnapshot(Model):
    mode: Literal['disabled','supplied_frozen'] = 'disabled'
    data: dict = Field(default_factory=dict)

    @field_validator('data')
    @classmethod
    def finite(cls,value): return finite_json(value)

    @model_validator(mode='after')
    def disabled_empty(self):
        if self.mode == 'disabled' and self.data:
            raise ValueError('disabled learning must be empty')
        return self


class TrustDeclaration(Model):
    purpose: Literal['synthetic_regression_only'] = 'synthetic_regression_only'
    reference: str = Field(min_length=1)
    policy_id: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    trusted_source_ids: tuple[str, ...] = Field(min_length=1)
    # This is supplied by the operator, never auto-created by the runner.
    custody_status: Literal['operator_declaration_not_authenticated_approval'] = 'operator_declaration_not_authenticated_approval'


class Cell(Model):
    cell_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    repeat_id: str = Field(min_length=1)
    case_identity: str = Field(min_length=1)
    binding_id: str = Field(min_length=1)
    mode: Literal['corpus_delivery','direct_fixture_control'] = 'corpus_delivery'
    reset_fault: Literal['none','failed_reset','incomplete_reset'] = 'none'
    tool_fault: Literal['none','failed_tool','rollback_before_commit','partial_commit','unrelated_state_change',
                        'timeout','delayed_audit','missing_audit','contradictory_audit'] = 'none'


class RunPlan(Model):
    schema_version: Literal['talos.research-run.v1'] = RUN_VERSION
    run_id: str = Field(pattern=r'^[A-Za-z0-9_-]+$')
    purpose: Literal['offline_engineering_only'] = 'offline_engineering_only'
    provenance: Provenance
    corpus_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    profile: TargetProfile
    target_version: str = Field(min_length=1)
    oracle_version: Literal['talos.action-oracle.v2.0'] = 'talos.action-oracle.v2.0'
    policy_id: str
    policy_version: str
    seed: StrictInt
    order: Literal['declared','seeded_shuffle'] = 'declared'
    timeout_ms: int = Field(gt=0,strict=True)
    limits: Limits
    learning: LearningSnapshot = Field(default_factory=LearningSnapshot)
    trust: TrustDeclaration | None = None
    cells: tuple[Cell, ...] = Field(min_length=1)

    @model_validator(mode='after')
    def unique(self):
        if len({c.cell_id for c in self.cells}) != len(self.cells):
            raise ValueError('duplicate cell identity')
        if len({(c.scenario_id,c.repeat_id) for c in self.cells}) != len(self.cells):
            raise ValueError('reset context repeated within run')
        if self.trust and (self.trust.policy_id,self.trust.policy_version) != (self.policy_id,self.policy_version):
            raise ValueError('trust declaration policy mismatch')
        if self.provenance.attacker_model_id is not None or self.provenance.target_model_id is not None:
            raise ValueError('no model adapters are implemented in this engineering runner')
        return self

    def digest(self): return content_hash(self)


class Packet(Model):
    observation: Observation
    request_latency_ms: int | None = Field(default=None,ge=0,strict=True)
    input_tokens: int | None = Field(default=None,ge=0,strict=True)
    output_tokens: int | None = Field(default=None,ge=0,strict=True)
    cost_microunits: int | None = Field(default=None,ge=0,strict=True)
    policy: PolicyAssessment | None
    policy_enabled: bool = Field(strict=True)
    evidence: EvidenceBundle
    raw_store_records: dict
    reset_receipt: dict
    reader_issues: tuple[str, ...]
    trusted_source_ids: tuple[str, ...]
    verdict: Verdict

    @model_validator(mode='after')
    def action_identity(self):
        digest=self.observation.action.digest()
        if self.verdict.action_digest != digest or (self.policy and self.policy.action_digest != digest):
            raise ValueError('packet action mismatch')
        if any(r.action_digest != digest for r in self.evidence.records):
            raise ValueError('packet evidence action mismatch')
        return self


class CellResult(Model):
    cell_id: str
    outcome: Outcome
    state: Literal['completed','unknown','inapplicable','delivery_unavailable','budget_exhausted',
                   'reset_failed','timed_out','error','interrupted','missing']
    reason: str = Field(min_length=1)
    packet: Packet | None = None
    elapsed_ms: int | None = Field(default=None,ge=0,strict=True)
    input_tokens: int | None = Field(default=None,ge=0,strict=True)
    output_tokens: int | None = Field(default=None,ge=0,strict=True)
    cost_microunits: int | None = Field(default=None,ge=0,strict=True)
    abstention_reason: str | None = None

    @model_validator(mode='after')
    def outcome_contract(self):
        if self.packet and self.outcome != self.packet.verdict.status:
            raise ValueError('result must preserve full oracle verdict')
        if not self.packet and self.outcome != Outcome.UNKNOWN:
            raise ValueError('no oracle packet means UNKNOWN')
        if self.outcome == Outcome.UNKNOWN and not self.abstention_reason:
            raise ValueError('UNKNOWN requires abstention reason')
        return self
