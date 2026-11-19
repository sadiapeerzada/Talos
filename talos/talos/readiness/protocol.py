"""Freeze preparation identity, with no operation that freezes a cohort/study."""
from pathlib import Path
from typing import Literal
from pydantic import Field
from talos.corpus.models import Model


class ProtocolDraft(Model):
    schema_version:Literal['talos.study-freeze-preparation.v1']='talos.study-freeze-preparation.v1'
    protocol_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    governing_final_plan_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    governing_original_plan_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    base_commit:Literal['700d6acf9c06e98c82cd623abf17c65c301ef24d']='700d6acf9c06e98c82cd623abf17c65c301ef24d'
    frozen:Literal[False]=False
    approval:Literal[None]=None
    test_cohort:Literal[None]=None
    primary_budget:Literal[None]=None
    sample_size:Literal[None]=None
    model_approvals:Literal[None]=None
    target_approvals:Literal[None]=None
    primary:Literal['A2-A1']='A2-A1'
    proposed_secondary:Literal['A4-A1_PENDING_APPROVAL']='A4-A1_PENDING_APPROVAL'
    empirical_execution:Literal['NO-GO']='NO-GO'
    pr09_experimental_complete:Literal[False]=False
