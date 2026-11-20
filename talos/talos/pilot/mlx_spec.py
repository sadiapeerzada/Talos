"""Candidate-specific settings. Selected candidate is never execution approval."""
import hashlib,json
from pathlib import Path
from typing import Literal
from pydantic import Field,model_validator
from talos.corpus.models import Model
from talos.readiness.contracts import ModelConfiguration

CHECKPOINT='mlx-community/Qwen3-4B-Instruct-2507-4bit'
REVISION='50d427756c6b1b2fe0c0a10f67fbda1fc8e82c1b'
VERSIONS={'mlx-lm':'0.26.2','mlx':'0.26.2','transformers':'4.53.3'}


def candidate():
    value=json.loads(Path(__file__).with_name('qwen_mlx_candidate.json').read_text())
    if value['checkpoint']!=CHECKPOINT or value['checkpoint_revision']!=REVISION or value['runtime_versions']!=VERSIONS:
        raise ValueError('candidate pin changed')
    return value


def candidate_hash():return hashlib.sha256(Path(__file__).with_name('qwen_mlx_candidate.json').read_bytes()).hexdigest()


class MLXModel(Model):
    runtime:Literal['mlx-lm']='mlx-lm'
    role:Literal['defender_target_agent_not_attacker']='defender_target_agent_not_attacker'
    deterministic_generation_assumed:Literal[False]=False
    configuration:ModelConfiguration
    candidate_manifest_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    local_snapshot:str=Field(min_length=1)
    context_tokens:Literal[4096]=4096
    max_input_tokens:Literal[3584]=3584
    request_timeout_ms:int=Field(ge=100,le=120000,strict=True)
    currency:Literal['INR']='INR'
    cost_basis:Literal['local_paid_API_spending_only_hardware_unmeasured']='local_paid_API_spending_only_hardware_unmeasured'
    price_schedule_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    batch_id:str=Field(min_length=1)

    @model_validator(mode='after')
    def exact_candidate(self):
        cfg=self.configuration
        if cfg.model_id!=CHECKPOINT or cfg.revision!=REVISION or cfg.max_output_tokens!=512 or cfg.temperature!=0 or cfg.seed is not None:
            raise ValueError('exact selected candidate/revision/proposed output/temperature; no determinism claim')
        path=Path(self.local_snapshot)
        if not path.is_absolute() or '..' in path.parts:raise ValueError('explicit local immutable snapshot path only; no hub resolver')
        if self.candidate_manifest_sha256!=candidate_hash():raise ValueError('candidate manifest identity differs')
        return self

    def debit(self,input_tokens,output_tokens):
        # Only paid API spend: no API/network exists. This is not hardware cost.
        return 0


class ProposedMLXPilot(Model):
    status:Literal['PROPOSED_NOT_APPROVED']='PROPOSED_NOT_APPROVED'
    episodes:Literal[8]=8
    model_requests_per_episode:Literal[4]=4
    total_requests:Literal[32]=32
    total_wall_ms:Literal[1800000]=1800000
    paid_api_spending_inr:Literal[0]=0
    actual_hardware_cost:Literal[None]=None
    approval:Literal[None]=None
