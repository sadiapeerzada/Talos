"""Explicit isolated native test worker. No framework import in Talos's process."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from talos.corpus.models import content_hash
from talos.comparator.contracts import Config,NativeReceipt,PYRIT_COMMIT,PYRIT_VERSION


def bundle_root(): return Path(__file__).resolve().parents[3]/'comparators'/'pyrit'


def bundle_identity():
    root=bundle_root();value=json.loads((root/'upstream_identity.json').read_text())
    if (value['version'],value['commit'],value['native_class'])!=(PYRIT_VERSION,PYRIT_COMMIT,'pyrit.executor.attack.multi_turn.red_teaming.RedTeamingAttack'):
        raise ValueError('unapproved framework identity')
    return value


def lock_hash(): return hashlib.sha256((bundle_root()/'requirements.lock').read_bytes()).hexdigest()


def worker_environment(seed:int):
    # No credentials, .env paths, PYTHONPATH, global PyRIT config, proxy or telemetry fallback.
    return {'LANG':'C.UTF-8','PYTHONHASHSEED':str(seed),'HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1',
            'OTEL_SDK_DISABLED':'true','OTEL_TRACES_EXPORTER':'none','DO_NOT_TRACK':'1'}


def native_control(config:Config, *, objective:str,adversarial_messages:tuple[str,...],objective_responses:tuple[str,...],
                   marker:str,python:Path,timeout_ms:int):
    config=Config.model_validate(config.model_dump())
    if not objective or not marker: raise ValueError('explicit objective/diagnostic marker required')
    if len(adversarial_messages)!=config.max_turns or len(objective_responses)!=config.max_turns:
        raise ValueError('exact scripted native turn bounds required')
    identity=bundle_identity();root=bundle_root()
    python=Path(python).absolute()
    if not python.is_file(): raise ValueError('explicit isolated Python interpreter unavailable')
    request={'mode':'offline_native_stubs','provider_execution':'DISABLED','max_turns':config.max_turns,'seed':config.seed,
        'objective':objective,'adversarial_messages':list(adversarial_messages),'objective_responses':list(objective_responses),
        'native_marker':marker,'config_sha256':content_hash(config)}
    started=time.monotonic_ns()
    with tempfile.TemporaryDirectory(prefix='talos-pyrit-offline-') as directory:
        work=Path(directory);request_file=work/'request.json';request_file.write_text(json.dumps(request))
        result=subprocess.run([str(python),'-I',str(root/'offline_worker.py'),str(request_file),str(root/'upstream_identity.json')],
            cwd=work,env=worker_environment(config.seed),capture_output=True,text=True,timeout=timeout_ms/1000)
        elapsed=(time.monotonic_ns()-started+999999)//1000000
        if result.returncode:
            # Do not echo arbitrary provider/credential-bearing diagnostics.
            raise RuntimeError('isolated native comparator failed; no retry or success inference')
        receipt=NativeReceipt.model_validate_json(result.stdout)
        if receipt.source_files!=identity['source_files'] or receipt.config_sha256!=content_hash(config) or receipt.objective_sha256!=content_hash(objective):
            raise ValueError('native receipt differs from exact pinned objective/configuration/source')
        if any(v>config.max_turns for v in receipt.counts.values()): raise ValueError('native callback ceiling exceeded')
        return receipt,int(elapsed)


def deterministic_projection(receipt:NativeReceipt):
    """Replayable semantic view, not a claim that UUIDs/timing/provider sampling repeat."""
    receipt=NativeReceipt.model_validate(receipt.model_dump())
    scores=[{k:s.get(k) for k in ('score_value','score_type','score_rationale','score_category')} for s in receipt.native_scores]
    return {'schema_version':'talos.pyrit-semantic-projection.v1','events':[e.model_dump(mode='json') for e in receipt.events],
            'native_outcome':receipt.native_outcome,'diagnostic_scores':scores,'counts':receipt.counts,
            'normalization':'native UUIDs/timestamps/raw result remain separately preserved; no stochastic equivalence implied'}
