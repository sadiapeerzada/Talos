"""Isolated native PyRIT loop with scripted targets only; never a provider runner.

No Talos import/selection/rendering. Upstream attack implementation is unmodified.
"""
from __future__ import annotations
import asyncio
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import socket
import sys
import time
from unittest.mock import patch


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def deny_network(*args,**kwargs): raise PermissionError('PR08 worker has no network capability')


def audit(event,args):
    if event in ('socket.connect','socket.getaddrinfo','subprocess.Popen','os.system','os.exec','os.posix_spawn'):
        raise PermissionError('PR08 worker denies network/process/plugin execution')


async def run(request,root,identity):
    initialization_started=time.monotonic_ns()
    if request['mode']!='offline_native_stubs' or request.get('provider_execution')!='DISABLED':
        raise PermissionError('actual provider execution disabled')
    if importlib.metadata.version('pyrit')!=identity['version']: raise ValueError('external package version mismatch')
    distribution=importlib.metadata.distribution('pyrit')
    hashes={p:hashlib.sha256(Path(distribution.locate_file(p)).read_bytes()).hexdigest() for p in identity['source_files']}
    if hashes!=identity['source_files']: raise ValueError('upstream native source fingerprint mismatch')
    # Only filesystem-location policy is patched; no attack/generation/scoring code is replaced.
    with patch('appdirs.user_data_dir',side_effect=lambda appname,*a,**kw:str(root/appname)):
        from pyrit.common.random_context import configure_random_seed
        from pyrit.memory import CentralMemory,SQLiteMemory
        from pyrit.models import Message,TargetCapabilities,construct_response_from_request
        from pyrit.prompt_target import PromptTarget,TargetConfiguration
        from pyrit.executor.attack import AttackAdversarialConfig,AttackScoringConfig,RedTeamingAttack
        from pyrit.score import SubStringScorer
        configure_random_seed(seed=request['seed'])
        memory=SQLiteMemory(db_path=':memory:',silent=True)
        CentralMemory.set_memory_instance(memory)
        events=[];counts={'adversarial_stub':0,'objective_stub':0}
        max_turns=request['max_turns']
        if type(max_turns) is not int or not 1<=max_turns<=10: raise ValueError('invalid turn bound')
        class ScriptedTarget(PromptTarget):
            _DEFAULT_CONFIGURATION=TargetConfiguration(capabilities=TargetCapabilities(
                supports_multi_turn=True,supports_system_prompt=True,supports_json_schema=True,
                supports_json_output=True,supports_editable_history=True))
            def __init__(self,*,role):
                super().__init__()
                self.role=role
            def _build_identifier(self): return self._create_identifier(params={'offline_stub_role':self.role})
            async def _send_prompt_to_target_async(self,*,normalized_conversation:list[Message]):
                role=self.role
                if counts[role]>=max_turns: raise RuntimeError('native callback budget exhausted; no retries')
                index=counts[role];counts[role]+=1
                text=normalized_conversation[-1].get_piece().converted_value
                if role=='adversarial_stub':
                    value=request['adversarial_messages'][index]
                    response=json.dumps({'next_message':value,'rationale':'scripted offline test rationale',
                                         'last_response_summary':'scripted offline test summary'})
                else: response=request['objective_responses'][index]
                events.append({'sequence':len(events),'role':role,'request_text':text,'response_text':response,
                    'basis':'native_framework_scripted_target_callback_not_provider_inference'})
                return [construct_response_from_request(request=normalized_conversation[-1].get_piece(),response_text_pieces=[response])]
        attacker=ScriptedTarget(role='adversarial_stub');objective=ScriptedTarget(role='objective_stub')
        diagnostic_scores=[]
        scorer=SubStringScorer(substring=request['native_marker'])
        original_score=scorer.score_async
        async def traced_score(*args,**kwargs):
            scores=await original_score(*args,**kwargs)
            diagnostic_scores.extend(score.model_dump(mode='json') for score in scores)
            return scores
        scorer.score_async=traced_score
        attack=RedTeamingAttack(objective_target=objective,max_turns=max_turns,
            attack_adversarial_config=AttackAdversarialConfig(target=attacker),
            attack_scoring_config=AttackScoringConfig(objective_scorer=scorer,
                                                     use_score_as_feedback=False))
        initialization_ms=(time.monotonic_ns()-initialization_started+999999)//1000000
        execution_started=time.monotonic_ns()
        result=await attack.execute_async(objective=request['objective'])
        raw=result.model_dump(mode='json')
        scores=diagnostic_scores or ([raw['automated_score']] if raw.get('automated_score') else [])
        receipt={'schema_version':'talos.pyrit-native-receipt.v1','framework_version':'1.2.1','source_files':hashes,
            'config_sha256':request['config_sha256'],'objective_sha256':digest(request['objective']),
            'events':events,'native_outcome':str(result.outcome.value),'native_scores':scores,'raw_result':raw,
            'phase_elapsed_ms':{'framework_initialization':initialization_ms,'native_execution':(time.monotonic_ns()-execution_started+999999)//1000000},
            'environment':{'python':sys.version,'packages':dict(sorted((d.metadata['Name'],d.version) for d in importlib.metadata.distributions() if d.metadata['Name']))},
            'counts':counts,'provider_model_ids':None,'tokens':None,'cost':None,'actual_agent_delivery':'UNAVAILABLE'}
        await memory.dispose_engine_async()
        return receipt


def main():
    request=json.loads(Path(sys.argv[1]).read_text());identity=json.loads(Path(sys.argv[2]).read_text())
    root=Path.cwd()
    socket.socket.connect=deny_network;socket.socket.connect_ex=deny_network;socket.getaddrinfo=deny_network
    sys.addaudithook(audit)
    result=asyncio.run(run(request,root,identity))
    print(json.dumps(result,sort_keys=True,allow_nan=False))


if __name__=='__main__': main()
