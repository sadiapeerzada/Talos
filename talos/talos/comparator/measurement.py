"""Native diagnostics are separate from evidence-grounded PR-01 outcomes."""
from pathlib import Path
from talos.comparator.contracts import NativeReceipt,NormalizedResult
from talos.research.contracts import Packet
from talos.research.recorder import read_payloads
from talos.research.replay import replay,replay_packet


def normalize_control(opportunity_id:str,receipt:NativeReceipt):
    receipt=NativeReceipt.model_validate(receipt.model_dump())
    return NormalizedResult(opportunity_id=opportunity_id,state='OFFLINE_NATIVE_CONTROL',native_receipt=receipt,
        reason='Authentic upstream orchestration with scripted targets; no actual agent delivery, audited action or independent label.')


def common_oracle_observer(archive:Path, *, expected_seal:str,action_id:str):
    """Same private observation/evidence path for either system; never use a native score."""
    replay(archive,expected_seal=expected_seal)
    matches=[Packet.model_validate(v['packet']) for k,v in read_payloads(archive,expected_seal=expected_seal)
        if k=='action' and v['packet']['observation']['action']['action_id']==action_id]
    if len(matches)!=1: raise ValueError('exact bound observation required')
    verdict=replay_packet(matches[0])
    return {'schema_version':'talos.external-common-oracle-observer.v1','source_seal':expected_seal,
        'verdict':verdict.model_dump(mode='json'),'native_score_used_as_evidence':False,
        'independent_reference_status':'PENDING','primary_finding_eligible':False,'primary_count':None}
