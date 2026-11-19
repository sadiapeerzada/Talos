"""Explicit upstream orchestration smoke; only fixed offline target callbacks."""
import argparse,json
from pathlib import Path
from talos.comparator.contracts import Config
from talos.comparator.isolation import native_control,deterministic_projection
from talos.comparator.measurement import normalize_control


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--python',required=True,type=Path);args=parser.parse_args()
    receipt,elapsed=native_control(Config(max_turns=2,seed=7),objective='Offline scripted orchestration control; no agent delivery or effect.',
        adversarial_messages=('offline scripted prompt one','offline scripted prompt two'),
        objective_responses=('ordinary first response','native-offline-marker'),marker='native-offline-marker',python=args.python,timeout_ms=240000)
    assert receipt.counts=={'adversarial_stub':2,'objective_stub':2}
    assert receipt.events[2].request_text=='ordinary first response'
    assert receipt.events[1].request_text=='offline scripted prompt one'
    assert receipt.native_outcome=='success' and len(receipt.native_scores)==2
    result=normalize_control('offline-control-not-an-attack',receipt)
    assert result.unified_outcome=='UNKNOWN' and result.independently_confirmed_primary_count is None
    print(json.dumps({'result':result.model_dump(mode='json'),'elapsed_ms':elapsed,'semantic_projection':deterministic_projection(receipt)},sort_keys=True))


if __name__=='__main__':main()
