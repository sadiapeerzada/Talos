"""Offline design/replay CLI. No model, target or attack execution command."""
import argparse
import json
from pathlib import Path
from talos.ablation import Plan,dry_run,replay


def main():
    parser=argparse.ArgumentParser(description='Four-arm engineering plan/replay; empirical gates remain blocked')
    sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('plan');p.add_argument('manifest',type=Path)
    p=sub.add_parser('replay');p.add_argument('archive',type=Path);p.add_argument('--expected-seal',required=True)
    args=parser.parse_args()
    result=dry_run(Plan.model_validate_json(args.manifest.read_text())) if args.command=='plan' else replay(args.archive,expected_seal=args.expected_seal)['summary']
    print(json.dumps(result,sort_keys=True,indent=2))


if __name__=='__main__': main()
