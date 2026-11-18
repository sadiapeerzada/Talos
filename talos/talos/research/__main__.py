"""Offline planning/replay only; no scan or inference subcommand."""
import argparse
import json
from pathlib import Path
from talos.research import RunPlan, dry_run, replay


def main():
    parser=argparse.ArgumentParser(description='Opt-in passive research plan/replay')
    sub=parser.add_subparsers(dest='command',required=True)
    plan=sub.add_parser('plan');plan.add_argument('manifest',type=Path)
    review=sub.add_parser('replay');review.add_argument('archive',type=Path);review.add_argument('--expected-seal')
    args=parser.parse_args()
    if args.command=='plan':
        output=dry_run(RunPlan.model_validate_json(args.manifest.read_text()))
    else: output=replay(args.archive,expected_seal=args.expected_seal)['accounting']
    print(json.dumps(output,sort_keys=True,indent=2))


if __name__=='__main__': main()
