"""Readiness, schemas and replay only. No live/pilot execution command."""
import argparse,json
from pathlib import Path
from talos.readiness import EngineeringPlan,CapabilityRequest,report,replay


def main():
    p=argparse.ArgumentParser();s=p.add_subparsers(dest='command',required=True)
    s.add_parser('report');s.add_parser('schema')
    r=s.add_parser('replay');r.add_argument('archive',type=Path);r.add_argument('--seal',required=True)
    a=p.parse_args()
    if a.command=='report':value=report()
    elif a.command=='schema':value={'engineering':EngineeringPlan.model_json_schema(),'prospective_capability':CapabilityRequest.model_json_schema()}
    else:value=replay(a.archive,expected_seal=a.seal)
    print(json.dumps(value,sort_keys=True,indent=2))


if __name__=='__main__':main()
