"""Explicit file-based human review workflow, without generated judgments."""
import argparse
import json
from pathlib import Path

from talos.validation import Adjudication,Clearance,ReferenceLabel,Study,Submission,validation_report
from talos.validation.metrics import Bootstrap


def main():
    parser=argparse.ArgumentParser(description='Offline blinded annotation and reference comparison; never certification')
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('schema')
    for name in ('export','submit','adjudication-view','adjudicate','seal','report'):
        command=sub.add_parser(name);command.add_argument('study',type=Path)
        if name=='export':
            command.add_argument('assignment');command.add_argument('destination',type=Path)
            command.add_argument('--clearance',type=Path,required=True)
        elif name in ('submit','adjudicate'): command.add_argument('file',type=Path)
        elif name=='adjudication-view': command.add_argument('sample_id')
        elif name=='report':
            command.add_argument('--expected-seal',required=True)
            command.add_argument('--calibration',action='store_true')
            command.add_argument('--resamples',type=int);command.add_argument('--seed',type=int)
            command.add_argument('--confidence',type=float)
    args=parser.parse_args()
    if args.command=='schema': result=ReferenceLabel.model_json_schema()
    else:
        study=Study(args.study)
        if args.command=='export': result={'packet_sha256':study.export(args.assignment,args.destination,Clearance.model_validate_json(args.clearance.read_text()))}
        elif args.command=='submit': result={'submission_sha256':study.import_submission(Submission.model_validate_json(args.file.read_text()))}
        elif args.command=='adjudicate': result={'adjudication_sha256':study.import_adjudication(Adjudication.model_validate_json(args.file.read_text()))}
        elif args.command=='adjudication-view': result=study.adjudication_packet(args.sample_id)
        elif args.command=='seal': result={'seal_sha256':study.seal()}
        else:
            bootstrap=None
            if args.resamples is not None:
                if args.seed is None or args.confidence is None: parser.error('resampling requires explicit seed and confidence')
                bootstrap=Bootstrap(seed=args.seed,resamples=args.resamples,confidence=args.confidence)
            result=validation_report(study,expected_seal=args.expected_seal,calibration=args.calibration,bootstrap=bootstrap)
    print(json.dumps(result,sort_keys=True,indent=2,default=str))


if __name__=='__main__': main()
