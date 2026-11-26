"""Closed process-scoped macOS profile; no installation or system-wide changes.

The bootstrap baseline is constrained by inverse data/map/write allowlists,
network denial and process-fork denial. Metadata names remain visible. macOS
private/deprecated interfaces still require actual host validation and approval.
"""
import json
from pathlib import Path


def public_read_roots(python_path,snapshot):
    python=Path(python_path)
    if not python.is_absolute():raise PermissionError('explicit isolated interpreter path required')
    runtime=python.parent.parent.resolve()
    if not (runtime/'pyvenv.cfg').is_file():raise PermissionError('isolated virtual environment required')
    base=python.resolve().parent.parent
    package=Path(__file__).resolve().parents[1]
    return sorted(set(map(str,(runtime,base,package,Path(snapshot).resolve()))))+['/System','/usr/lib','/usr/share','/Library/Apple','/private/var/db/dyld']


def build_profile(python_path,snapshot,read_files):
    roots=public_read_roots(python_path,snapshot)
    expressions=['(subpath '+json.dumps(p)+')' for p in roots]
    expressions+=['(literal '+json.dumps(str(Path(p).resolve()))+')' for p in sorted(set(map(str,read_files)))]
    expressions+=['(literal "/")','(literal "/dev/urandom")','(literal "/dev/random")','(literal "/dev/null")',
                  '(subpath (param "SCRATCH"))']
    outside='(require-all '+' '.join('(require-not '+x+')' for x in expressions)+')'
    return ('(version 1)\n(allow default)\n(deny network*)\n(deny process-fork)\n'
            '(deny file-read-data '+outside+')\n(deny file-map-executable '+outside+')\n'
            '(deny file-write* (require-all (require-not (subpath (param "SCRATCH"))) (require-not (literal "/dev/null"))))\n')
