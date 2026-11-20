"""Verify operator-provisioned local assets only. No Hub resolver/downloader."""
import hashlib,importlib.metadata,json,platform,re
from pathlib import Path
from talos.pilot.mlx_spec import candidate,MLXModel


def verify_snapshot(model:MLXModel):
    root=Path(model.local_snapshot)
    if root.is_symlink() or not root.is_dir():raise PermissionError('operator-provisioned immutable snapshot missing')
    pin=candidate();allowed=set(pin['checkpoint_files']);required=allowed-{'.gitattributes','README.md'}
    if any(p.name not in allowed or p.is_symlink() or not p.is_file() for p in root.iterdir()):
        raise PermissionError('unexpected/symlinked snapshot asset')
    verified={}
    for name in sorted(required):
        entry=pin['checkpoint_files'][name];path=root/name
        if not path.is_file() or path.is_symlink() or path.stat().st_size!=entry['size_bytes']:
            raise PermissionError('required pinned snapshot asset missing/size mismatch')
        sha=hashlib.sha256();git=hashlib.sha1(b'blob '+str(entry['size_bytes']).encode()+b'\0')
        with path.open('rb') as stream:
            for chunk in iter(lambda:stream.read(1048576),b''):sha.update(chunk);git.update(chunk)
        if 'sha256' in entry:
            if sha.hexdigest()!=entry['sha256']:raise PermissionError('snapshot SHA-256 differs from candidate')
        elif git.hexdigest()!=entry['git_blob_sha1']:raise PermissionError('snapshot Git blob differs from candidate')
        verified[name]={'sha256':sha.hexdigest(),'size_bytes':entry['size_bytes']}
    return verified


def runtime_lock():return Path(__file__).resolve().parents[2]/'requirements-mlx-candidate.lock'


def verify_environment():
    if platform.system()!='Darwin' or platform.machine()!='arm64':raise PermissionError('MLX candidate requires Apple Silicon macOS')
    versions={}
    # The lock was resolved for CPython 3.13 / macOS arm64; no unsupported lock claims.
    import sys
    if sys.version_info[:2]!=(3,13):raise PermissionError('reviewed candidate dependency lock targets CPython 3.13')
    for line in runtime_lock().read_text().splitlines():
        match=re.match(r'^([A-Za-z0-9_.-]+)==([^\s;]+)',line)
        if match:
            name,expected=match.groups();actual=importlib.metadata.version(name)
            if actual!=expected:raise PermissionError('isolated MLX dependency differs from lock')
            versions[name]=actual
    if any(versions.get(k)!=v for k,v in candidate()['runtime_versions'].items()):raise PermissionError('core runtime pin absent')
    return versions
