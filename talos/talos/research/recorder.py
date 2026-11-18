"""Atomic append-only content-addressed journal, not authenticated custody."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from talos.corpus.models import content_hash


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()


class IntegrityError(ValueError): pass


def _read(path):
    try:
        data=path.read_bytes(); value=json.loads(data)
        if canonical(value)!=data: raise ValueError('noncanonical JSON')
        return value
    except (OSError,ValueError) as e:
        raise IntegrityError(f'invalid/missing archive file: {path.name}') from e


def _create(path,value):
    """Publish complete bytes by exclusive hard link, fsync file and directory."""
    with NamedTemporaryFile(dir=path.parent,prefix='.pending-',delete=False) as temp:
        tmp=Path(temp.name)
        try:
            temp.write(canonical(value));temp.flush();os.fsync(temp.fileno())
            os.link(tmp,path)  # fail rather than replace existing history
            fd=os.open(path.parent,os.O_RDONLY)
            try: os.fsync(fd)
            finally: os.close(fd)
        finally: tmp.unlink(missing_ok=True)


class Recorder:
    def __init__(self,path:Path, *, create=False):
        self.path=Path(path)
        if create:
            self.path.mkdir(parents=False,exist_ok=False)
            (self.path/'objects').mkdir();(self.path/'events').mkdir()
        if self.path.is_symlink(): raise IntegrityError('symlink archive root prohibited')
        self.lock=open(self.path/'.writer-lock','a+b')
        try: fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            self.lock.close();raise IntegrityError('archive already has a writer') from None
        try:
            self.events=verify(self.path,allow_incomplete=True)
            if (self.path/'seal.json').exists(): raise IntegrityError('sealed archive is read-only')
        except BaseException:
            self.close();raise

    def __enter__(self): return self
    def __exit__(self,*exc): self.close()
    def close(self):
        if not self.lock.closed:
            fcntl.flock(self.lock,fcntl.LOCK_UN);self.lock.close()

    def append(self,kind,payload):
        if self.lock.closed or (self.path/'seal.json').exists(): raise IntegrityError('closed/sealed recorder')
        # Recheck current chain before writing; concurrent writes are excluded by lock.
        if verify(self.path,allow_incomplete=True)!=self.events: raise IntegrityError('journal changed during custody')
        payload=json.loads(canonical(payload))
        digest=content_hash(payload)
        object_path=self.path/'objects'/f'{digest}.json'
        if object_path.exists():
            if _read(object_path)!=payload: raise IntegrityError('content address collision')
        else: _create(object_path,payload)
        event={'schema_version':'talos.research-event.v1','sequence':len(self.events),'kind':kind,
               'previous':content_hash(self.events[-1]) if self.events else None,'payload_sha256':digest}
        _create(self.path/'events'/f'{len(self.events):08d}.json',event)
        self.events.append(event)
        return content_hash(event)

    def seal(self):
        if self.lock.closed: raise IntegrityError('closed recorder cannot seal')
        if (self.path/'seal.json').exists(): raise IntegrityError('already sealed')
        events=verify(self.path,allow_incomplete=True)
        value={'schema_version':'talos.research-seal.v1','event_count':len(events),
               'head_sha256':content_hash(events[-1]) if events else None}
        _create(self.path/'seal.json',value)
        return content_hash(value)


def verify(path:Path, *, expected_seal:str|None=None, allow_incomplete=False):
    path=Path(path)
    if path.is_symlink(): raise IntegrityError('symlink archive prohibited')
    if not (path/'objects').is_dir() or not (path/'events').is_dir():
        raise IntegrityError('archive directories missing')
    for p in path.rglob('*'):
        if p.is_symlink(): raise IntegrityError('symlink archive entry prohibited')
    entries=sorted((path/'events').glob('*.json'))
    events=[]
    for index,entry in enumerate(entries):
        if entry.name!=f'{index:08d}.json': raise IntegrityError('event gap/order mismatch')
        event=_read(entry)
        if set(event)!={'schema_version','sequence','kind','previous','payload_sha256'} or event['schema_version']!='talos.research-event.v1':
            raise IntegrityError('event schema mismatch')
        if event['sequence']!=index or event['previous']!=(content_hash(events[-1]) if events else None):
            raise IntegrityError('event chain mismatch')
        digest=event['payload_sha256']
        if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
            raise IntegrityError('invalid content address')
        if content_hash(_read(path/'objects'/f'{digest}.json'))!=digest: raise IntegrityError('payload integrity failure')
        events.append(event)
    sealpath=path/'seal.json'
    if sealpath.exists():
        seal=_read(sealpath)
        expected={'schema_version':'talos.research-seal.v1','event_count':len(events),
                  'head_sha256':content_hash(events[-1]) if events else None}
        if seal!=expected or (expected_seal and content_hash(seal)!=expected_seal): raise IntegrityError('seal/head mismatch')
    elif expected_seal or not allow_incomplete:
        raise IntegrityError('archive incomplete/unsealed')
    return events


def read_payloads(path:Path, **kwargs):
    return [(e['kind'],_read(Path(path)/'objects'/f"{e['payload_sha256']}.json")) for e in verify(path,**kwargs)]
