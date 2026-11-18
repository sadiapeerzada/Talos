"""Explicit PYTHONPATH-only CI/test guard, never production startup behavior."""
import ipaddress
import os
from pathlib import Path
import socket
import tempfile

_state=Path(os.environ.get('TALOS_RESEARCH_TEST_STATE_DIR',str(Path(tempfile.gettempdir())/'talos-research-offline-tests')))
_state.mkdir(parents=True,exist_ok=True)
import talos.storage
talos.storage.default_data_dir=lambda:_state
talos.storage.default_db_path=lambda:_state/'dashboard.db'
_connect=socket.socket.connect
_connect_ex=socket.socket.connect_ex
_getaddrinfo=socket.getaddrinfo


def _check(address):
    if isinstance(address,tuple):
        host=address[0].decode('ascii') if isinstance(address[0],bytes) else address[0]
        try: allowed=host=='localhost' or ipaddress.ip_address(host).is_loopback
        except ValueError: allowed=False
        if not allowed: raise RuntimeError('Offline research CI prohibits non-loopback connections')


def connect(self,address):
    _check(address);return _connect(self,address)


def connect_ex(self,address):
    _check(address);return _connect_ex(self,address)


socket.socket.connect=connect
socket.socket.connect_ex=connect_ex


def getaddrinfo(host,*args,**kwargs):
    if host is not None: _check((host,0))
    return _getaddrinfo(host,*args,**kwargs)

socket.getaddrinfo=getaddrinfo
