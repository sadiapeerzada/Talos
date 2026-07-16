from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _wait_for(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            resp = httpx.get(url, timeout=1.0)
            if resp.status_code == 200:
                return
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
        time.sleep(0.3)
    raise RuntimeError(f"Server at {url} never became ready: {last_exc}")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def native_server_url():
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "talos.sample_agents.native_server", "--port", str(port)],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_for(f"http://127.0.0.1:{port}/agent/tools")
        yield f"http://127.0.0.1:{port}/agent"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture(scope="session")
def langchain_server_url():
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "talos.sample_agents.langchain_server", "--port", str(port)],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_for(f"http://127.0.0.1:{port}/agent/tools", timeout=30.0)
        yield f"http://127.0.0.1:{port}/agent"
    finally:
        proc.terminate()
        proc.wait(timeout=5)
