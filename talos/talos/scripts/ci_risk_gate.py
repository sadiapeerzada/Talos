"""
CI regression gate for Talos's own risk score.

Runs a Talos scan against the native sample agent, compares the resulting
risk_score against a committed baseline (.ci/baseline_risk_score.json at
the project root), and fails (non-zero exit) if the score got WORSE
(higher -- more vulnerable) than the baseline. A security scanner's own CI
should block increases in its demo target's exposure, not just run tests.

The comparison logic (`evaluate_regression`) is deliberately a small, pure
function with no I/O, so it's directly unit-testable without needing to
spin up a server or run a real scan -- see tests/test_ci_risk_gate.py.

Usage:
    python -m talos.scripts.ci_risk_gate                # run + check
    python -m talos.scripts.ci_risk_gate --update        # run + overwrite baseline
    python -m talos.scripts.ci_risk_gate --target URL --adapter native
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

BASELINE_PATH = Path(__file__).resolve().parents[2] / ".ci" / "baseline_risk_score.json"
DEFAULT_PORT = 8799


@dataclass
class RegressionResult:
    passed: bool
    baseline_score: int
    new_score: int
    message: str


def evaluate_regression(baseline_score: int, new_score: int) -> RegressionResult:
    """Pure comparison logic, no I/O. A regression is the new score being
    STRICTLY HIGHER (more vulnerable) than the baseline; equal or lower
    always passes."""
    if new_score > baseline_score:
        return RegressionResult(
            passed=False,
            baseline_score=baseline_score,
            new_score=new_score,
            message=(
                f"REGRESSION: risk score increased from {baseline_score} to {new_score} "
                f"(+{new_score - baseline_score}). This PR made the scanned target MORE "
                f"vulnerable than the committed baseline allows."
            ),
        )
    delta = baseline_score - new_score
    if delta > 0:
        message = f"OK: risk score improved from {baseline_score} to {new_score} (-{delta})."
    else:
        message = f"OK: risk score unchanged at {new_score}."
    return RegressionResult(passed=True, baseline_score=baseline_score, new_score=new_score, message=message)


def load_baseline(path: Path = BASELINE_PATH) -> dict:
    with open(path) as f:
        return json.load(f)


def save_baseline(data: dict, path: Path = BASELINE_PATH) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _wait_for_server(port: int, timeout: float = 15.0) -> None:
    import httpx

    deadline = time.time() + timeout
    last_error: Optional[Exception] = None
    while time.time() < deadline:
        try:
            httpx.get(f"http://127.0.0.1:{port}/agent/tools", timeout=1.0)
            return
        except Exception as exc:  # noqa: BLE001 - retry loop, any failure just means "not up yet"
            last_error = exc
            time.sleep(0.3)
    raise RuntimeError(f"native sample agent on port {port} did not come up in time: {last_error}")


def run_scan_and_get_risk_score(target: str, adapter: str) -> int:
    from talos.scan_service import run_scan_pipeline

    report, _events = run_scan_pipeline(target=target, adapter_name=adapter, repro_runs=1)
    return report.stats.risk_score


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=None, help="Target agent URL. Defaults to starting the native sample agent locally.")
    parser.add_argument("--adapter", default="native")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--update", action="store_true", help="Overwrite the committed baseline with the freshly-measured score instead of gating on it.")
    parser.add_argument("--baseline-path", default=str(BASELINE_PATH))
    args = parser.parse_args(argv)

    baseline_path = Path(args.baseline_path)
    baseline = load_baseline(baseline_path)

    proc = None
    target = args.target
    try:
        if target is None:
            proc = subprocess.Popen(
                [sys.executable, "-m", "talos.sample_agents.native_server", "--port", str(args.port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            _wait_for_server(args.port)
            target = f"http://127.0.0.1:{args.port}/agent"

        new_score = run_scan_and_get_risk_score(target, args.adapter)
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    if args.update:
        baseline["risk_score"] = new_score
        baseline["target"] = target
        baseline["adapter"] = args.adapter
        save_baseline(baseline, baseline_path)
        print(f"Baseline updated: risk_score = {new_score} (written to {baseline_path})")
        return 0

    result = evaluate_regression(baseline["risk_score"], new_score)
    print(result.message)
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
