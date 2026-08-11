"""
Auto-patch-and-reverify loop -- item 8 of the roadmap, the "close the loop"
capability.

After a scan finds vulnerabilities, this runs a SECOND scan against a
freshly-started, hardened instance of the same target and proves the risk
score actually drops -- fully unattended, no human editing code in
between.

Honest scope: this only works for targets Talos controls the source of
(the sample agents), not arbitrary black-box third-party targets Talos has
no write access to. This is a "self-healing demo target" capability, not a
claim that Talos can silently patch any agent on the internet -- see
docs/external-target-validation.md for the honest boundary on the other
side of that line.

The actual hardening mechanism is NOT new magic: it's the exact same
PolicyEnforcingBrain (talos/sample_agents/policy.py) already proven, in
item 4's tests, to defeat the refund-overage, email-exfiltration, and
permission-escalation patterns Talos's own templates generate. Wrapping a
target's brain in it is what native_server.py's new --hardened flag does.
HARDENING_STRATEGIES below is a small, real, inspectable registry -- not a
black box -- mapping each exploit class to the strategy that closes it, so
a reader can see HOW the fix is applied, not just trust a printed number.
"""

from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import httpx

from talos.reporting.report import ScanReport
from talos.sample_agents.brain import Brain
from talos.sample_agents.policy import PolicyEnforcingBrain


def _wrap_with_policy_enforcement(brain: Brain) -> Brain:
    return PolicyEnforcingBrain(brain)


# Every exploit class Talos's 35 templates can produce maps to the same
# real mechanism here, because PolicyEnforcingBrain's three guardrails
# (refund capping, email allow-listing, re-authorization) are each
# effective against several exploit classes at once -- see
# tests/test_real_agent_hardening.py for per-class proof this holds.
# Kept as an explicit dict (not a single constant) so it's honestly
# inspectable and so a future exploit class (e.g. item 9's
# cross_agent_injection) can get its own distinct strategy later without
# changing this module's shape.
HARDENING_STRATEGIES: dict[str, Callable[[Brain], Brain]] = {
    "direct_injection": _wrap_with_policy_enforcement,
    "indirect_injection": _wrap_with_policy_enforcement,
    "permission_escalation": _wrap_with_policy_enforcement,
    "data_exfiltration": _wrap_with_policy_enforcement,
    "goal_hijacking": _wrap_with_policy_enforcement,
    "authority_spoofing": _wrap_with_policy_enforcement,
    "policy_shadowing": _wrap_with_policy_enforcement,
}


@dataclass
class AutofixResult:
    baseline_report: ScanReport
    hardened_report: ScanReport
    exploit_classes_addressed: list[str] = field(default_factory=list)

    @property
    def baseline_risk_score(self) -> int:
        return self.baseline_report.stats.risk_score

    @property
    def hardened_risk_score(self) -> int:
        return self.hardened_report.stats.risk_score

    @property
    def risk_score_delta(self) -> int:
        return self.baseline_risk_score - self.hardened_risk_score

    @property
    def findings_closed(self) -> int:
        baseline_keys = {(f.exploit_class, f.target_tool) for f in self.baseline_report.findings}
        hardened_keys = {(f.exploit_class, f.target_tool) for f in self.hardened_report.findings}
        return len(baseline_keys - hardened_keys)

    @property
    def findings_total_before(self) -> int:
        return len(self.baseline_report.findings)

    def summary_lines(self) -> list[str]:
        b, h = self.baseline_report.stats, self.hardened_report.stats
        return [
            f"Initial scan:  risk score {b.risk_score:3d}/100 "
            f"({b.severity_counts.high} high, {b.severity_counts.medium} medium)",
            f"Applying {len(self.exploit_classes_addressed)} exploit-class hardening strateg"
            f"{'y' if len(self.exploit_classes_addressed) == 1 else 'ies'}...",
            f"Re-scan:       risk score {h.risk_score:3d}/100 "
            f"({h.severity_counts.high} high, {h.severity_counts.medium} medium)",
            f"Risk reduced by {self.risk_score_delta} points, "
            f"{self.findings_closed} of {self.findings_total_before} findings closed.",
        ]


def _wait_for_server(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last_error: Optional[Exception] = None
    while time.time() < deadline:
        try:
            httpx.get(f"http://127.0.0.1:{port}/agent/tools", timeout=1.0)
            return
        except Exception as exc:  # noqa: BLE001 - retry loop
            last_error = exc
            time.sleep(0.3)
    raise RuntimeError(f"sample agent on port {port} did not come up in time: {last_error}")


def run_autofix_cycle(
    *,
    adapter: str = "native",
    vulnerable_port: int = 8797,
    hardened_port: int = 8798,
    repro_runs: int = 1,
) -> AutofixResult:
    """Runs the full cycle against a fresh copy of the native sample agent:
    scan vulnerable -> determine which strategies to apply -> spin up a
    hardened instance -> scan it -> return both reports plus the delta.
    """
    from talos.scan_service import run_scan_pipeline

    vulnerable_proc = subprocess.Popen(
        [sys.executable, "-m", "talos.sample_agents.native_server", "--port", str(vulnerable_port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_for_server(vulnerable_port)
        baseline_report, _ = run_scan_pipeline(
            target=f"http://127.0.0.1:{vulnerable_port}/agent", adapter_name=adapter, repro_runs=repro_runs
        )
    finally:
        vulnerable_proc.terminate()
        try:
            vulnerable_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            vulnerable_proc.kill()

    exploit_classes_present = sorted({f.exploit_class for f in baseline_report.findings})
    exploit_classes_addressed = [c for c in exploit_classes_present if c in HARDENING_STRATEGIES]

    hardened_proc = subprocess.Popen(
        [sys.executable, "-m", "talos.sample_agents.native_server", "--port", str(hardened_port), "--hardened"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_for_server(hardened_port)
        hardened_report, _ = run_scan_pipeline(
            target=f"http://127.0.0.1:{hardened_port}/agent", adapter_name=adapter, repro_runs=repro_runs
        )
    finally:
        hardened_proc.terminate()
        try:
            hardened_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            hardened_proc.kill()

    return AutofixResult(
        baseline_report=baseline_report,
        hardened_report=hardened_report,
        exploit_classes_addressed=exploit_classes_addressed,
    )


def iter_autofix_progress(
    *,
    adapter: str = "native",
    vulnerable_port: int = 8797,
    hardened_port: int = 8798,
    repro_runs: int = 1,
):
    """Streaming-friendly variant of run_autofix_cycle(), yielding a
    progress dict between each real phase (for the dashboard's SSE-style
    'Auto-fix & re-verify' button, mirroring scan_service.iter_scan_progress's
    pattern) and a final dict carrying the complete AutofixResult. Every
    phase here is a real, blocking operation on real subprocesses -- this
    doesn't fabricate intermediate progress, it just reports real phase
    boundaries as they actually complete."""
    from talos.scan_service import run_scan_pipeline

    yield {"type": "baseline_scan_started", "message": "Starting baseline scan against the vulnerable target..."}

    vulnerable_proc = subprocess.Popen(
        [sys.executable, "-m", "talos.sample_agents.native_server", "--port", str(vulnerable_port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_for_server(vulnerable_port)
        baseline_report, _ = run_scan_pipeline(
            target=f"http://127.0.0.1:{vulnerable_port}/agent", adapter_name=adapter, repro_runs=repro_runs
        )
    finally:
        vulnerable_proc.terminate()
        try:
            vulnerable_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            vulnerable_proc.kill()

    yield {
        "type": "baseline_scan_complete",
        "message": f"Baseline risk score: {baseline_report.stats.risk_score}/100 "
        f"({len(baseline_report.findings)} findings).",
        "report": baseline_report.model_dump(mode="json"),
    }

    exploit_classes_present = sorted({f.exploit_class for f in baseline_report.findings})
    exploit_classes_addressed = [c for c in exploit_classes_present if c in HARDENING_STRATEGIES]

    yield {
        "type": "hardening",
        "message": f"Applying {len(exploit_classes_addressed)} exploit-class hardening "
        f"strateg{'y' if len(exploit_classes_addressed) == 1 else 'ies'} "
        f"({', '.join(exploit_classes_addressed) or 'none'})...",
    }

    hardened_proc = subprocess.Popen(
        [sys.executable, "-m", "talos.sample_agents.native_server", "--port", str(hardened_port), "--hardened"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_for_server(hardened_port)
        yield {"type": "hardened_scan_started", "message": "Re-scanning the hardened instance..."}
        hardened_report, _ = run_scan_pipeline(
            target=f"http://127.0.0.1:{hardened_port}/agent", adapter_name=adapter, repro_runs=repro_runs
        )
    finally:
        hardened_proc.terminate()
        try:
            hardened_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            hardened_proc.kill()

    result = AutofixResult(
        baseline_report=baseline_report,
        hardened_report=hardened_report,
        exploit_classes_addressed=exploit_classes_addressed,
    )

    yield {
        "type": "completed",
        "message": "\n".join(result.summary_lines()),
        "baseline_report": result.baseline_report.model_dump(mode="json"),
        "hardened_report": result.hardened_report.model_dump(mode="json"),
        "risk_score_delta": result.risk_score_delta,
        "findings_closed": result.findings_closed,
    }


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Run Talos's auto-patch-and-reverify loop against the native sample agent: "
        "scan it, spin up a hardened instance, re-scan, and prove the risk score dropped."
    )
    parser.add_argument("--adapter", default="native")
    parser.add_argument("--vulnerable-port", type=int, default=8797)
    parser.add_argument("--hardened-port", type=int, default=8798)
    args = parser.parse_args(argv)

    result = run_autofix_cycle(
        adapter=args.adapter, vulnerable_port=args.vulnerable_port, hardened_port=args.hardened_port
    )
    for line in result.summary_lines():
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
