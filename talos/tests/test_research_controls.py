"""Outcome-based positive/negative gates plus actual failed-test sentinel."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

from talos.judging import Outcome, judge
from talos.research import execute,replay
from talos.targets import ControlledEnvironment
from .research_helpers import control_plan


@pytest.mark.parametrize('variant,suffix,fault,expected',[
    ('vulnerable','DIRECT','none',Outcome.CONFIRMED),
    ('hardened','DIRECT','none',Outcome.BLOCKED),
    ('vulnerable','AUTHORIZED','none',Outcome.NO_VIOLATION),
    ('hardened','AUTHORIZED','none',Outcome.NO_VIOLATION),
    ('vulnerable','DIRECT','missing_audit',Outcome.UNKNOWN),
])
def test_golden_research_control(tmp_path,monkeypatch,variant,suffix,fault,expected):
    # Test-only mutation flag, not a runtime research option or provider opt-in.
    if os.environ.get('TALOS_TEST_DISABLED_DETECTOR')=='1':
        import talos.research.runner as runner
        def disabled(observation,**kwargs):
            return judge(observation)  # no policy/evidence: always abstains
        monkeypatch.setattr(runner,'judge',disabled)
    with ControlledEnvironment('it-helpdesk',variant=variant) as env:
        plan=control_plan(env,trust=True,suffix=suffix)
        raw=plan.model_dump();raw['cells'][0]['tool_fault']=fault
        plan=type(plan).model_validate(raw)
        # A disabled detector must fail either replay consistency or expectation.
        execute(plan,env,tmp_path/'run')
        report=replay(tmp_path/'run')
        assert report['results']['cell-0'].outcome==expected


def test_disabled_detector_causes_actual_regression_test_failure():
    env=dict(os.environ);env['TALOS_TEST_DISABLED_DETECTOR']='1'
    result=subprocess.run([sys.executable,'-m','pytest',str(Path(__file__)),
                           '-k','test_golden_research_control','-q'],env=env,capture_output=True,text=True)
    assert result.returncode==1,result.stdout+result.stderr
    assert 'failed' in result.stdout
    assert 'test_golden_research_control' in result.stdout
