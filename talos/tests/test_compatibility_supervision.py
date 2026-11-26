"""Harmless process lifecycle tests; no models, approvals or system services."""
import json,os,signal,subprocess,sys,time,threading
from pathlib import Path
import pytest
from talos.pilot.compat_supervisor import CompatibilitySupervisor
from talos.pilot.mlx_process import OwnedRequest

ROOT=Path(__file__).resolve().parents[1]


def process_live(pid):
    result=subprocess.run(['/bin/ps','-p',str(pid),'-o','stat='],capture_output=True,text=True)
    return bool(result.stdout.strip()) and not result.stdout.strip().startswith('Z')


def wait_dead(pid):
    deadline=time.monotonic()+3
    while time.monotonic()<deadline and process_live(pid):time.sleep(0.02)
    return not process_live(pid)


def coordinator(tmp_path,mode):
    code=tmp_path/('coordinator-'+mode+'.py');pidfile=tmp_path/('pids-'+mode+'.json')
    child='import json,os,sys,time; from pathlib import Path; d=json.load(sys.stdin); Path(d["pidfile"]).write_text(json.dumps({"worker":os.getpid(),"coordinator":os.getppid()})); time.sleep(d["sleep"]); print(json.dumps({"non_model":True}))'
    code.write_text('import sys,os,json,threading,time\nfrom pathlib import Path\nsys.path.insert(0,'+repr(str(ROOT))+')\n'
        'from talos.pilot.compat_supervisor import CompatibilitySupervisorClient\nfrom talos.pilot.mlx_process import OwnedRequest\n'
        'client=CompatibilitySupervisorClient(os.getppid());request=OwnedRequest()\n'
        +('threading.Timer(0.8,lambda:os._exit(7)).start()\n' if mode=='crash' else '')+
        'try:\n result=request.run([sys.executable,"-c",'+repr(child)+'],{"pidfile":'+repr(str(pidfile))+',"sleep":'+('0.01' if mode=='normal' else '10')+'},'+('150' if mode=='request_timeout' else '5000')+',supervisor=client)\n'
        'except Exception as error:\n result={"failure":type(error).__name__}\n'
        'finally:\n client.close()\n'
        'Path('+repr(str(tmp_path/('result-'+mode+'.json')))+').write_text(json.dumps(result))\n')
    return code,pidfile


@pytest.mark.parametrize('mode',['normal','request_timeout','crash','supervisor_deadline','supervisor_cancel'])
def test_registration_and_cleanup_for_single_process_failure(tmp_path,mode):
    code,pidfile=coordinator(tmp_path,mode);supervisor=CompatibilitySupervisor()
    timer=threading.Timer(1.5,supervisor.cancel) if mode=='supervisor_cancel' else None
    if timer:timer.start()
    result=supervisor.run([sys.executable,str(code)],1500 if mode=='supervisor_deadline' else 6000,
        environment={'LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
    assert any(e['kind']=='registered_before_payload' for e in result['events'])
    pids=json.loads(pidfile.read_text()) if pidfile.exists() else {'worker':next(iter(supervisor.workers))}
    assert wait_dead(pids['worker'])
    assert supervisor.process.poll() is not None
    if timer:timer.join(timeout=1)
    if mode=='normal':assert json.loads((tmp_path/'result-normal.json').read_text())=={'non_model':True}


def test_supervisor_death_triggers_coordinator_cleanup(tmp_path):
    code,pidfile=coordinator(tmp_path,'supervisor_crash')
    launch=tmp_path/'supervisor.py';launch.write_text('import sys\nsys.path.insert(0,'+repr(str(ROOT))+')\n'
        'from talos.pilot.compat_supervisor import CompatibilitySupervisor\n'
        'CompatibilitySupervisor().run([sys.executable,'+repr(str(code))+'],6000,environment={"LANG":"C.UTF-8"})\n')
    process=subprocess.Popen([sys.executable,str(launch)],start_new_session=True)
    pids={}
    try:
        deadline=time.monotonic()+3
        while not pidfile.exists() and time.monotonic()<deadline:time.sleep(0.01)
        pids=json.loads(pidfile.read_text());os.kill(process.pid,signal.SIGKILL);process.wait(timeout=3)
        assert wait_dead(pids['worker']) and wait_dead(pids['coordinator'])
    finally:
        if process.poll() is None:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=3)
        for pid in pids.values():
            if process_live(pid):
                try:os.killpg(pid,signal.SIGKILL)
                except ProcessLookupError:pass


def test_rejected_registration_cannot_release_payload(tmp_path):
    marker=tmp_path/'must-not-exist'
    class Reject:
        def register(self,request,timeout_ms):raise PermissionError('no approved supervisor')
    code='import sys; from pathlib import Path; sys.stdin.read(); Path('+repr(str(marker))+').touch()'
    request=OwnedRequest()
    with pytest.raises(PermissionError):request.run([sys.executable,'-c',code],{},1000,supervisor=Reject())
    assert not marker.exists() and request.process.poll() is not None


def test_supervised_input_write_cannot_block_deadline():
    class Ack:
        def register(self,request,timeout_ms):pass
    request=OwnedRequest()
    with pytest.raises(TimeoutError):request.run([sys.executable,'-c','import time; time.sleep(5)'],{'large':'x'*200000},100,supervisor=Ack())
    assert request.process.poll() is not None
