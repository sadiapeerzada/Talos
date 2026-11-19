"""Network-denied child; no SDK, credentials, plugin or provider transport."""
import json,os,socket,sys
from pathlib import Path

# -I ignores inherited search paths. Only this checked-in source root is added.
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))


def deny(*a,**kw):raise PermissionError('Stage A offline worker denies network and subprocesses')


def audit(event,args):
    if event in ('socket.connect','socket.getaddrinfo','subprocess.Popen','os.system','os.exec','os.posix_spawn'):deny()


def main():
    socket.socket.connect=deny;socket.socket.connect_ex=deny;socket.getaddrinfo=deny
    sys.addaudithook(audit)
    from talos.readiness.contracts import EngineeringPlan
    from talos.readiness.agent import control
    plan=EngineeringPlan.model_validate_json(sys.stdin.read(1000000))
    try:result=control(plan)
    except Exception as error:
        # Provider credentials/exception text are never copied to the archive.
        result={'worker_failure':type(error).__name__,'primary_eligible':False,'actual_provider_usage':None}
    print(json.dumps(result,sort_keys=True,allow_nan=False))


if __name__=='__main__':main()
