"""No trusted identities, approval signatures or positive authority fixtures created."""
from datetime import datetime,timezone,timedelta
import hashlib,json,subprocess,sys,os
from pathlib import Path
import pytest
from talos.pilot import ApprovalGate,LocalModelBackend
from talos.pilot.authority import Registry
from talos.pilot.custody import OwnedServer
from talos.readiness.agent import control
from .pilot_helpers import plan,scope


@pytest.mark.parametrize('opt_in',[False,True])
def test_missing_actual_authority_blocks_before_any_client(monkeypatch,opt_in):
    import httpx
    def forbidden(*a,**kw):raise AssertionError('client constructed without authority')
    monkeypatch.setattr(httpx,'Client',forbidden)
    p=plan();backend=LocalModelBackend(p,scope(p),opt_in=opt_in)
    with pytest.raises(PermissionError):control(p,backend=backend)
    assert backend.receipts==[]


@pytest.mark.parametrize('key',['OPENAI_API_KEY','ANTHROPIC_API_KEY','TALOS_APPROVAL','TALOS_PILOT_ENABLED'])
def test_environment_cannot_create_authority(monkeypatch,key):
    monkeypatch.setenv(key,'not-authorization')
    with pytest.raises(PermissionError):ApprovalGate().require(scope(plan()),opt_in=True)


@pytest.mark.parametrize('mutation',['missing','hash','expired','empty','duplicate_json','malformed'])
def test_unverifiable_or_incomplete_real_record_inputs_fail_closed(tmp_path,mutation):
    path=tmp_path/'operator-input.json'
    raw={'schema_version':'talos.external-authority-registry.v1','valid_until':(datetime.now(timezone.utc)+timedelta(days=1)).isoformat(),'authorities':[]}
    if mutation=='expired':raw['valid_until']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
    path.write_text(json.dumps(raw) if mutation!='malformed' else '{}')
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    if mutation=='missing':path.unlink()
    if mutation=='hash':digest='0'*64
    if mutation=='duplicate_json':path.write_text('{"authorities":[],"authorities":[]}')
    with pytest.raises((PermissionError,ValueError)):ApprovalGate(registry_path=path,registry_sha256=digest).require(scope(plan()),opt_in=True)


def test_unaware_authority_expiry_rejected():
    with pytest.raises(ValueError):Registry(valid_until='2099-01-01T00:00:00',authorities=())


def test_plain_pid_cannot_authorize_killing_an_unowned_server(tmp_path):
    with pytest.raises(PermissionError):OwnedServer(os.getpid(),weights=tmp_path/'x',server=tmp_path/'y',template=tmp_path/'z')


def test_owned_non_model_test_process_hard_cancel_reaped(tmp_path):
    # Actual software sleep process, never a model/backend/custody attestation.
    process=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],start_new_session=True)
    owned=OwnedServer(process,weights=tmp_path/'unused',server=Path(sys.executable),template=tmp_path/'unused')
    try:
        owned.arm_deadline(100);process.wait(timeout=3)
        assert owned.closed and process.poll() is not None
        with pytest.raises(ProcessLookupError):os.kill(process.pid,0)
    finally:owned.cancel()
