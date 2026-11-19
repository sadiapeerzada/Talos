"""Actual owned local server handle, artifact checks and process-group cancellation."""
from pathlib import Path
import json,os,signal,subprocess,threading,time
from talos.pilot.authority import file_hash


class OwnedServer:
    """Attaches only to a caller-owned Popen, never an arbitrary PID from JSON.

    Provisioning/launch, OS egress containment and independent cancellation review
    must be supplied by the operator; B1 never starts a model server.
    """
    def __init__(self,process:subprocess.Popen, *, weights:Path,server:Path,template:Path):
        if type(process) is not subprocess.Popen:raise PermissionError('real caller-owned process handle required')
        self.process=process;self.weights=Path(weights);self.server=Path(server);self.template=Path(template)
        self.closed=False;self._lock=threading.RLock();self._timer=None;self._fingerprints=None

    def check(self,model,lease_path,scope):
        with self._lock:
            if self.closed or self.process.poll() is not None:raise PermissionError('owned local server unavailable')
            if os.getpgid(self.process.pid)!=self.process.pid or os.getpgrp()==self.process.pid:
                raise PermissionError('server requires separately owned isolated process group')
            paths=(self.weights,self.server,self.template)
            fingerprints=tuple((p.stat().st_dev,p.stat().st_ino,p.stat().st_size,p.stat().st_mtime_ns) for p in paths)
            if self._fingerprints is None:
                if tuple(file_hash(p) for p in paths)!=(model.weights_sha256,model.server_sha256,model.chat_template_sha256):
                    raise PermissionError('weights/server/template artifact changed')
                self._fingerprints=fingerprints
            elif fingerprints!=self._fingerprints:raise PermissionError('deployment artifacts changed during run')
            # The approved server context bounds worst-case prompt-token reservation.
            expected_command=[str(self.server),'--model',str(self.weights),'--alias',model.configuration.model_id,
                '--host','127.0.0.1','--port',str(__import__('urllib.parse',fromlist=['urlsplit']).urlsplit(model.endpoint).port),
                '--ctx-size',str(model.max_input_tokens),'--parallel','1','--jinja','--chat-template-file',str(self.template),
                '--no-webui','--no-context-shift']
            if self.process.args!=expected_command:raise PermissionError('unreviewed server command/context/tool/plugin configuration')
            lease=__import__('talos.pilot.protocol',fromlist=['loads']).loads(Path(lease_path).read_text())
            required={'pid':self.process.pid,'plan_sha256':scope.plan_sha256,'run_nonce':scope.run_nonce,
                'endpoint':model.endpoint,'weights_sha256':model.weights_sha256,'server_sha256':model.server_sha256,
                'chat_template_sha256':model.chat_template_sha256,'command':self.process.args}
            if lease!=required:raise PermissionError('signed provider custody does not match actual owned deployment')

    def arm_deadline(self,timeout_ms):
        with self._lock:
            if self._timer is not None or self.closed:raise PermissionError('server lease cannot be reused')
            self._timer=threading.Timer(timeout_ms/1000,self.cancel);self._timer.daemon=True;self._timer.start()

    def cancel(self):
        with self._lock:
            self.closed=True
            if self._timer is not None:self._timer.cancel()
            if self.process.poll() is None:
                try:os.killpg(self.process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
            self.process.wait(timeout=5)
            # This confirms the owned leader is reaped, not arbitrary escaped native code.
            return {'owned_server_reaped':self.process.poll() is not None,'late_provider_usage':'UNKNOWN_IF_INTERRUPTED'}
