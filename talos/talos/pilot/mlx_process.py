"""Hard-kill a single owned request process. No model is launched on import."""
import json,os,signal,subprocess,tempfile,threading
from pathlib import Path


def offline_environment():
    return {'LANG':'C.UTF-8','PYTHONHASHSEED':'0','HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1',
        'HF_DATASETS_OFFLINE':'1','HF_HUB_DISABLE_TELEMETRY':'1','LANGSMITH_TRACING':'false','OTEL_SDK_DISABLED':'true'}


class RequestCancelled(TimeoutError):
    def __init__(self,pid,reaped):
        super().__init__('owned MLX request timed out/cancelled; usage/finality incomplete')
        self.pid=pid;self.reaped=reaped


class OwnedRequest:
    def __init__(self):self.process=None;self.cancelled=False;self.lock=threading.RLock()

    def cancel(self):
        with self.lock:
            self.cancelled=True;p=self.process
            if p is not None and p.poll() is None:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                p.wait(timeout=5)

    def run(self,command,payload,timeout_ms):
        if self.cancelled or self.process is not None:raise PermissionError('owned request cannot be reused')
        with tempfile.TemporaryDirectory(prefix='talos-mlx-request-') as directory:
            env=offline_environment();env['TMPDIR']=directory
            with self.lock:
                if self.cancelled:raise PermissionError('cancelled before request spawn')
                self.process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    text=True,start_new_session=True,env=env,cwd=directory)
            try:
                out,_=self.process.communicate(json.dumps(payload),timeout=timeout_ms/1000)
                if self.cancelled:raise RequestCancelled(self.process.pid,self.process.poll() is not None)
                if self.process.returncode or len(out)>2000000:raise ValueError('isolated MLX worker failed/oversized; no retry')
                return json.loads(out)
            except subprocess.TimeoutExpired:
                self.cancel();raise RequestCancelled(self.process.pid,self.process.poll() is not None) from None
            except BaseException:
                if self.process.poll() is None:self.cancel()
                raise
