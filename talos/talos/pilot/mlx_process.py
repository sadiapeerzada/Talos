"""Hard-kill a single owned request process. No model is launched on import."""
import hashlib,json,os,selectors,signal,subprocess,tempfile,threading,time
from pathlib import Path


def offline_environment():
    return {'LANG':'C.UTF-8','PYTHONHASHSEED':'0','HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1',
        'HF_DATASETS_OFFLINE':'1','HF_HUB_DISABLE_TELEMETRY':'1','LANGSMITH_TRACING':'false','OTEL_SDK_DISABLED':'true'}


class RequestCancelled(TimeoutError):
    def __init__(self,pid,reaped):
        super().__init__('owned MLX request timed out/cancelled; usage/finality incomplete')
        self.pid=pid;self.reaped=reaped


class OwnedRequest:
    def __init__(self):self.process=None;self.cancelled=False;self.lock=threading.RLock();self.diagnostics=None

    def cancel(self):
        with self.lock:
            self.cancelled=True;p=self.process
            if p is not None:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                p.wait(timeout=5)

    def run(self,command,payload,timeout_ms):
        started=time.monotonic()
        if self.cancelled or self.process is not None:raise PermissionError('owned request cannot be reused')
        encoded=json.dumps(payload,allow_nan=False).encode()
        if len(encoded)>1000000:raise ValueError('owned request payload exceeds worker input ceiling')
        with tempfile.TemporaryDirectory(prefix='talos-mlx-request-') as directory:
            env=offline_environment();env['TMPDIR']=directory
            input_path=Path(directory)/'request.json';input_path.write_bytes(encoded)
            with input_path.open('rb') as input_stream,self.lock:
                if self.cancelled:raise PermissionError('cancelled before request spawn')
                self.process=subprocess.Popen(command,stdin=input_stream,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    start_new_session=True,env=env,cwd=directory)
            streams={};deadline=started+timeout_ms/1000
            try:
                # Drain both streams incrementally. communicate() buffered unlimited
                # stderr/stdout until timeout; each stream is now capped at 2 MB.
                with selectors.DefaultSelector() as selector:
                    for name,stream in (('stdout',self.process.stdout),('stderr',self.process.stderr)):
                        selector.register(stream,selectors.EVENT_READ,name);streams[name]=bytearray()
                    while selector.get_map():
                        remaining=deadline-time.monotonic()
                        if remaining<=0 or self.cancelled:raise subprocess.TimeoutExpired(command,timeout_ms/1000)
                        for key,_ in selector.select(min(remaining,0.05)):
                            chunk=os.read(key.fileobj.fileno(),65536)
                            if not chunk:selector.unregister(key.fileobj);continue
                            if len(streams[key.data])+len(chunk)>2000000:raise ValueError('isolated MLX worker stream ceiling exceeded')
                            streams[key.data].extend(chunk)
                self.process.wait(timeout=max(0.001,deadline-time.monotonic()))
                if self.cancelled:raise RequestCancelled(self.process.pid,self.process.poll() is not None)
                if self.process.returncode:raise ValueError('isolated MLX worker failed; no retry')
                return json.loads(streams['stdout'].decode('utf-8'))
            except subprocess.TimeoutExpired:
                self.cancel();raise RequestCancelled(self.process.pid,self.process.poll() is not None) from None
            except BaseException:
                if self.process.poll() is None:self.cancel()
                raise
            finally:
                # A leader may exit while descendants retain pipes. Reap the
                # original owned group even after the leader has terminated.
                try:os.killpg(self.process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                self.process.wait(timeout=5)
                self.diagnostics={name:{'bytes_retained':len(value),'sha256':hashlib.sha256(value).hexdigest()} for name,value in streams.items()}
                self.diagnostics['stderr_text']=bytes(streams.get('stderr',b'')).decode('utf-8',errors='replace')
                for stream in (self.process.stdout,self.process.stderr):stream.close()
