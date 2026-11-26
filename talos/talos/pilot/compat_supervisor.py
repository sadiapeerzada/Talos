"""One-shot mutual supervision and pre-payload child registration.

No model launcher, authority or inference CLI. Single-process-failure coverage
requires at least one of supervisor/coordinator to remain runnable. Simultaneous
death, hostile root and kernel/driver hangs are not claimed covered.
"""
import json,os,selectors,signal,socket,subprocess,threading,time


def kill_group(pid):
    try:os.killpg(pid,signal.SIGKILL)
    except ProcessLookupError:pass


class CompatibilitySupervisor:
    def __init__(self):self.process=None;self.workers=set();self.events=[];self.cancelled=threading.Event()

    def cancel(self):self.cancelled.set()

    def run(self,command,timeout_ms, *, environment=None,stdout=None,stderr=None):
        if self.process is not None:raise PermissionError('supervisor is one-shot')
        parent,child=socket.socketpair();started=time.monotonic();data=b'';completed=False;channel_lost=False
        env=dict(environment or {});env['TALOS_COMPAT_SUPERVISOR_FD']=str(child.fileno())
        env['TALOS_COMPAT_SUPERVISOR_PID']=str(os.getpid())
        try:
            self.process=subprocess.Popen(command,env=env,pass_fds=(child.fileno(),),start_new_session=True,stdout=stdout,stderr=stderr)
            child.close();parent.setblocking(False)
            with selectors.DefaultSelector() as selected:
                selected.register(parent,selectors.EVENT_READ)
                while self.process.poll() is None and not channel_lost:
                    if self.cancelled.is_set() or (time.monotonic()-started)*1000>=timeout_ms:
                        self.events.append({'kind':'stop','reason':'cancelled_or_deadline'});break
                    for _,_ in selected.select(0.02):
                        chunk=parent.recv(4096)
                        if not chunk:
                            if completed:selected.unregister(parent);continue
                            self.events.append({'kind':'stop','reason':'coordinator_supervision_channel_lost'})
                            channel_lost=True;break
                        data+=chunk
                        if len(data)>8192:raise PermissionError('oversized supervisor message')
                        while b'\n' in data:
                            line,data=data.split(b'\n',1);message=json.loads(line)
                            if message=={'op':'complete'}:
                                completed=True;self.events.append({'kind':'coordinator_finished_requests'});continue
                            if set(message)!={'op','pid'} or message['op']!='register' or type(message['pid']) is not int:
                                raise PermissionError('unknown supervisor operation')
                            pid=message['pid']
                            # Check actual parent before acknowledging release. No caller
                            # can register an arbitrary unrelated user's process/group.
                            actual=int(subprocess.check_output(['/bin/ps','-p',str(pid),'-o','ppid='],text=True,timeout=1).strip())
                            if actual!=self.process.pid or os.getpgid(pid)!=pid:raise PermissionError('unowned native request group')
                            self.workers.add(pid);self.events.append({'kind':'registered_before_payload','pid':pid,'coordinator_pid':actual})
                            parent.sendall(json.dumps({'registered':pid}).encode()+b'\n')
            returncode=self.process.poll()
            return {'coordinator_returncode':returncode,'events':list(self.events),'inference_authorized_by_supervisor':False}
        finally:
            # The coordinator's channel monitor also cancels its active child if
            # this supervisor disappears. Do not rely on coordinator finally.
            for pid in self.workers:kill_group(pid)
            if self.process is not None:
                if self.process.poll() is None:kill_group(self.process.pid)
                self.process.wait(timeout=5)
            parent.close();child.close()


class CompatibilitySupervisorClient:
    def __init__(self,expected_supervisor_pid):
        if expected_supervisor_pid!=os.getppid() or str(expected_supervisor_pid)!=os.environ.get('TALOS_COMPAT_SUPERVISOR_PID'):
            raise PermissionError('actual approved supervisor parent unavailable')
        value=os.environ.pop('TALOS_COMPAT_SUPERVISOR_FD',None)
        if value is None:raise PermissionError('private inherited supervisor channel unavailable')
        fd=int(value)
        if fd<3:raise PermissionError('invalid supervisor capability descriptor')
        self.socket=socket.socket(fileno=fd);self.lock=threading.Lock();self.active=None
        self.condition=threading.Condition();self.acknowledged=set();self.dead=False;self.closed=False
        self.monitor=threading.Thread(target=self._monitor,daemon=True);self.monitor.start()

    def _monitor(self):
        pending=b''
        try:
            while not self.closed:
                chunk=self.socket.recv(4096)
                if not chunk:break
                pending+=chunk
                if len(pending)>8192:break
                while b'\n' in pending:
                    line,pending=pending.split(b'\n',1);reply=json.loads(line)
                    with self.condition:self.acknowledged.add(reply['registered']);self.condition.notify_all()
        except (OSError,ValueError,KeyError):pass
        finally:
            with self.condition:self.dead=True;self.condition.notify_all()
            if not self.closed and self.active is not None:self.active.cancel()

    def register(self,request,timeout_ms):
        self.active=request
        with self.condition:
            if self.dead:raise PermissionError('supervisor disappeared before payload release')
            self.socket.sendall(json.dumps({'op':'register','pid':request.process.pid}).encode()+b'\n')
            deadline=time.monotonic()+min(timeout_ms/1000,1.0)
            while request.process.pid not in self.acknowledged:
                remaining=deadline-time.monotonic()
                if self.dead or remaining<=0:raise PermissionError('supervisor registration not acknowledged')
                self.condition.wait(remaining)

    def close(self):
        self.closed=True
        try:self.socket.sendall(b'{"op":"complete"}\n')
        except OSError:pass
        try:self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        self.socket.close();self.monitor.join(timeout=1)
