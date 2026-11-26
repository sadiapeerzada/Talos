"""One shared DEV batch ledger. Proposed ceilings are not approval authority."""
import time
from talos.pilot.mlx_spec import ProposedMLXPilot


class MLXBatchLedger:
    def _caps(self):return ProposedMLXPilot()

    def __init__(self,batch_id, *, clock=time.monotonic,state_path=None):
        if not batch_id:raise ValueError('explicit batch identity required')
        self.batch_id=batch_id;self.clock=clock;self.started=clock();self.episodes={};self.closed=False;self.stop_reason=None
        self.caps=self._caps();self.recorder=None;self.initial_sha256=None
        if state_path is not None:
            from talos.research.recorder import Recorder
            from talos.corpus.models import content_hash
            from datetime import datetime,timezone
            self.recorder=Recorder(state_path,create=True)
            initial={'batch_id':batch_id,'caps':self.caps.model_dump(mode='json'),'created_utc':datetime.now(timezone.utc).isoformat(),'resume':'NOT_SUPPORTED'}
            self.initial_sha256=content_hash(initial);self.recorder.append('MLX_batch_manifest',initial)

    def check(self):
        if self.closed or (self.clock()-self.started)*1000>=self.caps.total_wall_ms:
            self.closed=True;raise TimeoutError('proposed total DEV wall ceiling exhausted')

    def begin(self,episode_id):
        self.check()
        if episode_id in self.episodes:raise ValueError('episode identity cannot be reused')
        if len(self.episodes)>=self.caps.episodes:raise PermissionError('proposed eight episode ceiling exhausted')
        self.episodes[episode_id]=0
        if self.recorder:self.recorder.append('MLX_episode',self.snapshot())

    def request(self,episode_id):
        self.check()
        if episode_id not in self.episodes:raise ValueError('episode not reserved')
        if self.episodes[episode_id]>=self.caps.model_requests_per_episode:raise PermissionError('proposed four request ceiling exhausted')
        self.episodes[episode_id]+=1
        if self.recorder:self.recorder.append('MLX_request_intent',self.snapshot())

    def remaining_ms(self):
        self.check();return max(0,self.caps.total_wall_ms-int((self.clock()-self.started)*1000))

    def snapshot(self):
        return {'batch_id':self.batch_id,'episodes':dict(self.episodes),'request_attempts':sum(self.episodes.values()),
            'elapsed_ms':int((self.clock()-self.started)*1000),'paid_API_spending_inr':0,
            'actual_hardware_cost':None,'caps_status':'PROPOSED_NOT_APPROVED','approval_created':False,'closed':self.closed,'stop_reason':self.stop_reason}

    def close(self):
        self.closed=True
        if self.recorder and not self.recorder.lock.closed:
            self.recorder.append('MLX_batch_stop',self.snapshot());self.recorder.seal();self.recorder.close()

    def halt(self,reason):
        self.closed=True;self.stop_reason=reason
        if self.recorder:self.recorder.append('MLX_batch_abstained',self.snapshot())
