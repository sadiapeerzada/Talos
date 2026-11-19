"""Prospective provider receipt accounting, without transport or execution authority."""
from talos.readiness.contracts import ProviderUsage,ModelConfiguration
from talos.research.budget import Budget,BudgetStop
from talos.research.contracts import Limits


class ProviderLedger:
    """Reserves explicit worst-case usage; rejects stale/wrong/missing receipts.

    This validates supplied records, not their authenticity or billing accuracy.
    A ledger is never a capability to call a model.
    """
    def __init__(self,limits:Limits,model:ModelConfiguration, *, currency:str,price_schedule_sha256:str):
        self.budget=Budget(limits);self.model=model;self.currency=currency;self.price_schedule_sha256=price_schedule_sha256
        self.pending_id=None;self.seen=set();self.receipts=[];self.seen_receipts=set()

    def reserve(self,request_id:str, *, input_tokens:int,output_tokens:int,cost_microunits:int,retries:int,elapsed_ms:int):
        if not request_id or request_id in self.seen:raise ValueError('exact new provider request identity required')
        if output_tokens>self.model.max_output_tokens:raise ValueError('output reserve exceeds approved model configuration')
        self.budget.reserve({'target_model_calls':1,'input_tokens':input_tokens,'output_tokens':output_tokens,
            'cost_microunits':cost_microunits,'retries':retries,'elapsed_ms':elapsed_ms})
        self.pending_id=request_id

    def settle(self,usage:ProviderUsage|None, *, elapsed_ms:int):
        if self.pending_id is None:raise ValueError('receipt without reservation')
        pending=self.pending_id;self.pending_id=None;self.seen.add(pending)
        try:
            if usage is None:raise ValueError('missing provider usage')
            usage=ProviderUsage.model_validate(usage.model_dump())
            if (usage.request_id!=pending or usage.model_id!=self.model.model_id or usage.model_revision!=self.model.revision or
                usage.currency!=self.currency or usage.price_schedule_sha256!=self.price_schedule_sha256 or
                usage.provider_receipt_sha256 in self.seen_receipts):
                raise ValueError('provider model/revision/pricing/currency/request mismatch')
        except (ValueError,TypeError):
            self.budget.settle({'target_model_calls':1,'input_tokens':None,'output_tokens':None,
                'cost_microunits':None,'retries':None,'elapsed_ms':elapsed_ms})
            raise AssertionError('unreachable missing-usage stop')
        self.seen_receipts.add(usage.provider_receipt_sha256)
        self.receipts.append(usage)
        self.budget.settle({'target_model_calls':1,'input_tokens':usage.input_tokens,'output_tokens':usage.output_tokens,
            'cost_microunits':usage.cost_microunits,'retries':usage.retries,'elapsed_ms':elapsed_ms})

    def invoke(self,*args,**kwargs):raise PermissionError('No approved provider transport or authority; ledger is not consent')
