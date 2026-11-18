"""Reserve before calls; missing usage and overages close the ledger."""
from talos.research.contracts import DIMENSIONS, Limits


class BudgetStop(RuntimeError): pass


class Budget:
    def __init__(self, limits: Limits):
        self.limits=Limits.model_validate(limits.model_dump()).amounts
        self.used={key:0 for key in DIMENSIONS}
        self.pending=None
        self.stop_reason=None
        self.missing_dimensions=[]

    def _amounts(self,amounts):
        if not set(amounts)<=DIMENSIONS or any(type(v) is not int or v<0 for v in amounts.values()):
            raise ValueError('invalid budget amounts')
        return {k:amounts.get(k,0) for k in DIMENSIONS}

    def reserve(self,ceilings):
        if self.stop_reason or self.pending is not None:
            raise BudgetStop(self.stop_reason or 'unsettled reservation')
        values=self._amounts(ceilings)
        exceeded=[k for k,v in values.items() if self.used[k]+v>self.limits[k]]
        if exceeded:
            self.stop_reason='budget exhausted: '+','.join(sorted(exceeded))
            raise BudgetStop(self.stop_reason)
        self.pending=values

    def settle(self,actual):
        if self.pending is None:
            raise ValueError('no pending reservation')
        pending=self.pending
        missing={k for k,v in pending.items() if v>0 and actual.get(k) is None} | {k for k,v in actual.items() if v is None}
        if missing:
            # Preserve known amounts; do not turn absent usage into zero.
            known={k:v for k,v in actual.items() if v is not None}
            for k,v in self._amounts(known).items(): self.used[k]+=v
            self.missing_dimensions=sorted(missing)
            self.pending=None
            self.stop_reason='missing usage measurement; further calls prohibited'
            raise BudgetStop(self.stop_reason)
        values=self._amounts({k:v for k,v in actual.items() if v is not None})
        for k,v in values.items(): self.used[k]+=v
        self.pending=None
        if any(values[k]>pending[k] or self.used[k]>self.limits[k] for k in DIMENSIONS):
            self.stop_reason='actual usage exceeded reservation/limit; no further calls'
            raise BudgetStop(self.stop_reason)

    def snapshot(self):
        return {'limits':dict(self.limits),'used':{k:(None if k in self.missing_dimensions else v) for k,v in self.used.items()},
                'known_usage_lower_bound':dict(self.used),'missing_dimensions':list(self.missing_dimensions),'pending':self.pending,'stop_reason':self.stop_reason}
