"""Surface delivery interface, without a fabricated prompt adapter."""
from typing import Literal, Protocol
from pydantic import Field, model_validator
from talos.corpus.models import Model, Surface
from talos.corpus.planning import PublicOpportunity
from talos.judging import Observation


class DeliveryContext(Model):
    run_id: str
    cell_id: str
    target_id: str
    actor_id: str
    authorization_context_id: str
    scenario_id: str
    repeat_id: str
    case_identity: str


class DeliveryReceipt(Model):
    schema_version: Literal['talos.delivery-receipt.v1'] = 'talos.delivery-receipt.v1'
    adapter_id: str
    adapter_version: str
    context: DeliveryContext
    status: Literal['delivered','blocked','unknown']
    reason: str = Field(min_length=1)
    observations: tuple[Observation,...] = ()
    attacker_calls: int | None = Field(default=None,ge=0,strict=True)
    target_calls: int | None = Field(default=None,ge=0,strict=True)
    input_tokens: int | None = Field(default=None,ge=0,strict=True)
    output_tokens: int | None = Field(default=None,ge=0,strict=True)
    cost_microunits: int | None = Field(default=None,ge=0,strict=True)

    @model_validator(mode='after')
    def exact_scope(self):
        for observation in self.observations:
            if any(getattr(observation.action,k)!=getattr(self.context,k) for k in (
                'target_id','actor_id','authorization_context_id','scenario_id','run_id','repeat_id')):
                raise ValueError('delivery observation belongs to another context')
        return self


class DeliveryAdapter(Protocol):
    adapter_id: str
    adapter_version: str
    supported_surfaces: frozenset[Surface]

    def deliver(self, opportunity: PublicOpportunity, *, context: DeliveryContext,
                deadline_ns: int) -> DeliveryReceipt:
        """Delivery status is not an oracle verdict or successful attack label.

        Review must cover identity binding, surface reachability, network, reset,
        budget ceilings, feedback visibility and cancellation before integration.
        """
        ...


class UnavailableDelivery:
    adapter_id='unavailable'
    adapter_version='1'
    supported_surfaces=frozenset()

    def deliver(self,*args,**kwargs):
        raise NotImplementedError('PR-03 has no prompt/tool-output/document delivery adapter')
