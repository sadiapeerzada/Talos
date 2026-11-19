"""Supplied usage receipt controls are not actual provider measurements."""
import pytest
from talos.readiness import ModelConfiguration,ProviderUsage
from talos.readiness.accounting import ProviderLedger
from talos.research.budget import BudgetStop
from talos.research.contracts import Limits,DIMENSIONS


def ledger():
    amounts={d:0 for d in DIMENSIONS};amounts.update(target_model_calls=2,input_tokens=20,output_tokens=20,cost_microunits=200,retries=2,elapsed_ms=2000)
    return ProviderLedger(Limits(amounts=amounts),ModelConfiguration(model_id='offline-receipt-test',revision='1',temperature=0,
        max_output_tokens=10,seed_support='unsupported'),currency='USD',price_schedule_sha256='a'*64)


def usage(**changes):
    raw=dict(request_id='request-one',model_id='offline-receipt-test',model_revision='1',input_tokens=5,output_tokens=5,retries=0,
        cost_microunits=50,currency='USD',price_schedule_sha256='a'*64,provider_receipt_sha256='b'*64)
    raw.update(changes);return ProviderUsage(**raw)


def reserve(value,request_id='request-one'):
    value.reserve(request_id,input_tokens=10,output_tokens=10,cost_microunits=100,retries=1,elapsed_ms=1000)


def test_reservation_actual_usage_and_no_execution_authority():
    value=ledger();reserve(value);value.settle(usage(),elapsed_ms=100)
    assert value.budget.snapshot()['used']['cost_microunits']==50
    assert value.budget.snapshot()['used']['input_tokens']==5
    with pytest.raises(PermissionError):value.invoke()
    with pytest.raises(ValueError):reserve(value)


@pytest.mark.parametrize('field,wrong',[('request_id','different'),('model_id','different'),('model_revision','different'),
    ('currency','EUR'),('price_schedule_sha256','0'*64)])
def test_mismatched_provider_receipt_stops_future_requests(field,wrong):
    value=ledger();reserve(value)
    with pytest.raises(BudgetStop):value.settle(usage(**{field:wrong}),elapsed_ms=100)
    assert value.budget.snapshot()['used']['cost_microunits'] is None
    with pytest.raises(BudgetStop):reserve(value,'next')


def test_missing_usage_never_becomes_zero_or_a_retry():
    value=ledger();reserve(value)
    with pytest.raises(BudgetStop):value.settle(None,elapsed_ms=100)
    assert value.budget.snapshot()['used']['input_tokens'] is None
    assert value.budget.snapshot()['known_usage_lower_bound']['target_model_calls']==1
    with pytest.raises(BudgetStop):reserve(value,'next')


@pytest.mark.parametrize('field,amount',[('cost_microunits',101),('input_tokens',11),('output_tokens',11),('retries',2)])
def test_excess_actual_consumption_halts(field,amount):
    value=ledger();reserve(value)
    with pytest.raises(BudgetStop):value.settle(usage(**{field:amount}),elapsed_ms=100)
    with pytest.raises(BudgetStop):reserve(value,'next')


def test_no_hidden_concurrent_reservation_or_unreserved_receipt():
    value=ledger()
    with pytest.raises(ValueError):value.settle(usage(),elapsed_ms=1)
    reserve(value)
    with pytest.raises(BudgetStop):reserve(value,'concurrent')
    value.settle(usage(),elapsed_ms=10)
    with pytest.raises(ValueError):value.settle(usage(),elapsed_ms=10)


def test_reused_provider_receipt_is_not_two_independent_measurements():
    value=ledger();reserve(value);value.settle(usage(),elapsed_ms=10);reserve(value,'request-two')
    with pytest.raises(BudgetStop):value.settle(usage(request_id='request-two'),elapsed_ms=10)
    assert value.budget.snapshot()['used']['cost_microunits'] is None
