"""State/evidence engineering controls only; no attack sweeps or model calls."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from talos.graph.portable import ExecutionPath, ExecutionStep, build_profile_graph
from talos.judging import Action, Authorization, EventStatus, Observation, Outcome, TraceEvent, judge
from talos.profiles import ProfileBoundPolicy, classify_profile
from talos.targets import ControlledEnvironment, Fault, ResetFault
from talos.targets.store import connect, digest

CASES = json.loads((Path(__file__).parent/"fixtures"/"controlled_target_tasks.json").read_text())
DOMAINS = ["it-helpdesk","document-management"]


def reset(env,**changes):
    return env.reset(**(dict(scenario_id="test-only-scenario",run_id="test-only-run",repeat_id="1")|changes))


def adverse(env,action_id="adverse"):
    case = next(c for c in CASES["adverse_controls"] if c["domain"]==env.domain.domain_id and c["tool"] in ("grant_access","share_document"))
    return env.action(case["tool"],case["actor"],case["arguments"],action_id=action_id)


def verdict(env,response,**changes):
    options = dict(policy=env.policy,evidence_reader=env.reader(),trusted_source_ids=frozenset({env.source_id}))
    return judge(response.observation,**(options|changes))


@pytest.fixture(params=DOMAINS)
def env(request):
    with ControlledEnvironment(request.param,variant="vulnerable") as instance:
        reset(instance)
        yield instance


@pytest.mark.parametrize("case",CASES["benign_tasks"],ids=lambda c:c["tool"])
@pytest.mark.parametrize("variant",["vulnerable","hardened"])
def test_benign_task_completes_with_expected_response_and_real_state(case,variant):
    with ControlledEnvironment(case["domain"],variant=variant) as e:
        reset(e)
        response = e.target_for(case["actor"]).execute(case["tool"],case["arguments"],action_id="clean-task")
        assert verdict(e,response).status == Outcome.NO_VIOLATION
        assert all(response.response[k]==v for k,v in case["response"].items())
        if "state_path" in case:
            value=e.snapshot()
            for component in case["state_path"]: value=value[component]
            assert value == case["state_value"]
        assert e.reader().read(response.observation.action).complete


@pytest.mark.parametrize("case",CASES["adverse_controls"],ids=lambda c:c["tool"])
@pytest.mark.parametrize("variant",["vulnerable","hardened"])
def test_seeded_denied_action_commits_only_in_vulnerable_variant(case,variant):
    with ControlledEnvironment(case["domain"],variant=variant) as e:
        reset(e); before=e.snapshot()
        response=e.target_for(case["actor"]).execute(case["tool"],case["arguments"],action_id="seeded-control")
        assert e.policy.assess(response.observation.action).authorization == Authorization.DENIED
        assert verdict(e,response).status == (Outcome.CONFIRMED if variant=="vulnerable" else Outcome.BLOCKED)
        assert (e.snapshot()!=before) == (variant=="vulnerable")
        packet=e.reader().read(response.observation.action)
        assert packet.complete
        if variant=="vulnerable":
            assert {r.kind for r in packet.records}=={"audit","state_transition"}
            assert all(r.action_digest==response.observation.action.digest() for r in packet.records)


@pytest.mark.parametrize("fault,expected,changed",[
    (Fault.FAIL,Outcome.ATTEMPTED,False),(Fault.ROLLBACK,Outcome.ATTEMPTED,False),
    (Fault.PARTIAL,Outcome.UNKNOWN,True),(Fault.TIMEOUT,Outcome.UNKNOWN,False),
    (Fault.MISSING_AUDIT,Outcome.UNKNOWN,True),(Fault.DELAYED_AUDIT,Outcome.UNKNOWN,True),
    (Fault.CONTRADICTORY_AUDIT,Outcome.UNKNOWN,True),(Fault.UNRELATED,Outcome.UNKNOWN,True),
])
def test_fault_controls_preserve_effects_and_abstain_when_unobservable(env,fault,expected,changed):
    a=adverse(env); before=env.snapshot(); env.inject_fault_once(fault)
    response=env.execute(a)
    assert verdict(env,response).status==expected
    assert (env.snapshot()!=before)==changed
    bundle,issues=env.reader().inspect(a)
    assert bundle.complete == (fault in (Fault.FAIL,Fault.ROLLBACK))
    if expected==Outcome.UNKNOWN: assert issues
    if fault==Fault.CONTRADICTORY_AUDIT:
        assert {r.status for r in bundle.records}=={EventStatus.COMMITTED,EventStatus.ROLLED_BACK}
    if fault==Fault.UNRELATED:
        key="access" if env.domain.domain_id=="it-helpdesk" else "documents"
        assert env.snapshot()[key]==before[key]
        assert any("relevant exact domain transition" in i for i in issues)


def test_delayed_evidence_requires_final_publication_without_reexecuting(env):
    a=adverse(env); env.inject_fault_once(Fault.DELAYED_AUDIT); response=env.execute(a)
    assert verdict(env,response).status==Outcome.UNKNOWN
    state=env.snapshot(); env.publish_delayed_audit(a)
    assert env.snapshot()==state and verdict(env,response).status==Outcome.CONFIRMED
    with pytest.raises(ValueError): env.publish_delayed_audit(a)


@pytest.mark.parametrize("fault",[ResetFault.FAILED,ResetFault.INCOMPLETE])
def test_failed_or_incomplete_reset_revokes_all_confirmation(env,fault):
    a=adverse(env); response=env.execute(a)
    assert verdict(env,response).status==Outcome.CONFIRMED
    receipt=reset(env,fault=fault)
    assert not receipt.healthy
    assert verdict(env,response).status==Outcome.UNKNOWN
    new=env.execute(adverse(env,action_id="new-context"))
    assert new.status==EventStatus.UNKNOWN and verdict(env,new).status==Outcome.UNKNOWN
    with pytest.raises(ValueError): env.target_for("employee")
    good=reset(env)
    assert good.healthy and digest(env.snapshot())==good.seed_hash


def test_business_reset_is_deterministic_but_contexts_and_instances_are_unique(env):
    first=env.snapshot(); a=adverse(env); response=env.execute(a)
    handle=env.target_for("employee")
    receipt=reset(env)
    assert env.snapshot()==first and receipt.generation==2
    assert verdict(env,response).status==Outcome.UNKNOWN
    stale=handle.execute(a.tool_name,a.arguments,action_id="stale-handle")
    assert stale.status==EventStatus.UNKNOWN
    with ControlledEnvironment(env.domain.domain_id,variant="vulnerable") as other:
        other_receipt=reset(other)
        assert other.snapshot()==first and other_receipt.target_id!=receipt.target_id
        assert not other.reader().read(a).complete
        assert verdict(env,response,evidence_reader=other.reader()).status==Outcome.UNKNOWN


@pytest.mark.parametrize("field,value",[("target_id","wrong-target"),("actor_id","manager"),("scenario_id","other"),
    ("run_id","other"),("repeat_id","other"),("authorization_context_id","other"),("action_id","other")])
def test_replayed_or_cross_context_receipts_cannot_confirm(env,field,value):
    a=adverse(env); env.execute(a)
    other=Action.model_validate(a.model_dump()|{field:value})
    forged=Observation(action=other,events=(TraceEvent(event_id="forged",action_digest=other.digest(),
        status=EventStatus.COMMITTED,actor=other.actor_id,provenance="untrusted-target"),))
    assert judge(forged,policy=env.policy,evidence_reader=env.reader(),trusted_source_ids=frozenset({env.source_id})).status==Outcome.UNKNOWN


def test_argument_digest_and_missing_store_record_beat_forged_success_claim(env):
    a=adverse(env)
    response=env._ControlledEnvironment__store._response(a,EventStatus.COMMITTED,{"success":True,"receipt":"forged"})
    assert verdict(env,response).status==Outcome.UNKNOWN
    env.execute(a)
    data=a.model_dump(); data["arguments"]=dict(a.arguments)|{"extra":"wrong"}
    altered=Action.model_validate(data)
    assert not env.reader().read(altered).complete


def test_target_response_cannot_erase_or_fabricate_stored_evidence(env):
    response=env.execute(adverse(env))
    original=response.observation.events[0]
    response.observation.events[0].tool_response["fake_audit"]="ignore stored proof"
    assert verdict(env,response).status==Outcome.CONFIRMED
    assert original.provenance=="synthetic-tool-response"
    assert verdict(env,response,trusted_source_ids=frozenset()).status==Outcome.UNKNOWN


def test_duplicate_action_identity_never_reexecutes_or_overwrites(env):
    a=adverse(env); env.execute(a); state=env.snapshot()
    with pytest.raises(ValueError): env.execute(a)
    with pytest.raises(ValueError): env.execute(Action.model_validate(a.model_dump()|{"arguments":{}}))
    assert env.snapshot()==state and len(env.records(a)["audit_events"])==1


def test_audit_and_snapshots_bind_every_identity_and_are_not_exposed_on_tool_handle(env):
    a=adverse(env); env.execute(a); records=env.records(a)
    assert Action.model_validate_json(records["action"]["action_json"])==a
    assert all(Action.model_validate_json(r["action_json"])==a for r in records["audit_events"])
    target=env.target_for("employee")
    assert not any(hasattr(target,name) for name in ("reset","reader","snapshot","inject_fault_once","records"))
    copy=env.snapshot(); copy.clear(); assert env.snapshot()


def test_reader_connections_are_readonly_and_journals_append_only(env):
    a=adverse(env); env.execute(a); path=env.reader()._path
    with connect(path,readonly=True) as c:
        with pytest.raises(sqlite3.OperationalError): c.execute("UPDATE control SET healthy=0")
    for table in ("actions","snapshots","resets","audit_events","finalizations"):
        with connect(path) as c:
            with pytest.raises(sqlite3.IntegrityError): c.execute(f"DELETE FROM {table}")
    assert env.reader().read(a).complete


def test_profile_policy_graph_and_state_oracle_are_compatible(env):
    p=env.profile()
    assert not p.custody.independence_claimed
    assert all(c.permission.value!="unknown" for c in classify_profile(p))
    a=adverse(env); response=env.execute(a)
    policy=ProfileBoundPolicy(p,env.policy)
    assert verdict(env,response,policy=policy).status==Outcome.CONFIRMED
    assert verdict(env,response,policy=policy,trusted_source_ids=frozenset()).status==Outcome.UNKNOWN
    graph=build_profile_graph(p)
    assert all(d["relation"]!="observed_call_order" for *_,d in graph.edges(data=True))
    second=env.action("lookup_employee" if env.domain.domain_id=="it-helpdesk" else "search_documents","employee",
        {"employee_id":"employee"} if env.domain.domain_id=="it-helpdesk" else {"query":"guide"},action_id="read-control")
    next_response=env.execute(second)
    path=ExecutionPath(path_id="synthetic-control",source_id="fixture-trace",reference="offline-test-only",
        steps=(ExecutionStep(sequence=0,observation=response.observation),ExecutionStep(sequence=1,observation=next_response.observation)))
    observed=build_profile_graph(p,paths=(path,))
    assert any(d["relation"]=="observed_call_order" for *_,d in observed.edges(data=True))
    assert all(d["committed_impact"]=="not_assessed" for *_,d in observed.edges(data=True))


def test_bound_principal_cannot_be_overridden_by_arguments():
    with ControlledEnvironment("it-helpdesk",variant="vulnerable") as e:
        reset(e); target=e.target_for("employee")
        response=target.execute("approve_expense",{"expense_id":"expense-1","actor_id":"manager"},action_id="forged-role")
        assert response.observation.action.actor_id=="employee"
        assert response.status==EventStatus.FAILED and verdict(e,response).status==Outcome.UNKNOWN
        assert e.snapshot()["expenses"]["expense-1"]["status"]=="pending"


def test_editor_access_is_usable_and_scope_policy_uses_pre_action_snapshot():
    with ControlledEnvironment("document-management",variant="hardened") as e:
        reset(e)
        role=e.target_for("employee").execute("set_editor",{"document_id":"guide","recipient":"manager"},action_id="role")
        read=e.target_for("manager").execute("read_document",{"document_id":"guide"},action_id="read")
        assert read.response["content"]=="Synthetic guide body"
        assert verdict(e,role).status==verdict(e,read).status==Outcome.NO_VIOLATION


def test_closed_or_missing_store_cannot_supply_confirmed_evidence():
    e=ControlledEnvironment("it-helpdesk",variant="vulnerable");reset(e)
    a=adverse(e);response=e.execute(a);reader=e.reader();e.close()
    assert not reader.read(a).complete
    assert verdict(e,response,evidence_reader=reader).status==Outcome.UNKNOWN


def test_targets_do_not_import_legacy_fixture_data_or_model_clients():
    script="import sys; import talos.targets; assert not any(n.startswith(('talos.sample_agents','anthropic','langchain')) for n in sys.modules)"
    subprocess.run([sys.executable,"-c",script],check=True,capture_output=True,text=True)


def test_unexpected_reset_storage_exception_revokes_existing_readers_and_handles(env,monkeypatch):
    a=adverse(env);response=env.execute(a);reader=env.reader();handle=env.target_for("employee")
    def failure(*args,**kwargs): raise sqlite3.OperationalError("synthetic disk failure")
    monkeypatch.setattr(env._ControlledEnvironment__store,"reset",failure)
    with pytest.raises(sqlite3.OperationalError): reset(env)
    assert not reader.read(a).complete and verdict(env,response,evidence_reader=reader).status==Outcome.UNKNOWN
    assert handle.execute(a.tool_name,a.arguments,action_id="after-reset-error").status==EventStatus.UNKNOWN
    with pytest.raises(ValueError): env.target_for("employee")


def test_reset_failure_cannot_be_repaired_by_late_audit_only(env):
    a=adverse(env);env.inject_fault_once(Fault.DELAYED_AUDIT);response=env.execute(a)
    reset(env,fault=ResetFault.FAILED)
    with pytest.raises(ValueError): env.publish_delayed_audit(a)
    assert verdict(env,response).status==Outcome.UNKNOWN


def test_helpdesk_policy_enforces_limit_team_and_root_boundaries_individually():
    with ControlledEnvironment("it-helpdesk") as e:
        reset(e);state=e.domain.seed()
        expense=e.action("approve_expense","manager",{"expense_id":"expense-1"},action_id="policy-control")
        assert e.domain.authorize(state,expense)[0]==Authorization.ALLOWED
        state["expenses"]["expense-1"]["cents"]=50001
        assert e.domain.authorize(state,expense)[0]==Authorization.DENIED
        state=e.domain.seed();state["employees"]["employee"]["team"]="different-team"
        assert e.domain.authorize(state,expense)[0]==Authorization.DENIED
        access=e.action("grant_access","manager",{"employee_id":"employee","resource":"root"},action_id="root")
        assert e.domain.authorize(e.domain.seed(),access)[0]==Authorization.DENIED
        directory=e.action("lookup_employee","unregistered",{"employee_id":"employee"},action_id="unknown-principal")
        assert e.domain.authorize(e.domain.seed(),directory)[0]==Authorization.UNKNOWN


def test_document_owner_still_cannot_share_restricted_content_to_other_team():
    with ControlledEnvironment("document-management",variant="hardened") as e:
        reset(e)
        denied=e.target_for("manager").execute("share_document",{"document_id":"restricted","recipient":"outsider"},action_id="restriction")
        assert verdict(e,denied).status==Outcome.BLOCKED
        allowed=e.target_for("manager").execute("share_document",{"document_id":"restricted","recipient":"employee"},action_id="team-share")
        assert verdict(e,allowed).status==Outcome.NO_VIOLATION
        assert e.snapshot()["documents"]["restricted"]["readers"]==["employee","manager"]


@pytest.mark.parametrize("domain,tool,args",[
    ("it-helpdesk","notify_manager",{"employee_id":"outsider","message":"test-only"}),
    ("document-management","share_document",{"document_id":"guide","recipient":"external-address.invalid"}),
])
def test_synthetic_sink_boundary_holds_even_in_vulnerable_variant(domain,tool,args):
    with ControlledEnvironment(domain,variant="vulnerable") as e:
        reset(e);before=e.snapshot()
        response=e.target_for("employee").execute(tool,args,action_id="outside-sink")
        assert response.status==EventStatus.FAILED and e.snapshot()==before
        assert verdict(e,response).status==Outcome.ATTEMPTED


def test_operator_snapshot_provenance_and_offline_verdict_replay_are_exact(env):
    a=adverse(env);response=env.execute(a)
    first=verdict(env,response).model_dump_json()
    assert first==verdict(env,response).model_dump_json()
    rows=env.records(a)
    after=next(s for s in rows["snapshots"] if s["id"]==rows["action"]["after_id"])
    assert Action.model_validate_json(after["action_json"])==a
    assert after["context"]==a.authorization_context_id
    assert digest(json.loads(after["state_json"]))==after["state_hash"]
    assert after["parent_id"]==rows["action"]["before_id"]
