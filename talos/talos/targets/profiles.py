"""PR-02 descriptions of the implemented fixtures, never trust approvals."""
from talos.profiles import TargetProfile
from talos.targets.store import POLICY_VERSION


def target_profile(domain,target_id,source_id,variant):
    string = {"type":"string"}
    array = {"type":"array","items":string}
    fields = {
        "lookup_employee":{"employee_id":string,"team":string},
        "approve_expense":{"expense_id":string,"status":string},
        "grant_access":{"employee_id":string,"resources":array},
        "notify_manager":{"queued_in":string},
        "search_documents":{"documents":array},
        "read_document":{"document_id":string,"content":string},
        "share_document":{"document_id":string,"readers":array},
        "set_editor":{"document_id":string,"editors":array},
    }
    code = f"talos/talos/targets/{'helpdesk' if domain.domain_id == 'it-helpdesk' else 'documents'}.py"
    tools,boundaries = [],[]
    for tool in domain.tools:
        tools.append(dict(name=tool.name,description=tool.description,input_schema=tool.arguments.model_json_schema(),
            output_schema={"type":"object","properties":fields[tool.name]},evidence_ids=["implementation"],
            effects=[{"effect":e,"evidence_ids":["implementation"]} for e in tool.effects],
            permissions=[{"permission":tool.permission,"boundary_ids":[tool.name],"evidence_ids":["implementation"]}],
            output_trust=[{"trust":tool.output_trust,"evidence_ids":["implementation"]}],audit_capability_ids=["audit","state"]))
        boundaries.append(dict(boundary_id=tool.name,description="Versioned synthetic rules enforced in hardened variant.",
            policy_id=domain.policy_id,policy_version=POLICY_VERSION,rule_id=tool.name,evidence_ids=["implementation"]))
    flows = [("lookup_employee","approve_expense"),("lookup_employee","grant_access")] if domain.domain_id == "it-helpdesk" else [
        ("search_documents","read_document"),("read_document","share_document")]
    return TargetProfile.model_validate(dict(target_id=target_id,domain=domain.domain_id,fixture_id=f"{domain.domain_id}.{variant}.v1",
        custody={"custodian_id":"repository-authored-synthetic-fixture","independence_claimed":False,"evidence_ids":["implementation"]},
        evidence=[dict(evidence_id="implementation",source_id="repository-fixture-source",reference=code,origin="operator_declaration",
            detail="Synthetic code contract; no independent validation or operational approval.")],
        tools=tools,authorization_boundaries=boundaries,
        audit_capabilities=[dict(capability_id=ident,source_id=source_id,kind=kind,can_observe_commit=True,
            can_attest_no_effect=True,action_digest_binding=True,description="Operator-only local store capability; explicit oracle trust still required.",
            evidence_ids=["implementation"]) for ident,kind in [("audit","audit"),("state","state_transition"),("reset","reset")]],
        possible_flows=[dict(flow_id=f"flow-{i}",source_tool=a,target_tool=b,description="Possible workflow, not observed execution.",
                             evidence_ids=["implementation"]) for i,(a,b) in enumerate(flows)],
        state_reset_description="Deterministic seeded business state; fresh instance identity and reset generation; invalid reset revokes evidence completeness.",
        authorized_test_objectives=["Synthetic offline regression controls only; not empirical study permission."],
        prohibited_effects=["No production IAM/payment/email/sharing; fixed local principals/inboxes only."],
        allowed_egress=["No network; synthetic principal/inbox state only."],privacy_policy_reference="docs/experimental/pr03_targets.md"))
