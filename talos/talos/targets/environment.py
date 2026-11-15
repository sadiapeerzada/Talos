"""Controller owns reset/audit/fault handles; exposed target only executes tools."""
from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal
from uuid import uuid4

from talos.judging import Action, EventStatus
from talos.targets.documents import DocumentDomain
from talos.targets.evidence import FixtureEvidenceReader, FixturePolicy
from talos.targets.helpdesk import HelpdeskDomain
from talos.targets.store import Fault, FixtureStore, ResetFault, ResetReceipt, ResetAuthority, connect


class ToolTarget:
    def __init__(self,make_action,execute):
        self.__make_action,self.__execute = make_action,execute

    def execute(self,tool_name: str,arguments: dict, *, action_id: str):
        return self.__execute(self.__make_action(tool_name,arguments,action_id))


class ControlledEnvironment:
    """Local tool fixture, not an LLM agent, independent target or OS sandbox."""
    def __init__(self,domain: Literal["it-helpdesk","document-management"], *, variant="hardened"):
        if variant not in ("vulnerable","hardened"):
            raise ValueError("variant must be vulnerable or hardened")
        domains = {"it-helpdesk":HelpdeskDomain,"document-management":DocumentDomain}
        if domain not in domains:
            raise ValueError("unknown domain")
        self.domain,self.variant = domains[domain](),variant
        self.target_id = f"synthetic:{domain}:{uuid4().hex}"
        self.source_id = f"{self.target_id}:operator-store"
        self.__directory = TemporaryDirectory(prefix="talos-synthetic-")
        self.__path = (Path(self.__directory.name)/"state.sqlite").resolve()
        self.__store = FixtureStore(self.__path,self.domain,self.target_id,variant)
        self.__authority = ResetAuthority()
        self.policy = FixturePolicy(self.__path,self.domain,self.__authority)
        self.__receipt = None

    def __enter__(self):
        return self

    def __exit__(self,*exc):
        self.close()

    def close(self):
        self.__authority.context_id = None
        self.__directory.cleanup()

    def reset(self, *, scenario_id: str, run_id: str, repeat_id: str, fault=ResetFault.NONE) -> ResetReceipt:
        self.__authority.context_id = None
        self.__store.fault = Fault.NONE
        self.__receipt = self.__store.reset(scenario_id,run_id,repeat_id,fault)
        self.__authority.context_id = self.__receipt.authorization_context_id if self.__receipt.healthy else None
        return self.__receipt

    def action(self,tool_name: str,actor_id: str,arguments: dict, *, action_id: str) -> Action:
        if self.__receipt is None:
            raise ValueError("reset required before building an action")
        receipt = self.__receipt.model_dump()
        return Action(**{name:receipt[name] for name in ("target_id","scenario_id","run_id","repeat_id","authorization_context_id")},
            tool_name=tool_name,actor_id=actor_id,arguments=arguments,action_id=action_id)

    def execute(self,action: Action):
        """Operator harness entry; untrusted tool callers must use target_for()."""
        if self.__authority.context_id != action.authorization_context_id:
            return self.__store._response(action,EventStatus.UNKNOWN,{"error":"reset authority is unavailable or revoked"})
        return self.__store.execute(action)

    def target_for(self,actor_id: str) -> ToolTarget:
        """Bind identity/reset context out-of-band, never from tool arguments."""
        if (self.__receipt is None or not self.__receipt.healthy
                or self.__authority.context_id != self.__receipt.authorization_context_id):
            raise ValueError("healthy reset required before binding a target handle")
        principals = self.domain.seed().get("employees",self.domain.seed().get("principals",{}))
        if actor_id not in principals:
            raise ValueError("unknown synthetic principal")
        receipt = self.__receipt.model_dump()
        def make_action(tool,args,action_id):
            return Action(**{name:receipt[name] for name in ("target_id","scenario_id","run_id","repeat_id","authorization_context_id")},
                          actor_id=actor_id,tool_name=tool,arguments=args,action_id=action_id)
        return ToolTarget(make_action,self.execute)

    def reader(self) -> FixtureEvidenceReader:
        return FixtureEvidenceReader(self.__path,self.domain,self.source_id,self.__authority)

    def snapshot(self) -> dict:
        with connect(self.__path,readonly=True) as c:
            row = c.execute("SELECT s.state_json FROM snapshots s JOIN control c ON c.snapshot_id=s.id WHERE c.id=1").fetchone()
            return json.loads(row[0]) if row else {}

    def inject_fault_once(self,fault: Fault):
        self.__store.fault = Fault(fault)

    def publish_delayed_audit(self,action: Action):
        if self.__authority.context_id != action.authorization_context_id:
            raise ValueError("reset authority is revoked")
        self.__store.publish_delayed_audit(action)

    def records(self,action: Action) -> dict:
        """Operator-only complete stored provenance; never part of tool responses."""
        with connect(self.__path,readonly=True) as c:
            row = c.execute("SELECT * FROM actions WHERE digest=?",(action.digest(),)).fetchone()
            events = c.execute("SELECT * FROM audit_events WHERE digest=? ORDER BY id",(action.digest(),)).fetchall()
            snapshots = [] if not row else c.execute("SELECT * FROM snapshots WHERE id IN (?,?) ORDER BY id",
                                                                    (row["before_id"],row["after_id"])).fetchall()
            return {"action":dict(row) if row else None,"audit_events":[dict(e) for e in events],
                    "snapshots":[dict(s) for s in snapshots]}

    def profile(self):
        from talos.targets.profiles import target_profile
        return target_profile(self.domain,self.target_id,self.source_id,self.variant)
