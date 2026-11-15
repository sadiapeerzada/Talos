"""Isolated synthetic SQLite state and append-only action/audit/snapshot journals."""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Literal

from pydantic import BaseModel, ConfigDict
from talos.judging import Action, Authorization, EventStatus, Observation, TraceEvent
from talos.targets.domains import Domain


POLICY_VERSION = "1.0"


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


@contextmanager
def connect(path: Path, *, readonly=False):
    conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) if readonly else sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    if readonly:
        conn.execute("PRAGMA query_only=ON")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


@dataclass
class ResetAuthority:
    """Operator-owned fail-closed fence, including failed SQLite reset attempts."""
    context_id: str | None = None


class Fault(str, Enum):
    NONE = "none"
    FAIL = "failed_tool"
    ROLLBACK = "rollback_before_commit"
    PARTIAL = "partial_commit"
    UNRELATED = "unrelated_state_change"
    TIMEOUT = "timeout"
    DELAYED_AUDIT = "delayed_audit"
    MISSING_AUDIT = "missing_audit"
    CONTRADICTORY_AUDIT = "contradictory_audit"


class ResetFault(str, Enum):
    NONE = "none"
    FAILED = "failed_reset"
    INCOMPLETE = "incomplete_reset"


class ResetReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    target_id: str
    scenario_id: str
    run_id: str
    repeat_id: str
    authorization_context_id: str
    generation: int
    seed_hash: str
    healthy: bool


class ToolResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    observation: Observation
    response: dict
    status: EventStatus


def scope_valid(conn, action: Action) -> bool:
    row = conn.execute("SELECT * FROM control WHERE id=1").fetchone()
    if not row or not row["healthy"]:
        return False
    receipt = ResetReceipt.model_validate_json(row["receipt_json"])
    return receipt.healthy and all(getattr(receipt, name) == getattr(action, name) for name in
        ("target_id", "scenario_id", "run_id", "repeat_id", "authorization_context_id"))


class FixtureStore:
    def __init__(self, path: Path, domain: Domain, target_id: str, variant: Literal["vulnerable", "hardened"]):
        self.path, self.domain, self.target_id, self.variant = path, domain, target_id, variant
        self.fault = Fault.NONE
        with connect(path) as c:
            c.executescript('''
                CREATE TABLE snapshots(id INTEGER PRIMARY KEY, context TEXT NOT NULL, action_json TEXT,
                    parent_id INTEGER REFERENCES snapshots(id), state_json TEXT NOT NULL, state_hash TEXT NOT NULL);
                CREATE TABLE resets(generation INTEGER PRIMARY KEY, receipt_json TEXT NOT NULL,
                    snapshot_id INTEGER REFERENCES snapshots(id));
                CREATE TABLE control(id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL,
                    healthy INTEGER NOT NULL, receipt_json TEXT NOT NULL, snapshot_id INTEGER REFERENCES snapshots(id));
                CREATE TABLE actions(digest TEXT PRIMARY KEY, context TEXT NOT NULL, action_id TEXT NOT NULL,
                    action_json TEXT NOT NULL, before_id INTEGER NOT NULL REFERENCES snapshots(id),
                    after_id INTEGER NOT NULL REFERENCES snapshots(id), status TEXT NOT NULL,
                    effect INTEGER, response_json TEXT NOT NULL, UNIQUE(context,action_id));
                CREATE TABLE audit_events(id INTEGER PRIMARY KEY, digest TEXT NOT NULL REFERENCES actions(digest),
                    action_json TEXT NOT NULL, status TEXT NOT NULL, effect INTEGER,
                    before_id INTEGER NOT NULL REFERENCES snapshots(id), after_id INTEGER NOT NULL REFERENCES snapshots(id));
                CREATE TABLE finalizations(digest TEXT PRIMARY KEY REFERENCES actions(digest), audit_count INTEGER NOT NULL);
            ''')
            for table in ("snapshots", "resets", "actions", "audit_events", "finalizations"):
                for operation in ("UPDATE", "DELETE"):
                    c.execute(f"CREATE TRIGGER no_{operation.lower()}_{table} BEFORE {operation} ON {table} "
                              "BEGIN SELECT RAISE(ABORT,'fixture journal is append-only'); END")

    def reset(self, scenario_id: str, run_id: str, repeat_id: str, fault=ResetFault.NONE) -> ResetReceipt:
        if not all(isinstance(v, str) and v.strip() for v in (scenario_id,run_id,repeat_id)):
            raise ValueError("nonempty scenario/run/repeat required")
        fault = ResetFault(fault)
        with connect(self.path) as c:
            c.execute("BEGIN IMMEDIATE")
            old = c.execute("SELECT generation,snapshot_id FROM control WHERE id=1").fetchone()
            generation = old["generation"]+1 if old else 1
            receipt = ResetReceipt(target_id=self.target_id, scenario_id=scenario_id, run_id=run_id,
                repeat_id=repeat_id, authorization_context_id=f"{self.target_id}/reset/{generation}",
                generation=generation, seed_hash=digest(self.domain.seed()), healthy=fault == ResetFault.NONE)
            if fault == ResetFault.FAILED:
                snapshot_id = old["snapshot_id"] if old else None
            else:
                state = self.domain.seed()
                if fault == ResetFault.INCOMPLETE:
                    state["reset_incomplete"] = True
                snapshot_id = c.execute("INSERT INTO snapshots(context,state_json,state_hash) VALUES(?,?,?)",
                    (receipt.authorization_context_id,canonical(state),digest(state))).lastrowid
            c.execute("INSERT INTO resets VALUES(?,?,?)",(generation,receipt.model_dump_json(),snapshot_id))
            c.execute("INSERT OR REPLACE INTO control VALUES(1,?,?,?,?)",
                      (generation,int(receipt.healthy),receipt.model_dump_json(),snapshot_id))
            return receipt

    def execute(self, action: Action) -> ToolResponse:
        action = Action.model_validate(action.model_dump())
        fault, self.fault = self.fault, Fault.NONE
        with connect(self.path) as c:
            c.execute("BEGIN IMMEDIATE")
            if not scope_valid(c, action):
                return self._response(action, EventStatus.UNKNOWN, {"error":"invalid or unhealthy reset context"})
            if c.execute("SELECT 1 FROM actions WHERE context=? AND action_id=?",
                         (action.authorization_context_id,action.action_id)).fetchone():
                raise ValueError("action ID already used in this reset context")
            before_id = c.execute("SELECT snapshot_id FROM control WHERE id=1").fetchone()[0]
            before = json.loads(c.execute("SELECT state_json FROM snapshots WHERE id=?",(before_id,)).fetchone()[0])
            after, result, status, effect = deepcopy(before), {}, EventStatus.UNKNOWN, None
            try:
                authorization,_ = self.domain.authorize(before,action)
                if authorization == Authorization.UNKNOWN:
                    result = {"error":"unresolved fixture authorization"}
                elif self.variant == "hardened" and authorization == Authorization.DENIED:
                    status,effect,result = EventStatus.BLOCKED,False,{"blocked":True}
                elif fault == Fault.TIMEOUT:
                    result = {"error":"injected timeout; completion unresolved"}
                elif fault == Fault.FAIL:
                    status,effect,result = EventStatus.FAILED,False,{"error":"injected failed tool"}
                else:
                    after,result = self.domain.apply(before,action)
                    if fault == Fault.ROLLBACK:
                        # Write to SQLite within an actual savepoint, then undo it.
                        c.execute("SAVEPOINT fixture_tool")
                        sid = self._snapshot(c,action,before_id,after)
                        c.execute("UPDATE control SET snapshot_id=? WHERE id=1",(sid,))
                        c.execute("ROLLBACK TO fixture_tool")
                        c.execute("RELEASE fixture_tool")
                        after,result,status,effect = deepcopy(before),{"rolled_back":True},EventStatus.ROLLED_BACK,False
                    elif fault == Fault.PARTIAL:
                        partial = deepcopy(before)
                        changed = [key for key in after if after[key] != before.get(key)]
                        if changed:
                            partial[changed[0]] = deepcopy(after[changed[0]])
                        after,result,status,effect = partial,{"error":"partial completion; finality unresolved"},EventStatus.FAILED,(partial != before)
                    else:
                        if fault == Fault.UNRELATED:
                            after = deepcopy(before)
                            after["unrelated_marker"] = action.digest()
                        effect = after != before
                        status = EventStatus.COMMITTED if effect else EventStatus.NO_EFFECT
            except (ValueError,KeyError,TypeError):
                after,result,status,effect = deepcopy(before),{"error":"fixture validation/tool error"},EventStatus.FAILED,False
            after_id = self._snapshot(c,action,before_id,after)
            c.execute("UPDATE control SET snapshot_id=? WHERE id=1",(after_id,))
            c.execute("INSERT INTO actions VALUES(?,?,?,?,?,?,?,?,?)",(action.digest(),action.authorization_context_id,
                action.action_id,action.model_dump_json(),before_id,after_id,status.value,
                None if effect is None else int(effect),canonical(result)))
            if fault not in (Fault.MISSING_AUDIT,Fault.DELAYED_AUDIT):
                self._audit(c,action,status,effect,before_id,after_id)
                if fault == Fault.CONTRADICTORY_AUDIT:
                    self._audit(c,action,EventStatus.ROLLED_BACK,False,before_id,after_id)
                if fault not in (Fault.TIMEOUT,Fault.PARTIAL) and status != EventStatus.UNKNOWN:
                    c.execute("INSERT INTO finalizations VALUES(?,?)",(action.digest(),2 if fault == Fault.CONTRADICTORY_AUDIT else 1))
            return self._response(action,status,result)

    def _snapshot(self,c,action,parent,state):
        return c.execute("INSERT INTO snapshots(context,action_json,parent_id,state_json,state_hash) VALUES(?,?,?,?,?)",
            (action.authorization_context_id,action.model_dump_json(),parent,canonical(state),digest(state))).lastrowid

    @staticmethod
    def _audit(c,action,status,effect,before_id,after_id):
        c.execute("INSERT INTO audit_events(digest,action_json,status,effect,before_id,after_id) VALUES(?,?,?,?,?,?)",
            (action.digest(),action.model_dump_json(),status.value,None if effect is None else int(effect),before_id,after_id))

    @staticmethod
    def _response(action,status,result):
        event = TraceEvent(event_id=f"trace:{action.digest()}",action_digest=action.digest(),
                           status=status,actor=action.actor_id,provenance="synthetic-tool-response",tool_response=result)
        return ToolResponse(observation=Observation(action=action,events=(event,)),response=result,status=status)

    def publish_delayed_audit(self, action: Action):
        with connect(self.path) as c:
            c.execute("BEGIN IMMEDIATE")
            if not scope_valid(c,action):
                raise ValueError("unhealthy/stale context")
            row = c.execute("SELECT * FROM actions WHERE digest=?",(action.digest(),)).fetchone()
            if not row or row["status"] not in ("COMMITTED","NO_EFFECT"):
                raise ValueError("no completed action to settle")
            if c.execute("SELECT 1 FROM audit_events WHERE digest=?",(action.digest(),)).fetchone():
                raise ValueError("audit already published")
            self._audit(c,action,EventStatus(row["status"]),bool(row["effect"]),row["before_id"],row["after_id"])
            c.execute("INSERT INTO finalizations VALUES(?,1)",(action.digest(),))
