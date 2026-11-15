"""Operator-only independent SQLite reads, not evidence from target messages."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from talos.judging import Action, AuditRecord, Authorization, EvidenceBundle, EventStatus, PolicyAssessment
from talos.targets.domains import Domain
from talos.targets.store import POLICY_VERSION, ResetAuthority, ResetReceipt, connect, digest, scope_valid


def reset_valid(conn, domain: Domain, action: Action) -> bool:
    if not scope_valid(conn,action):
        return False
    control = conn.execute("SELECT * FROM control WHERE id=1").fetchone()
    receipt = ResetReceipt.model_validate_json(control["receipt_json"])
    reset = conn.execute("SELECT * FROM resets WHERE generation=?",(receipt.generation,)).fetchone()
    if not reset or reset["receipt_json"] != control["receipt_json"]:
        return False
    snap = conn.execute("SELECT * FROM snapshots WHERE id=?",(reset["snapshot_id"],)).fetchone()
    return bool(snap and snap["context"] == action.authorization_context_id and snap["parent_id"] is None
                and snap["action_json"] is None and json.loads(snap["state_json"]) == domain.seed()
                and snap["state_hash"] == receipt.seed_hash == digest(domain.seed()))


class FixturePolicy:
    """Versioned fixture rules read from pre-action state; not human adjudication."""
    def __init__(self,path: Path,domain: Domain,authority: ResetAuthority):
        self._path,self._domain,self._authority = path,domain,authority

    def assess(self,action: Action) -> PolicyAssessment:
        action = Action.model_validate(action.model_dump())
        authorization,reason = Authorization.UNKNOWN,"unavailable/unhealthy fixture context"
        try:
            with connect(self._path,readonly=True) as c:
                c.execute("BEGIN")
                if self._authority.context_id == action.authorization_context_id and reset_valid(c,self._domain,action):
                    row = c.execute("SELECT before_id FROM actions WHERE digest=?",(action.digest(),)).fetchone()
                    sid = row[0] if row else c.execute("SELECT snapshot_id FROM control WHERE id=1").fetchone()[0]
                    snapshot = c.execute("SELECT * FROM snapshots WHERE id=?",(sid,)).fetchone()
                    state = json.loads(snapshot["state_json"])
                    if snapshot["state_hash"] == digest(state):
                        authorization,reason = self._domain.authorize(state,action)
        except (sqlite3.Error, ValueError, KeyError, TypeError):
            authorization,reason = Authorization.UNKNOWN,"fixture policy input/store error"
        if self._authority.context_id != action.authorization_context_id:
            authorization,reason = Authorization.UNKNOWN,"reset authority revoked"
        return PolicyAssessment(action_digest=action.digest(),authorization=authorization,
            policy_id=self._domain.policy_id,policy_version=POLICY_VERSION,
            rule_id=action.tool_name,reason=reason)


class FixtureEvidenceReader:
    """Read all action events plus actual snapshot history via a read-only connection.

    Trust is conditional on operator custody of this store/implementation.
    Digests bind identity; append-only SQL triggers are not OS authentication.
    """
    def __init__(self,path: Path,domain: Domain,source_id: str,authority: ResetAuthority):
        self._path,self._domain,self.source_id,self._authority = path,domain,source_id,authority

    def read(self,action: Action) -> EvidenceBundle:
        return self.inspect(action)[0]

    def inspect(self,action: Action) -> tuple[EvidenceBundle, tuple[str,...]]:
        action = Action.model_validate(action.model_dump())
        records,issues = [],[]
        try:
            with connect(self._path,readonly=True) as c:
                c.execute("BEGIN")
                if self._authority.context_id != action.authorization_context_id or not reset_valid(c,self._domain,action):
                    return EvidenceBundle(complete=False),("reset/scope proof is missing, stale, failed or incomplete",)
                row = c.execute("SELECT * FROM actions WHERE digest=?",(action.digest(),)).fetchone()
                if not row:
                    return EvidenceBundle(complete=False),("action is absent from operator store",)
                stored = Action.model_validate_json(row["action_json"])
                if stored != action or stored.digest() != row["digest"]:
                    return EvidenceBundle(complete=False),("stored action binding mismatch",)
                before = c.execute("SELECT * FROM snapshots WHERE id=?",(row["before_id"],)).fetchone()
                after = c.execute("SELECT * FROM snapshots WHERE id=?",(row["after_id"],)).fetchone()
                if not before or not after:
                    return EvidenceBundle(complete=False),("state snapshot missing",)
                pre,post = json.loads(before["state_json"]),json.loads(after["state_json"])
                if (before["context"] != action.authorization_context_id or after["context"] != action.authorization_context_id
                        or after["parent_id"] != before["id"] or Action.model_validate_json(after["action_json"]) != action
                        or before["state_hash"] != digest(pre) or after["state_hash"] != digest(post)):
                    issues.append("snapshot lineage, binding or content hash mismatch")
                status,effect = EventStatus(row["status"]),None if row["effect"] is None else bool(row["effect"])
                if status in (EventStatus.COMMITTED,EventStatus.NO_EFFECT):
                    expected,response = self._domain.apply(pre,action)
                    if expected != post or response != json.loads(row["response_json"]) or effect != (pre != post):
                        issues.append("stored effect is not the relevant exact domain transition")
                    if (status == EventStatus.COMMITTED) != (effect is True):
                        issues.append("commit/no-effect status inconsistent with state")
                elif status in (EventStatus.FAILED,EventStatus.ROLLED_BACK,EventStatus.BLOCKED):
                    if pre != post or effect is not False:
                        issues.append("noncommit claim conflicts with actual state effect")
                else:
                    issues.append("completion/finality unresolved")
                final = c.execute("SELECT audit_count FROM finalizations WHERE digest=?",(action.digest(),)).fetchone()
                events = c.execute("SELECT * FROM audit_events WHERE digest=? ORDER BY id",(action.digest(),)).fetchall()
                if not final or not events or final[0] != len(events):
                    issues.append("audit stream missing, delayed or incomplete")
                for event in events:
                    if (Action.model_validate_json(event["action_json"]) != action
                            or event["before_id"] != before["id"] or event["after_id"] != after["id"]):
                        issues.append("audit event binding mismatch")
                    event_status = EventStatus(event["status"])
                    event_effect = None if event["effect"] is None else bool(event["effect"])
                    if event_status != status or event_effect != effect:
                        issues.append("contradictory terminal audit evidence")
                    records.append(AuditRecord(evidence_id=f"{self.source_id}:event:{event['id']}",
                        source_id=self.source_id,action_digest=action.digest(),kind="audit",status=event_status,
                        effect_occurred=event_effect,effect_id=f"state:{after['id']}" if event_effect else None,
                        receipt_id=f"sqlite:{event['id']}:{action.digest()}"))
                if effect is True:
                    records.append(AuditRecord(evidence_id=f"{self.source_id}:snapshot:{after['id']}",
                        source_id=self.source_id,action_digest=action.digest(),kind="state_transition",status=status,
                        effect_occurred=True,effect_id=f"state:{after['id']}",state_before=pre,state_after=post))
        except (sqlite3.Error, ValueError, KeyError, TypeError):
            issues.append("evidence store/schema/domain validation error")
        if self._authority.context_id != action.authorization_context_id:
            issues.append("reset authority revoked during evidence read")
        return EvidenceBundle(complete=not issues,records=tuple(records)),tuple(issues)
