"""Policy replay.

Change a policy, then re-decide the entire history against the new rules and
diff the outcome: "this change would have blocked 34 previously-allowed queries
and unblocked 6."

This works because `policy.evaluate` is a pure function of (features, policies).
The ledger already stores the features, so replay never re-parses SQL and never
touches the underlying tables -- it is an analytical scan over the ledger, which
is exactly what the engine underneath is built for.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pyexasol

from .analyze import Features
from .policy import evaluate, load_policies


@dataclass
class ReplayDiff:
    replay_id: str
    total: int
    changed: int
    newly_blocked: int
    newly_allowed: int

    def summary(self) -> str:
        return (f"replayed {self.total} decisions: {self.newly_blocked} would now be "
                f"blocked, {self.newly_allowed} would now be allowed "
                f"({self.changed} changed in total)")


def _features_from_json(blob: str) -> Features:
    data = json.loads(blob)
    f = Features()
    for key, value in data.items():
        if hasattr(f, key):
            setattr(f, key, value)
    return f


def replay(conn: pyexasol.ExaConnection, principal: str,
           limit: int | None = None) -> ReplayDiff:
    policies = load_policies(conn, principal)
    replay_id = uuid.uuid4().hex

    sql = ("SELECT SEQ, FEATURES, DECISION, EST_ROWS FROM AIRLOCK.LEDGER "
           "WHERE FEATURES IS NOT NULL ORDER BY SEQ")
    if limit:
        sql += f" LIMIT {int(limit)}"

    rows = conn.execute(sql).fetchall()
    changed = newly_blocked = newly_allowed = 0
    batch = []

    for row in rows:
        old = row["DECISION"]
        features = _features_from_json(row["FEATURES"])
        est = int(row["EST_ROWS"]) if row["EST_ROWS"] is not None else None
        new_decision = evaluate(features, policies, affected_rows=est)
        new = new_decision.effect
        did_change = new != old
        if did_change:
            changed += 1
            if old == "ALLOW" and new != "ALLOW":
                newly_blocked += 1
            elif old != "ALLOW" and new == "ALLOW":
                newly_allowed += 1
        batch.append([replay_id, int(row["SEQ"]), old, new, did_change,
                      new_decision.reason_text[:4000]])

    if batch:
        conn.ext.insert_multi(
            ("AIRLOCK", "REPLAY_RESULT"), batch,
            columns=["REPLAY_ID", "SEQ", "OLD_DECISION", "NEW_DECISION",
                     "CHANGED", "NEW_REASON"],
        )

    return ReplayDiff(replay_id=replay_id, total=len(rows), changed=changed,
                      newly_blocked=newly_blocked, newly_allowed=newly_allowed)
