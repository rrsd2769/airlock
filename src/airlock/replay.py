"""Policy replay.

Change a policy, then re-decide the entire history against the new rules and
diff the outcome: "this change would have blocked 34 previously-allowed queries
and unblocked 6."

This works because `policy.evaluate` is a pure function of (features, policies).
The ledger already stores the features and the measurements -- the blast radius
and the smallest group -- so replay never re-parses SQL and never touches the
underlying tables. It is an analytical scan over the ledger, which is exactly
what the engine underneath is built for.

Replay is a *what-if*: the amended policy set is built in memory and the real
AIRLOCK.POLICY table is never written to. You can ask what a rule change would
have cost before you inherit the consequences of making it.
"""
from __future__ import annotations

import argparse
import json
import uuid
from dataclasses import dataclass, field

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
    # (seq, old, new, reason) for the entries whose outcome moved.
    examples: list[tuple[int, str, str, str]] = field(default_factory=list)

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


def amend(policies: list[dict], *, thresholds: dict[str, float] | None = None,
          disable: set[str] | None = None) -> list[dict]:
    """Build a hypothetical policy set. The POLICY table is left untouched."""
    thresholds = {k.lower(): v for k, v in (thresholds or {}).items()}
    disable = {d.lower() for d in (disable or set())}
    amended = []
    for p in policies:
        name = (p["NAME"] or "").lower()
        if name in disable:
            continue
        row = dict(p)
        if name in thresholds:
            row["THRESHOLD"] = thresholds[name]
        amended.append(row)
    return amended


def replay(conn: pyexasol.ExaConnection, principal: str,
           policies: list[dict] | None = None,
           limit: int | None = None,
           persist: bool = True) -> ReplayDiff:
    """Re-decide every recorded statement against `policies`.

    `policies` defaults to the rule set currently in force, which answers a
    different and duller question ("does the engine still agree with itself?").
    Pass an amended set from `amend()` to ask what a change would have done.
    """
    if policies is None:
        policies = load_policies(conn, principal)
    replay_id = uuid.uuid4().hex

    sql = ("SELECT SEQ, FEATURES, DECISION, EST_ROWS, MIN_GROUP FROM AIRLOCK.LEDGER "
           "WHERE FEATURES IS NOT NULL ORDER BY SEQ")
    if limit:
        sql += f" LIMIT {int(limit)}"

    rows = conn.execute(sql).fetchall()
    changed = newly_blocked = newly_allowed = 0
    examples: list[tuple[int, str, str, str]] = []
    batch = []

    for row in rows:
        old = row["DECISION"]
        features = _features_from_json(row["FEATURES"])
        est = int(row["EST_ROWS"]) if row["EST_ROWS"] is not None else None
        grp = int(row["MIN_GROUP"]) if row["MIN_GROUP"] is not None else None
        new_decision = evaluate(features, policies, affected_rows=est, min_group=grp)
        new = new_decision.effect
        did_change = new != old
        if did_change:
            changed += 1
            if old == "ALLOW" and new != "ALLOW":
                newly_blocked += 1
            elif old != "ALLOW" and new == "ALLOW":
                newly_allowed += 1
            if len(examples) < 5:
                examples.append((int(row["SEQ"]), old, new, new_decision.reason_text))
        batch.append([replay_id, int(row["SEQ"]), old, new, did_change,
                      new_decision.reason_text[:4000]])

    if batch and persist:
        conn.ext.insert_multi(
            ("AIRLOCK", "REPLAY_RESULT"), batch,
            columns=["REPLAY_ID", "SEQ", "OLD_DECISION", "NEW_DECISION",
                     "CHANGED", "NEW_REASON"],
        )

    return ReplayDiff(replay_id=replay_id, total=len(rows), changed=changed,
                      newly_blocked=newly_blocked, newly_allowed=newly_allowed,
                      examples=examples)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m airlock.replay",
        description="Re-decide the whole ledger against an amended policy set.")
    parser.add_argument("--set", dest="sets", metavar="NAME=VALUE", action="append",
                        default=[], help="override a policy threshold, e.g. "
                                         "--set acctbal-k-anon=100")
    parser.add_argument("--disable", metavar="NAME", action="append", default=[],
                        help="drop a policy from the hypothetical rule set")
    parser.add_argument("--principal", default="demo-agent")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--no-persist", action="store_true",
                        help="do not write to AIRLOCK.REPLAY_RESULT")
    args = parser.parse_args()

    thresholds: dict[str, float] = {}
    for item in args.sets:
        if "=" not in item:
            parser.error(f"--set expects NAME=VALUE, got {item!r}")
        name, _, value = item.partition("=")
        thresholds[name.strip()] = float(value)

    from .db import connect
    conn = connect()
    current = load_policies(conn, args.principal)
    known = {(p["NAME"] or "").lower() for p in current}
    for name in list(thresholds) + list(args.disable):
        if name.lower() not in known:
            parser.error(f"no such policy: {name!r}. known: {sorted(known)}")

    amended = amend(current, thresholds=thresholds, disable=set(args.disable))

    print("=" * 78)
    print("Policy replay -- what-if, nothing is written to AIRLOCK.POLICY")
    print("-" * 78)
    for name, value in thresholds.items():
        before = next(p["THRESHOLD"] for p in current if p["NAME"].lower() == name.lower())
        print(f"  {name}: {before} -> {value:g}")
    for name in args.disable:
        print(f"  {name}: disabled")
    if not thresholds and not args.disable:
        print("  (no amendment -- replaying against the rules as they stand)")

    diff = replay(conn, args.principal, policies=amended, limit=args.limit,
                  persist=not args.no_persist)

    print("-" * 78)
    print(f"  {diff.summary()}")
    if diff.examples:
        print("\n  examples:")
        for seq, old, new, reason in diff.examples:
            print(f"    #{seq}: {old} -> {new}")
            print(f"        {reason}")
    if not args.no_persist:
        print(f"\n  written to AIRLOCK.REPLAY_RESULT as replay {diff.replay_id}")
    print("=" * 78)


if __name__ == "__main__":
    main()
