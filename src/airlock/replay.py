"""Policy replay.

Change a policy, then re-decide the entire history against the new rules and
diff the outcome: "this change would have blocked 34 previously-allowed queries
and unblocked 6."

This works because `policy.evaluate` is a pure function of (features, policies,
approval).
The ledger already stores the features and the measurements -- the blast radius,
the smallest group, and the worst taint score -- so replay never re-parses SQL
and never touches the underlying tables. It is an analytical scan over the ledger, which is exactly
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
from .policy import evaluate, load_policies, validate_new_rule


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
          disable: set[str] | None = None, add: list[dict] | None = None) -> list[dict]:
    """Build a hypothetical policy set. The POLICY table is left untouched.

    `add` previews rules that do not exist yet -- policy.add_rule()'s keyword
    shape (name, rule_kind, effect, target_schema, ...), one dict per rule.
    Each is validated with the exact validate_new_rule() add_rule() itself
    calls, so a rule that previews cleanly here is guaranteed to also insert
    cleanly through the rules desk, and a rule rejected here would be rejected
    there too -- one representation, not two designs that can quietly drift
    apart. Whether a name collides with an existing rule is the caller's
    question, not this function's: amend() stays a pure build of the list, the
    same way it always has for thresholds and disable.

    Each new rule gets a negative POLICY_ID (-1, -2, ... in the order given).
    Real rows are always positive, and evaluate() already uses POLICY_ID 0 for
    a structural denial that names no policy row -- a negative id cannot be
    mistaken for either.
    """
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

    for i, new_rule in enumerate(add or [], start=1):
        rule_kind = new_rule["rule_kind"]
        effect = new_rule["effect"]
        target_schema = new_rule.get("target_schema")
        target_column = new_rule.get("target_column")
        threshold = new_rule.get("threshold")
        validate_new_rule(rule_kind, effect, target_schema, target_column, threshold)
        amended.append({
            "POLICY_ID": -i, "NAME": new_rule["name"], "VERSION": 1, "IS_ENABLED": True,
            "RULE_KIND": rule_kind, "EFFECT": effect,
            "TARGET_SCHEMA": target_schema, "TARGET_TABLE": new_rule.get("target_table"),
            "TARGET_COLUMN": target_column, "PRINCIPAL": new_rule.get("principal"),
            "THRESHOLD": threshold, "NOTE": new_rule.get("note"),
        })
    return amended


def check_new_rule_names(known: set[str], add: list[dict]) -> None:
    """Reject an `add` whose NAME already exists or repeats within the list.

    Ambiguous otherwise: a name matching an existing rule could mean "amend
    it" (that's what `thresholds`/`disable` already do) or "add a second rule
    under the same name". amend() stays a pure data transform; this is what
    both callers -- the CLI and the console -- run before calling it.
    """
    seen: set[str] = set()
    for rule in add:
        name = (rule.get("name") or "").lower()
        if name in known:
            raise ValueError(f"a policy named {rule.get('name')!r} already exists; "
                             f"use --set/disable to amend it instead")
        if name in seen:
            raise ValueError(f"add contains {rule.get('name')!r} twice")
        seen.add(name)


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

    # The approval is the third input to the decision, alongside the features
    # and the rules, and an entry that only came back ALLOW because a human
    # released it must be re-decided as released. Without the join every
    # approved write in the history reads as "would now be blocked" under any
    # amendment at all -- the answer to a question nobody asked.
    sql = ("SELECT l.SEQ, l.FEATURES, l.DECISION, l.EST_ROWS, l.MIN_GROUP, "
           "l.TAINT_MAX, a.APPROVAL_ID "
           "FROM AIRLOCK.LEDGER l "
           "LEFT JOIN AIRLOCK.APPROVAL a "
           "  ON a.RESULT_SEQ = l.SEQ AND a.APPROVAL_STATE = 'APPROVED' "
           "WHERE l.FEATURES IS NOT NULL ORDER BY l.SEQ")
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
        tnt = float(row["TAINT_MAX"]) if row["TAINT_MAX"] is not None else None
        new_decision = evaluate(features, policies, affected_rows=est, min_group=grp,
                                taint_max=tnt,
                                approved=row.get("APPROVAL_ID") is not None)
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
    parser.add_argument("--add-json", dest="add_json", metavar="JSON", action="append",
                        default=[], help="preview a rule that does not exist yet -- "
                                         "JSON matching policy.add_rule()'s fields, e.g. "
                                         '--add-json \'{"name":"x","rule_kind":"TAINT_BLOCK",'
                                         '"effect":"DENY","threshold":0.5}\'')
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
    add_rules: list[dict] = []
    for blob in args.add_json:
        try:
            add_rules.append(json.loads(blob))
        except json.JSONDecodeError as exc:
            parser.error(f"--add-json is not valid JSON: {exc}")

    current = load_policies(conn, args.principal)
    known = {(p["NAME"] or "").lower() for p in current}
    for name in list(thresholds) + list(args.disable):
        if name.lower() not in known:
            parser.error(f"no such policy: {name!r}. known: {sorted(known)}")

    try:
        check_new_rule_names(known, add_rules)
        amended = amend(current, thresholds=thresholds, disable=set(args.disable),
                        add=add_rules)
    except (ValueError, KeyError) as exc:
        parser.error(str(exc))

    print("=" * 78)
    print("Policy replay -- what-if, nothing is written to AIRLOCK.POLICY")
    print("-" * 78)
    for name, value in thresholds.items():
        before = next(p["THRESHOLD"] for p in current if p["NAME"].lower() == name.lower())
        print(f"  {name}: {before} -> {value:g}")
    for name in args.disable:
        print(f"  {name}: disabled")
    for rule in add_rules:
        print(f"  + {rule['name']} ({rule['rule_kind']}, {rule['effect']})")
    if not thresholds and not args.disable and not add_rules:
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
