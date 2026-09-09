"""Replay is a what-if, so the amended rule set must never be the real one.

These run without a database: `amend` is list manipulation and `evaluate` is
pure, which together are the whole of replay's decision path.
"""
import pytest

from airlock.analyze import analyze
from airlock.policy import ALLOW, DENY, REQUIRE_APPROVAL, evaluate
from airlock.replay import _features_from_json, amend, check_new_rule_names, replay


def policy(**kw):
    base = dict(POLICY_ID=1, NAME="p", RULE_KIND="COLUMN_ACCESS", EFFECT=DENY,
                TARGET_SCHEMA=None, TARGET_TABLE=None, TARGET_COLUMN=None,
                PRINCIPAL=None, THRESHOLD=None, NOTE=None)
    base.update(kw)
    return base


def new_rule(**kw):
    base = {"name": "new", "rule_kind": "TAINT_BLOCK", "effect": DENY, "threshold": 0.7}
    base.update(kw)
    return base


def test_amend_does_not_mutate_the_live_policy_set():
    live = [policy(NAME="acctbal-k-anon", THRESHOLD=20)]
    amended = amend(live, thresholds={"acctbal-k-anon": 100})
    assert amended[0]["THRESHOLD"] == 100
    assert live[0]["THRESHOLD"] == 20, "the rules in force must be left alone"


def test_amend_matches_policy_names_case_insensitively():
    live = [policy(NAME="Acctbal-K-Anon", THRESHOLD=20)]
    assert amend(live, thresholds={"acctbal-k-anon": 100})[0]["THRESHOLD"] == 100


def test_amend_can_drop_a_rule_entirely():
    live = [policy(NAME="keep"), policy(NAME="drop", POLICY_ID=2)]
    assert [p["NAME"] for p in amend(live, disable={"drop"})] == ["keep"]


# --------------------------------------------------------------------------
# previewing a rule that does not exist yet
# --------------------------------------------------------------------------

def test_amend_can_preview_a_rule_that_does_not_exist_yet():
    live = [policy(NAME="existing")]
    amended = amend(live, add=[new_rule(name="fresh")])
    assert [p["NAME"] for p in amended] == ["existing", "fresh"]


def test_a_previewed_rule_gets_a_negative_id_never_a_real_one():
    """Real POLICY_IDs are always positive, and evaluate() already uses 0 for
    a structural denial that names no policy row (policy.py)."""
    amended = amend([], add=[new_rule(), new_rule(name="second")])
    assert [p["POLICY_ID"] for p in amended] == [-1, -2]


def test_a_previewed_rule_actually_participates_in_a_decision():
    """The whole point: a rule that only exists in the preview is still
    consulted by evaluate(), the same as one already in AIRLOCK.POLICY."""
    amended = amend([], add=[new_rule(name="new-taint-cap", threshold=0.5)])
    d = evaluate(analyze("SELECT S_COMMENT FROM TPCH.SUPPLIER"), amended, taint_max=0.6)
    assert d.effect == DENY
    assert -1 in d.matched


def test_amend_rejects_a_rule_that_could_never_match():
    """The exact validation add_rule() runs -- a rule that fails to preview
    would also fail to insert, and vice versa."""
    with pytest.raises(ValueError, match="THRESHOLD"):
        amend([], add=[new_rule(rule_kind="BLAST_RADIUS", threshold=None)])


def test_check_new_rule_names_rejects_a_collision_with_an_existing_rule():
    with pytest.raises(ValueError, match="already exists"):
        check_new_rule_names({"acctbal-k-anon"}, [new_rule(name="acctbal-k-anon")])


def test_check_new_rule_names_rejects_a_collision_within_add_itself():
    with pytest.raises(ValueError, match="twice"):
        check_new_rule_names(set(), [new_rule(name="dup"), new_rule(name="dup")])


def test_check_new_rule_names_is_case_insensitive():
    with pytest.raises(ValueError, match="already exists"):
        check_new_rule_names({"acctbal-k-anon"}, [new_rule(name="Acctbal-K-Anon")])


def test_features_survive_the_round_trip_through_the_ledger():
    """Replay re-decides from stored features, so the JSON must be lossless
    for everything the policy engine reads."""
    original = analyze("SELECT C_NATIONKEY, AVG(C_ACCTBAL) FROM TPCH.CUSTOMER "
                       "GROUP BY C_NATIONKEY")
    restored = _features_from_json(original.to_json())
    assert restored.kind == original.kind
    assert restored.tables == original.tables
    assert restored.columns == original.columns
    assert restored.schemas == original.schemas
    assert restored.has_aggregate == original.has_aggregate
    assert restored.select_star == original.select_star


def test_a_replayed_decision_matches_a_live_one():
    """The point of the pure function: history and live traffic get the same
    verdict from the same rules."""
    p = [policy(RULE_KIND="MIN_AGGREGATION", TARGET_SCHEMA="TPCH",
                TARGET_TABLE="CUSTOMER", TARGET_COLUMN="C_ACCTBAL", THRESHOLD=20)]
    sql = "SELECT C_NATIONKEY, AVG(C_ACCTBAL) FROM TPCH.CUSTOMER GROUP BY C_NATIONKEY"
    live = evaluate(analyze(sql), p, min_group=94)
    replayed = evaluate(_features_from_json(analyze(sql).to_json()), p, min_group=94)
    assert live.effect == replayed.effect == ALLOW


class FakeLedger:
    """Just enough connection to answer replay's single query.

    Replay reads the ledger and nothing else, so a double that returns rows is
    the whole of the seam. `persist=False` keeps `conn.ext` out of it.
    """

    def __init__(self, rows):
        self.rows = rows
        self.asked = ""

    def execute(self, sql, params=None):
        self.asked = sql
        return self

    def fetchall(self):
        return self.rows


def entry(seq, sql, *, decision, approval_id=None, est=None, grp=None, taint=None):
    return {"SEQ": seq, "FEATURES": analyze(sql).to_json(), "DECISION": decision,
            "EST_ROWS": est, "MIN_GROUP": grp, "TAINT_MAX": taint,
            "APPROVAL_ID": approval_id}


WIDE_WRITE = "UPDATE TPCH.ORDERS SET O_SHIPPRIORITY = 1 WHERE O_ORDERSTATUS = 'P'"
HOLD_BIG_WRITES = policy(NAME="write-blast-radius", RULE_KIND="BLAST_RADIUS",
                         EFFECT=REQUIRE_APPROVAL, THRESHOLD=500)


def test_an_approved_release_is_replayed_as_approved():
    """A release is ALLOW only because a human said so, and the amended rule
    set does not withdraw that. Replaying it without the approval would report
    every approved write in the history as newly blocked, under any amendment
    at all -- including ones that cannot touch a write."""
    conn = FakeLedger([entry(1, WIDE_WRITE, decision=ALLOW, approval_id=7, est=738)])
    diff = replay(conn, "demo-agent", policies=[HOLD_BIG_WRITES], persist=False)
    assert diff.newly_blocked == 0
    assert diff.changed == 0


def test_the_same_statement_without_an_approval_is_still_held():
    """The other half of the pair: the join is what makes the difference, not
    a blanket exemption for writes."""
    conn = FakeLedger([entry(1, WIDE_WRITE, decision=ALLOW, est=738)])
    diff = replay(conn, "demo-agent", policies=[HOLD_BIG_WRITES], persist=False)
    assert diff.newly_blocked == 1
