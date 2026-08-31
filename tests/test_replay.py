"""Replay is a what-if, so the amended rule set must never be the real one.

These run without a database: `amend` is list manipulation and `evaluate` is
pure, which together are the whole of replay's decision path.
"""
from airlock.analyze import analyze
from airlock.policy import ALLOW, DENY, evaluate
from airlock.replay import amend, _features_from_json


def policy(**kw):
    base = dict(POLICY_ID=1, NAME="p", RULE_KIND="COLUMN_ACCESS", EFFECT=DENY,
                TARGET_SCHEMA=None, TARGET_TABLE=None, TARGET_COLUMN=None,
                PRINCIPAL=None, THRESHOLD=None, NOTE=None)
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
