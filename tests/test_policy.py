"""The policy engine is a pure function, so it is tested without a database.

That purity is what makes replay possible: the same function decides live
traffic and historical traffic.
"""
from airlock.analyze import analyze
from airlock.policy import (ALLOW, DENY, REQUIRE_APPROVAL, TAINT_UNMEASURED,
                            evaluate)


def policy(**kw):
    base = dict(POLICY_ID=1, NAME="p", RULE_KIND="COLUMN_ACCESS", EFFECT=DENY,
                TARGET_SCHEMA=None, TARGET_TABLE=None, TARGET_COLUMN=None,
                PRINCIPAL=None, THRESHOLD=None, NOTE=None)
    base.update(kw)
    return base


def test_protected_column_is_denied():
    p = [policy(TARGET_SCHEMA="TPCH", TARGET_TABLE="CUSTOMER", TARGET_COLUMN="C_PHONE")]
    d = evaluate(analyze("SELECT C_PHONE FROM TPCH.CUSTOMER"), p)
    assert d.effect == DENY


def test_select_star_cannot_smuggle_a_protected_column():
    p = [policy(TARGET_SCHEMA="TPCH", TARGET_TABLE="CUSTOMER", TARGET_COLUMN="C_PHONE")]
    d = evaluate(analyze("SELECT * FROM TPCH.CUSTOMER"), p)
    assert d.effect == DENY


def test_unrelated_query_is_allowed():
    p = [policy(TARGET_SCHEMA="TPCH", TARGET_TABLE="CUSTOMER", TARGET_COLUMN="C_PHONE")]
    d = evaluate(analyze("SELECT N_NAME FROM TPCH.NATION"), p)
    assert d.effect == ALLOW


K_ANON = dict(RULE_KIND="MIN_AGGREGATION", TARGET_SCHEMA="TPCH",
              TARGET_TABLE="CUSTOMER", TARGET_COLUMN="C_ACCTBAL", THRESHOLD=20)
AGGREGATE = "SELECT AVG(C_ACCTBAL) FROM TPCH.CUSTOMER GROUP BY C_NATIONKEY"


def test_k_anonymity_blocks_raw_but_allows_a_large_enough_aggregate():
    p = [policy(**K_ANON)]
    raw = evaluate(analyze("SELECT C_ACCTBAL FROM TPCH.CUSTOMER"), p)
    agg = evaluate(analyze(AGGREGATE), p, min_group=94)
    assert raw.effect == DENY
    assert agg.effect == ALLOW


def test_k_anonymity_blocks_an_aggregate_whose_groups_are_too_small():
    """Aggregating is not the same as being anonymous: it is the group size
    that hides the individual, so the group size is what gets measured."""
    p = [policy(**K_ANON)]
    d = evaluate(analyze(AGGREGATE), p, min_group=10)
    assert d.effect == DENY
    assert "smallest group is 10 rows" in d.reason_text


def test_the_same_aggregate_flips_when_k_moves():
    """The k in the policy row is load-bearing -- this is what replay diffs."""
    q = analyze(AGGREGATE)
    assert evaluate(q, [policy(**{**K_ANON, "THRESHOLD": 20})], min_group=94).effect == ALLOW
    assert evaluate(q, [policy(**{**K_ANON, "THRESHOLD": 100})], min_group=94).effect == DENY


def test_unmeasured_group_size_is_not_waved_through():
    p = [policy(**K_ANON)]
    d = evaluate(analyze(AGGREGATE), p, min_group=None)
    assert d.effect == REQUIRE_APPROVAL


def test_blast_radius_holds_large_writes():
    p = [policy(RULE_KIND="BLAST_RADIUS", EFFECT=REQUIRE_APPROVAL, THRESHOLD=500)]
    f = analyze("UPDATE TPCH.CUSTOMER SET C_COMMENT = 'x' WHERE C_ACCTBAL > 0")
    assert evaluate(f, p, affected_rows=2900).effect == REQUIRE_APPROVAL
    assert evaluate(f, p, affected_rows=12).effect == ALLOW


def test_unmeasurable_blast_radius_is_not_waved_through():
    p = [policy(RULE_KIND="BLAST_RADIUS", EFFECT=REQUIRE_APPROVAL, THRESHOLD=500)]
    f = analyze("UPDATE TPCH.CUSTOMER SET C_COMMENT = 'x' WHERE C_ACCTBAL > 0")
    assert evaluate(f, p, affected_rows=None).effect == REQUIRE_APPROVAL


def test_principal_scope_confines_agent_to_its_schema():
    p = [policy(RULE_KIND="SCHEMA_SCOPE", EFFECT=ALLOW, TARGET_SCHEMA="ENERGY",
                PRINCIPAL="energy-analyst")]
    assert evaluate(analyze("SELECT * FROM ENERGY.ENERGY_READINGS"), p).effect == ALLOW
    assert evaluate(analyze("SELECT C_NAME FROM TPCH.CUSTOMER"), p).effect == DENY


def test_unparseable_statement_is_denied_by_default():
    assert evaluate(analyze("SELECT FROM WHERE (((("), []).effect == DENY


def test_ddl_never_passes_the_airlock():
    assert evaluate(analyze("DROP TABLE TPCH.CUSTOMER"), []).effect == DENY


def test_agent_cannot_erase_its_own_audit_trail():
    """The airlock must survive the traffic it governs, even with no policies."""
    assert evaluate(analyze("DELETE FROM AIRLOCK.LEDGER"), []).effect == DENY
    assert evaluate(analyze("SELECT * FROM AIRLOCK.POLICY"), []).effect == DENY
    assert evaluate(analyze("UPDATE AIRLOCK.POLICY SET IS_ENABLED = FALSE"), []).effect == DENY


def test_k_anonymity_does_not_fire_on_a_write_predicate():
    p = [policy(RULE_KIND="MIN_AGGREGATION", TARGET_SCHEMA="TPCH",
                TARGET_TABLE="CUSTOMER", TARGET_COLUMN="C_ACCTBAL", THRESHOLD=20)]
    f = analyze("UPDATE TPCH.CUSTOMER SET C_COMMENT = 'x' WHERE C_ACCTBAL > 0")
    assert evaluate(f, p, affected_rows=10).effect == ALLOW


def test_tainted_result_set_is_withheld():
    p = [policy(RULE_KIND="TAINT_BLOCK", THRESHOLD=0.7)]
    d = evaluate(analyze("SELECT C_COMMENT FROM TPCH.CUSTOMER"), p, taint_max=0.85)
    assert d.effect == DENY
    assert "injected instructions" in d.reason_text


def test_taint_below_the_threshold_is_recorded_not_blocked():
    """Someone writing 'drop table' in a note is not an attack. The score is
    kept either way -- the ledger records what was measured, not just what
    tripped a rule."""
    p = [policy(RULE_KIND="TAINT_BLOCK", THRESHOLD=0.7)]
    d = evaluate(analyze("SELECT C_COMMENT FROM TPCH.CUSTOMER"), p, taint_max=0.25)
    assert d.effect == ALLOW


def test_moving_the_taint_threshold_changes_the_verdict():
    """The threshold is replayable like every other one."""
    q = analyze("SELECT C_COMMENT FROM TPCH.CUSTOMER")
    assert evaluate(q, [policy(RULE_KIND="TAINT_BLOCK", THRESHOLD=0.7)],
                    taint_max=0.45).effect == ALLOW
    assert evaluate(q, [policy(RULE_KIND="TAINT_BLOCK", THRESHOLD=0.4)],
                    taint_max=0.45).effect == DENY


def _taint_rule(threshold=0.7):
    return [policy(POLICY_ID=6, NAME="block-tainted-rows", RULE_KIND="TAINT_BLOCK",
                   EFFECT=DENY, THRESHOLD=threshold)]


def test_a_result_set_that_could_not_be_scanned_is_held_not_allowed():
    """The other two measured rules already fail to REQUIRE_APPROVAL. This one
    used to be the way out: wrap a refused query in a UNION, lose the probe,
    and the rows came back."""
    d = evaluate(analyze("SELECT S_COMMENT FROM TPCH.SUPPLIER"), _taint_rule(),
                 taint_max=TAINT_UNMEASURED)
    assert d.effect == REQUIRE_APPROVAL
    assert "could not be scanned" in d.reason_text


def test_a_clean_scan_still_passes_and_a_dirty_one_still_denies():
    f = analyze("SELECT S_COMMENT FROM TPCH.SUPPLIER")
    assert evaluate(f, _taint_rule(), taint_max=0.0).effect == ALLOW
    assert evaluate(f, _taint_rule(), taint_max=0.9).effect == DENY


def test_no_scan_applied_is_not_the_same_as_a_scan_that_failed():
    """None means nothing text-bearing came back, which is not a refusal."""
    f = analyze("SELECT S_SUPPKEY FROM TPCH.SUPPLIER")
    assert evaluate(f, _taint_rule(), taint_max=None).effect == ALLOW
