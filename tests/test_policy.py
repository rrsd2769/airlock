"""The policy engine is a pure function, so it is tested without a database.

That purity is what makes replay possible: the same function decides live
traffic and historical traffic.
"""
from airlock.analyze import analyze
from airlock.policy import ALLOW, DENY, REQUIRE_APPROVAL, evaluate


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


def test_k_anonymity_blocks_raw_but_allows_aggregate():
    p = [policy(RULE_KIND="MIN_AGGREGATION", TARGET_SCHEMA="TPCH",
                TARGET_TABLE="CUSTOMER", TARGET_COLUMN="C_ACCTBAL", THRESHOLD=20)]
    raw = evaluate(analyze("SELECT C_ACCTBAL FROM TPCH.CUSTOMER"), p)
    agg = evaluate(analyze("SELECT AVG(C_ACCTBAL) FROM TPCH.CUSTOMER GROUP BY C_NATIONKEY"), p)
    assert raw.effect == DENY
    assert agg.effect == ALLOW


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
