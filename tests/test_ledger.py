"""The entry hash. No database needed here -- what proves Python and Exasol
agree byte for byte is a regenerated corpus with zero rows in LEDGER_BREAKS,
since every entry is written by Python and re-verified by SQL.
"""
from airlock.ledger import GENESIS, entry_hash

BASE = {
    "seq": 1, "session_id": "s", "ts": "2026-01-01 00:00:00.000000",
    "principal": "demo-agent", "stmt_kind": "SELECT", "statement": "SELECT 1",
    "decision": "ALLOW", "matched_policies": None, "reason": "no policy matched",
    "est_rows": None, "min_group": None, "taint_max": None, "rollback_sql": None,
    "prev_hash": GENESIS,
}


def h(**overrides):
    return entry_hash(**{**BASE, **overrides})


def test_hash_is_deterministic():
    assert h() == h()


def test_changing_the_statement_changes_the_hash():
    assert h() != h(statement="SELECT 2")


def test_changing_the_decision_changes_the_hash():
    assert h() != h(decision="DENY")


def test_chain_position_matters():
    assert h(seq=2, prev_hash="a" * 64) != h(seq=2, prev_hash="b" * 64)


def test_the_principal_is_covered():
    """Who ran a statement is half of what an audit trail is for."""
    assert h() != h(principal="someone-else")


def test_the_reason_and_the_rules_that_fired_are_covered():
    assert h() != h(reason="no policy matched ")
    assert h() != h(matched_policies="4")


def test_the_measurements_are_covered():
    """airlock.replay re-decides from these, so they are decision inputs."""
    assert h() != h(min_group=20)
    assert h() != h(est_rows=500)
    assert h() != h(taint_max=0.85)
    assert h() != h(rollback_sql="DELETE FROM x")


def test_a_null_measurement_and_a_zero_are_not_the_same():
    assert h(min_group=None) != h(min_group=0)
    assert h(taint_max=None) != h(taint_max=0.0)


def test_taint_is_distinguished_below_exasols_string_trimming():
    """0.8500 and 0.85 are the same number; 0.85 and 0.8501 are not. Exasol
    prints both of the latter differently only because the scale survives, so
    the payload lifts them onto integers rather than trusting the rendering."""
    assert h(taint_max=0.85) == h(taint_max=0.8500)
    assert h(taint_max=0.85) != h(taint_max=0.8501)


def test_the_statement_kind_is_covered():
    assert h() != h(stmt_kind="UPDATE")
