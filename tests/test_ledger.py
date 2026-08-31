from airlock.ledger import GENESIS, entry_hash


def test_hash_is_deterministic():
    a = entry_hash(1, "s", "2026-01-01 00:00:00.000000", "SELECT 1", "ALLOW", GENESIS)
    b = entry_hash(1, "s", "2026-01-01 00:00:00.000000", "SELECT 1", "ALLOW", GENESIS)
    assert a == b


def test_changing_the_statement_changes_the_hash():
    a = entry_hash(1, "s", "2026-01-01 00:00:00.000000", "SELECT 1", "ALLOW", GENESIS)
    b = entry_hash(1, "s", "2026-01-01 00:00:00.000000", "SELECT 2", "ALLOW", GENESIS)
    assert a != b


def test_changing_the_decision_changes_the_hash():
    a = entry_hash(1, "s", "2026-01-01 00:00:00.000000", "SELECT 1", "ALLOW", GENESIS)
    b = entry_hash(1, "s", "2026-01-01 00:00:00.000000", "SELECT 1", "DENY", GENESIS)
    assert a != b


def test_chain_position_matters():
    a = entry_hash(2, "s", "2026-01-01 00:00:00.000000", "SELECT 1", "ALLOW", "a" * 64)
    b = entry_hash(2, "s", "2026-01-01 00:00:00.000000", "SELECT 1", "ALLOW", "b" * 64)
    assert a != b
