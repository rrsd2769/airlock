"""The probes are rewrites, so they are checked as rewrites.

Whether the numbers they return are right is proven against the live database
by the demo; what matters here is that the rewrite keeps the parts of the query
that determine the answer and drops the parts that do not.
"""
from airlock.preflight import build_group_probe, build_probe, build_taint_probe


def test_group_probe_keeps_the_grouping_and_the_filter():
    probe = build_group_probe(
        "SELECT C_NATIONKEY, AVG(C_ACCTBAL) FROM TPCH.CUSTOMER "
        "WHERE C_ACCTBAL > 100 GROUP BY C_NATIONKEY")
    assert "GROUP BY C_NATIONKEY" in probe
    assert "C_ACCTBAL > 100" in probe
    assert "MIN(GRP_N)" in probe


def test_group_probe_drops_the_projections_it_is_not_measuring():
    probe = build_group_probe(
        "SELECT C_NATIONKEY, AVG(C_ACCTBAL) FROM TPCH.CUSTOMER GROUP BY C_NATIONKEY")
    assert "AVG" not in probe


def test_group_probe_drops_ordering_and_limits():
    """A LIMIT changes what is displayed, not how many people are in a group."""
    probe = build_group_probe(
        "SELECT C_NATIONKEY, AVG(C_ACCTBAL) FROM TPCH.CUSTOMER "
        "GROUP BY C_NATIONKEY ORDER BY 2 DESC LIMIT 5")
    assert "LIMIT" not in probe.upper()
    assert "ORDER BY" not in probe.upper()


def test_group_probe_uses_an_identifier_exasol_accepts():
    """Exasol rejects unquoted identifiers beginning with an underscore."""
    probe = build_group_probe("SELECT AVG(C_ACCTBAL) FROM TPCH.CUSTOMER")
    assert "_G " not in probe and "(_" not in probe


def test_group_probe_ignores_a_write():
    assert build_group_probe("UPDATE TPCH.CUSTOMER SET C_COMMENT = 'x'") is None


def test_group_probe_survives_unparseable_sql():
    assert build_group_probe("SELECT FROM WHERE ;;") is None


def test_blast_radius_probe_counts_what_the_write_would_touch():
    probe = build_probe("UPDATE TPCH.CUSTOMER SET C_COMMENT = 'x' WHERE C_ACCTBAL > 0")
    assert "COUNT(*)" in probe
    assert "C_ACCTBAL > 0" in probe


def test_taint_probe_scores_the_text_the_query_would_return():
    probe = build_taint_probe(
        "SELECT C_NAME, C_COMMENT FROM TPCH.CUSTOMER WHERE C_NATIONKEY = 3",
        ["C_COMMENT"])
    assert "AIRLOCK.SCAN_TAINT(C_COMMENT)" in probe
    assert "C_NATIONKEY = 3" in probe
    assert "MAX(" in probe


def test_taint_probe_takes_the_worst_of_several_columns():
    probe = build_taint_probe("SELECT * FROM TPCH.SUPPLIER",
                              ["S_ADDRESS", "S_COMMENT"])
    assert "GREATEST(" in probe
    assert "AIRLOCK.SCAN_TAINT(S_ADDRESS)" in probe
    assert "AIRLOCK.SCAN_TAINT(S_COMMENT)" in probe


def test_taint_probe_does_not_wrap_a_single_column_in_greatest():
    probe = build_taint_probe("SELECT C_COMMENT FROM TPCH.CUSTOMER", ["C_COMMENT"])
    assert "GREATEST(" not in probe


def test_taint_probe_drops_the_limit():
    """A LIMIT without an ORDER BY is an arbitrary slice, so probing with it
    would both scan rows the query will not return and miss rows it will."""
    probe = build_taint_probe(
        "SELECT C_COMMENT FROM TPCH.CUSTOMER LIMIT 10", ["C_COMMENT"])
    assert "LIMIT" not in probe.upper()


def test_taint_probe_is_skipped_when_no_text_comes_back():
    assert build_taint_probe("SELECT COUNT(*) FROM TPCH.CUSTOMER", []) is None


def test_taint_probe_ignores_a_write():
    assert build_taint_probe("UPDATE TPCH.CUSTOMER SET C_COMMENT = 'x'",
                             ["C_COMMENT"]) is None
