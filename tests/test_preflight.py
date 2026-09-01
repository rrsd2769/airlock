"""The probes are rewrites, so they are checked as rewrites.

Whether the numbers they return are right is proven against the live database
by the demo; what matters here is that the rewrite keeps the parts of the query
that determine the answer and drops the parts that do not.
"""
from airlock.analyze import analyze
from airlock.preflight import build_group_probe, build_probe, build_rollback, build_taint_probe


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


def _update(sql, key_columns=None):
    return build_rollback(sql, analyze(sql), "AIRLOCK.SNAP_X", key_columns=key_columns)


def test_rollback_keys_the_merge_on_the_primary_key():
    rollback = _update(
        "UPDATE TPCH.ORDERS SET O_ORDERPRIORITY = '1-URGENT' WHERE O_ORDERSTATUS = 'F'",
        ["O_ORDERKEY"])
    assert "MERGE INTO TPCH.ORDERS t" in rollback
    assert "USING AIRLOCK.SNAP_X s ON (t.O_ORDERKEY = s.O_ORDERKEY)" in rollback
    assert "UPDATE SET t.O_ORDERPRIORITY = s.O_ORDERPRIORITY" in rollback
    assert "TODO" not in rollback


def test_rollback_matches_on_every_column_of_a_composite_key():
    rollback = _update(
        "UPDATE TPCH.PARTSUPP SET PS_COMMENT = 'x' WHERE PS_AVAILQTY = 0",
        ["PS_PARTKEY", "PS_SUPPKEY"])
    assert "ON (t.PS_PARTKEY = s.PS_PARTKEY AND t.PS_SUPPKEY = s.PS_SUPPKEY)" in rollback


def test_rollback_restores_only_the_columns_the_write_touched():
    """The rest of the snapshot already matches; rewriting it would be noise."""
    rollback = _update(
        "UPDATE TPCH.CUSTOMER SET C_ACCTBAL = 0, C_COMMENT = 'x' WHERE C_NATIONKEY = 3",
        ["C_CUSTKEY"])
    assert "UPDATE SET t.C_ACCTBAL = s.C_ACCTBAL, t.C_COMMENT = s.C_COMMENT" in rollback
    assert "C_NAME" not in rollback


def test_rollback_without_a_key_replaces_the_affected_set_wholesale():
    """No key, but the predicate reads nothing the write changes -- so after the
    write it still selects exactly the rows that were touched."""
    rollback = _update(
        "UPDATE STAGING.EVENTS SET STATUS = 'done' WHERE BATCH_ID = 7")
    assert "DELETE FROM STAGING.EVENTS WHERE BATCH_ID = 7;" in rollback
    assert "INSERT INTO STAGING.EVENTS SELECT * FROM AIRLOCK.SNAP_X" in rollback


def test_rollback_refuses_to_guess_when_the_write_reads_what_it_writes():
    """Without a key, a predicate over a column the write changes cannot find
    the same rows again afterwards. Say so rather than emit plausible SQL."""
    rollback = _update(
        "UPDATE STAGING.EVENTS SET STATUS = 'done' WHERE STATUS = 'new'")
    assert "STATUS" in rollback
    assert "needs a key" in rollback
    for statement in ("MERGE", "DELETE FROM", "INSERT INTO"):
        assert statement not in rollback


def test_rollback_reinserts_what_a_delete_removed():
    sql = "DELETE FROM TPCH.ORDERS WHERE O_ORDERSTATUS = 'F'"
    rollback = build_rollback(sql, analyze(sql), "AIRLOCK.SNAP_X", ["O_ORDERKEY"])
    assert rollback == "INSERT INTO TPCH.ORDERS SELECT * FROM AIRLOCK.SNAP_X"


def test_rollback_carries_no_placeholders_for_any_write_kind():
    """These strings are shown to a human deciding whether to approve a write."""
    for sql in ("UPDATE TPCH.ORDERS SET O_ORDERPRIORITY = '1-URGENT' WHERE O_ORDERKEY > 1",
                "DELETE FROM TPCH.ORDERS WHERE O_ORDERKEY > 1",
                "INSERT INTO TPCH.ORDERS SELECT * FROM TPCH.ORDERS"):
        rollback = build_rollback(sql, analyze(sql), "AIRLOCK.SNAP_X", ["O_ORDERKEY"])
        assert "TODO" not in rollback and "<" not in rollback


def test_rollback_comments_hold_no_semicolons():
    """The script is pasted into clients that split statements on ';', so a
    semicolon inside a comment would cut a statement in half."""
    for sql, keys in (("UPDATE S.T SET STATUS = 'done' WHERE STATUS = 'new'", []),
                      ("UPDATE S.T SET STATUS = 'done' WHERE BATCH = 7", []),
                      ("INSERT INTO S.T SELECT * FROM S.U", ["ID"])):
        rollback = build_rollback(sql, analyze(sql), "AIRLOCK.SNAP_X", key_columns=keys)
        comments = [ln for ln in rollback.splitlines() if ln.lstrip().startswith("--")]
        assert comments
        assert not any(";" in ln for ln in comments)


def test_taint_probe_scans_both_branches_of_a_union():
    """Wrapping a refused query in `UNION ALL SELECT ... WHERE 1=0` used to
    produce no probe at all, and an unmeasured result set was allowed."""
    probe = build_taint_probe(
        "SELECT S_COMMENT FROM TPCH.SUPPLIER "
        "UNION ALL SELECT S_COMMENT FROM TPCH.SUPPLIER WHERE 1 = 0",
        ["S_COMMENT"])
    assert probe is not None
    assert probe.count("AIRLOCK.SCAN_TAINT(S_COMMENT)") == 2
    assert "UNION ALL" in probe.upper()


def test_taint_probe_scans_every_branch_of_a_chained_union():
    probe = build_taint_probe(
        "SELECT S_COMMENT FROM TPCH.SUPPLIER "
        "UNION ALL SELECT S_COMMENT FROM TPCH.SUPPLIER WHERE 1 = 0 "
        "UNION ALL SELECT S_COMMENT FROM TPCH.SUPPLIER WHERE 2 = 0",
        ["S_COMMENT"])
    assert probe.count("AIRLOCK.SCAN_TAINT(S_COMMENT)") == 3


def test_taint_probe_keeps_a_cte_it_selects_through():
    probe = build_taint_probe(
        "WITH x AS (SELECT S_COMMENT FROM TPCH.SUPPLIER) SELECT S_COMMENT FROM x",
        ["S_COMMENT"])
    assert probe is not None
    assert "WITH" in probe.upper()


def test_taint_probe_drops_the_limit_on_every_branch_of_a_union():
    probe = build_taint_probe(
        "SELECT S_COMMENT FROM TPCH.SUPPLIER LIMIT 5 "
        "UNION ALL SELECT S_COMMENT FROM TPCH.SUPPLIER LIMIT 5",
        ["S_COMMENT"])
    assert "LIMIT" not in probe.upper()
