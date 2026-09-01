"""The gateway's catalog lookups take names out of the agent's own statement.

Both of these run against the connection directly rather than through
`submit()`, so their inputs can be bound as parameters -- which is what these
pin. A fake connection stands in for the database: what matters is the query
text and the parameters the gateway hands over, not what Exasol replies.
"""
from airlock.analyze import analyze
from airlock.gateway import Airlock


class FakeConn:
    """Records what it was asked, answers nothing."""

    def __init__(self, rows=None):
        self.rows = rows or []
        self.query = None
        self.params = None

    def execute(self, query, params=None):
        self.query, self.params = query, params
        return self

    def fetchall(self):
        return self.rows


def _gateway(conn):
    """An Airlock without __init__: constructing one registers a session."""
    gate = Airlock.__new__(Airlock)
    gate.conn = conn
    gate._key_cache = {}
    return gate


def _columns(gate, sql):
    """The gateway asks for the columns and whether it could tell."""
    return gate._text_columns(analyze(sql), sql)


def test_table_names_are_bound_not_pasted_into_the_catalog_query():
    """A quote in a table name would otherwise rewrite the predicate and return
    every VARCHAR column in the database, including AIRLOCK's own."""
    conn = FakeConn()
    _columns(_gateway(conn), "SELECT C_COMMENT FROM \"TPCH\".\"CUSTOMER' OR '1'='1\"")
    assert "OR '1'='1" not in conn.query
    assert "CUSTOMER' OR '1'='1" in conn.params.values()


def test_every_table_in_the_query_gets_its_own_parameters():
    conn = FakeConn()
    _columns(_gateway(conn),
             "SELECT C_COMMENT, S_COMMENT FROM TPCH.CUSTOMER, TPCH.SUPPLIER")
    assert conn.params == {"s0": "TPCH", "t0": "CUSTOMER",
                           "s1": "TPCH", "t1": "SUPPLIER"}


def test_a_query_naming_no_qualified_table_asks_the_catalog_nothing():
    conn = FakeConn()
    assert _columns(_gateway(conn), "SELECT 1") == ([], True)
    assert conn.query is None


def test_select_star_takes_every_text_column_and_a_named_list_takes_its_own():
    rows = [{"C": "C_NAME"}, {"C": "C_COMMENT"}]
    gate = _gateway(FakeConn(rows))
    assert _columns(gate, "SELECT * FROM TPCH.CUSTOMER") == (["C_NAME", "C_COMMENT"], True)
    assert _columns(gate, "SELECT C_COMMENT FROM TPCH.CUSTOMER") == (["C_COMMENT"], True)


def test_the_key_lookup_binds_its_names_too():
    conn = FakeConn([{"C": "O_ORDERKEY"}])
    assert _gateway(conn)._key_columns("TPCH.ORDERS") == ["O_ORDERKEY"]
    assert conn.params == {"schema": "TPCH", "tbl": "ORDERS"}
    assert "TPCH" not in conn.query


def test_the_key_lookup_is_cached_per_table():
    conn = FakeConn([{"C": "O_ORDERKEY"}])
    gate = _gateway(conn)
    gate._key_columns("TPCH.ORDERS")
    conn.query = None
    assert gate._key_columns("TPCH.ORDERS") == ["O_ORDERKEY"]
    assert conn.query is None


def test_an_unqualified_target_has_no_key_to_look_up():
    conn = FakeConn()
    assert _gateway(conn)._key_columns("ORDERS") == []
    assert _gateway(conn)._key_columns(None) == []
    assert conn.query is None


def test_the_catalog_schema_is_not_scanned_for_taint():
    """An agent browsing SYS is not carrying a payload out of customer free
    text, and SCAN_TAINT cannot read a system view -- so no scan applies, which
    is different from one that failed."""
    conn = FakeConn()
    assert _columns(_gateway(conn), "SELECT SCHEMA_NAME FROM SYS.EXA_ALL_SCHEMAS") \
        == ([], True)
    assert conn.query is None


def test_a_star_over_a_cte_falls_back_to_the_columns_named():
    """The catalog lists the base table's text columns, not which ones a CTE
    passes through. Scanning one it does not expose makes the probe fail."""
    gate = _gateway(FakeConn([{"C": "S_NAME"}, {"C": "S_ADDRESS"}, {"C": "S_COMMENT"}]))
    sql = ("WITH x AS (SELECT S_NAME, S_COMMENT FROM TPCH.SUPPLIER) "
           "SELECT * FROM x")
    assert _columns(gate, sql) == (["S_NAME", "S_COMMENT"], True)


def test_a_star_over_a_cte_naming_no_text_is_not_called_clean():
    """Nothing to scan and no way to tell are different answers. Reporting the
    second as the first is how an unscannable result set gets waved through."""
    gate = _gateway(FakeConn([{"C": "S_COMMENT"}]))
    sql = "WITH x AS (SELECT S_SUPPKEY FROM TPCH.SUPPLIER) SELECT * FROM x"
    assert _columns(gate, sql) == ([], False)
