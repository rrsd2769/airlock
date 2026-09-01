"""The catalog module: one place that knows how to ask Exasol about itself.

These pin the facts that used to be re-derived by every caller -- that names
taken from an agent's statement are bound rather than pasted, that a key lookup
is worth caching, that `SNAP_`'s underscore is a LIKE wildcard, and that
`CREATED` is compared against the database's clock and not the session's.

A fake connection stands in for the database: what matters is the query text and
the parameters handed over, not what Exasol replies.
"""
from airlock.catalog import Catalog


class FakeConn:
    """Records what it was asked, answers whatever it was given."""

    def __init__(self, rows=None):
        self.rows = rows or []
        self.query = None
        self.params = None

    def execute(self, query, params=None):
        self.query, self.params = query, params
        return self

    def fetchall(self):
        return self.rows


# --------------------------------------------------------------------------
# columns
# --------------------------------------------------------------------------

def test_table_names_are_bound_not_pasted_into_the_catalog_query():
    """A quote in a table name would otherwise rewrite the predicate and return
    every VARCHAR column in the database, including AIRLOCK's own."""
    conn = FakeConn()
    Catalog(conn).text_columns(tables=["TPCH.CUSTOMER' OR '1'='1"])
    assert "OR '1'='1" not in conn.query
    assert "CUSTOMER' OR '1'='1" in conn.params.values()


def test_every_table_gets_its_own_parameters():
    conn = FakeConn()
    Catalog(conn).text_columns(tables=["TPCH.CUSTOMER", "TPCH.SUPPLIER"])
    assert (conn.params["s0"], conn.params["t0"]) == ("TPCH", "CUSTOMER")
    assert (conn.params["s1"], conn.params["t1"]) == ("TPCH", "SUPPLIER")


def test_asking_about_no_tables_asks_the_database_nothing():
    conn = FakeConn()
    assert Catalog(conn).text_columns(tables=[]) == []
    assert conn.query is None


def test_a_schema_sweep_binds_the_schema_and_uppercases_it():
    conn = FakeConn()
    Catalog(conn).text_columns(schema="tpch")
    assert conn.params["schema"] == "TPCH"


def test_columns_come_back_as_values_not_rows():
    conn = FakeConn([{"SCH": "TPCH", "TBL": "CUSTOMER",
                      "COL": "C_COMMENT", "WIDTH": 117}])
    found = Catalog(conn).text_columns(tables=["TPCH.CUSTOMER"])
    assert [c.name for c in found] == ["C_COMMENT"]
    assert found[0].qualified == "TPCH.CUSTOMER.C_COMMENT"
    assert found[0].width == 117


# --------------------------------------------------------------------------
# keys
# --------------------------------------------------------------------------

def test_the_key_lookup_binds_its_names_too():
    conn = FakeConn([{"C": "O_ORDERKEY"}])
    assert Catalog(conn).primary_key("TPCH.ORDERS") == ["O_ORDERKEY"]
    assert conn.params == {"schema": "TPCH", "tbl": "ORDERS"}
    assert "TPCH" not in conn.query


def test_the_key_lookup_is_cached_per_table():
    conn = FakeConn([{"C": "O_ORDERKEY"}])
    catalog = Catalog(conn)
    catalog.primary_key("TPCH.ORDERS")
    conn.query = None
    assert catalog.primary_key("TPCH.ORDERS") == ["O_ORDERKEY"]
    assert conn.query is None


def test_an_unqualified_target_has_no_key_to_look_up():
    conn = FakeConn()
    assert Catalog(conn).primary_key("ORDERS") == []
    assert Catalog(conn).primary_key(None) == []
    assert conn.query is None


# --------------------------------------------------------------------------
# tables, and the clock
# --------------------------------------------------------------------------

def test_retention_compares_against_the_database_clock_not_the_session():
    """CREATED is stamped on the database clock and CURRENT_TIMESTAMP is the
    session's timezone. Comparing one against the other made every snapshot look
    older than it was by the session's offset -- two hours, where this was
    found. This is the only place in AIRLOCK that makes the comparison."""
    conn = FakeConn()
    Catalog(conn).tables("AIRLOCK", prefix="SNAP_", older_than_days=7)
    assert "SYSTIMESTAMP" in conn.query
    assert "CURRENT_TIMESTAMP" not in conn.query
    assert "INTERVAL '7' DAY" in conn.query


def test_no_age_filter_means_no_cutoff_at_all():
    conn = FakeConn()
    Catalog(conn).tables("AIRLOCK", prefix="SNAP_")
    assert "INTERVAL" not in conn.query


def test_the_prefixs_underscore_is_escaped_because_like_treats_it_as_a_wildcard():
    """`SNAP_%` unescaped matches SNAPSHOT, SNAPPED and anything else that
    starts with SNAP -- including tables AIRLOCK did not create."""
    conn = FakeConn()
    Catalog(conn).tables("AIRLOCK", prefix="SNAP_")
    assert conn.params["pattern"] == "SNAP@_%"
    assert "ESCAPE '@'" in conn.query
