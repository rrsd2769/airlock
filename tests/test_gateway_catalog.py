"""What the gateway does with the catalog's answer.

The catalog's own behaviour -- binding, caching, the clock -- is pinned in
`test_catalog.py`. What is left here is the gateway's judgement on top of it:
which of a query's text columns it will actually scan, and, when the query's
shape means it cannot tell, saying so rather than reporting an empty list as a
clean result.

There is no fake connection in this file. The gateway takes its catalog, so a
test says which columns exist in Python and never sees catalog SQL.
"""
from airlock.gateway import Airlock
from airlock.statement import Statement
from tests.fakes import FakeCatalog, text

CUSTOMER = [text("TPCH", "CUSTOMER", "C_NAME"),
            text("TPCH", "CUSTOMER", "C_COMMENT")]
SUPPLIER = [text("TPCH", "SUPPLIER", "S_NAME"),
            text("TPCH", "SUPPLIER", "S_ADDRESS"),
            text("TPCH", "SUPPLIER", "S_COMMENT")]


def _gateway(columns=()):
    """An Airlock without __init__: constructing one registers a session."""
    gate = Airlock.__new__(Airlock)
    gate.conn = None
    gate.catalog = FakeCatalog(columns=columns)
    return gate


def _columns(gate, sql):
    """The gateway asks for the columns and whether it could tell."""
    return gate._text_columns(Statement.parse(sql))


def test_select_star_takes_every_text_column_and_a_named_list_takes_its_own():
    gate = _gateway(CUSTOMER)
    assert _columns(gate, "SELECT * FROM TPCH.CUSTOMER") == (["C_NAME", "C_COMMENT"], True)
    assert _columns(gate, "SELECT C_COMMENT FROM TPCH.CUSTOMER") == (["C_COMMENT"], True)


def test_a_query_naming_no_qualified_table_asks_the_catalog_nothing():
    gate = _gateway(CUSTOMER)
    assert _columns(gate, "SELECT 1") == ([], True)
    assert gate.catalog.asked == []


def test_the_catalog_schema_is_not_scanned_for_taint():
    """An agent browsing SYS is not carrying a payload out of customer free
    text, and SCAN_TAINT cannot read a system view -- so no scan applies, which
    is different from one that failed."""
    gate = _gateway(CUSTOMER)
    assert _columns(gate, "SELECT SCHEMA_NAME FROM SYS.EXA_ALL_SCHEMAS") == ([], True)
    assert gate.catalog.asked == []


def test_only_the_tables_the_query_names_are_asked_about():
    gate = _gateway(CUSTOMER + SUPPLIER)
    found, _ = _columns(gate, "SELECT C_COMMENT, S_COMMENT "
                              "FROM TPCH.CUSTOMER, TPCH.SUPPLIER")
    assert found == ["C_COMMENT", "S_COMMENT"]
    assert gate.catalog.asked == [
        ("text_columns", ("TPCH.CUSTOMER", "TPCH.SUPPLIER"), None)]


def test_a_star_over_a_cte_falls_back_to_the_columns_named():
    """The catalog lists the base table's text columns, not which ones a CTE
    passes through. Scanning one it does not expose makes the probe fail."""
    gate = _gateway(SUPPLIER)
    sql = ("WITH x AS (SELECT S_NAME, S_COMMENT FROM TPCH.SUPPLIER) "
           "SELECT * FROM x")
    assert _columns(gate, sql) == (["S_NAME", "S_COMMENT"], True)


def test_a_star_over_a_cte_naming_no_text_is_not_called_clean():
    """Nothing to scan and no way to tell are different answers. Reporting the
    second as the first is how an unscannable result set gets waved through."""
    gate = _gateway([text("TPCH", "SUPPLIER", "S_COMMENT")])
    sql = "WITH x AS (SELECT S_SUPPKEY FROM TPCH.SUPPLIER) SELECT * FROM x"
    assert _columns(gate, sql) == ([], False)
