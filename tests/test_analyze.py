from airlock.analyze import analyze


def test_extracts_qualified_tables_and_columns():
    f = analyze("SELECT C_NAME, C_PHONE FROM TPCH.CUSTOMER WHERE C_CUSTKEY = 1")
    assert f.kind == "SELECT"
    assert "TPCH.CUSTOMER" in f.tables
    assert "TPCH" in f.schemas
    assert "C_PHONE" in f.columns
    assert f.has_where is True


def test_detects_aggregation():
    f = analyze("SELECT C_NATIONKEY, AVG(C_ACCTBAL) FROM TPCH.CUSTOMER GROUP BY C_NATIONKEY")
    assert f.has_aggregate is True


def test_flags_select_star():
    f = analyze("SELECT * FROM TPCH.CUSTOMER")
    assert f.select_star is True


def test_identifies_write_target():
    f = analyze("UPDATE TPCH.CUSTOMER SET C_COMMENT = 'x' WHERE C_CUSTKEY = 1")
    assert f.kind == "UPDATE"
    assert f.target_table == "TPCH.CUSTOMER"


def test_unparseable_statement_is_marked():
    f = analyze("SELECT FROM WHERE ((((")
    assert f.parse_error is not None
