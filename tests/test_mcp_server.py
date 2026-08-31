"""The MCP surface's input guard. No database needed.

describe_table pastes its arguments into catalog SQL as literals -- the gateway
takes a statement, not a statement plus bound arguments -- so the identifier
check is the only thing between an agent's argument and the query text. It runs
before the gateway is reached, which is what lets these assert without a
connection.
"""
import json

from airlock.mcp_server import _IDENT, describe_table


def _decision(schema, table):
    return json.loads(describe_table(schema, table))


def test_plain_identifiers_are_accepted():
    assert _IDENT.match("CUSTOMER")
    assert _IDENT.match("TPCH")
    assert _IDENT.match("_private")
    assert _IDENT.match("TABLE$1")


def test_quote_breaking_is_refused_before_the_database_is_touched():
    d = _decision("TPCH' OR '1'='1", "CUSTOMER")
    assert d["decision"] == "DENY"
    assert "not a valid identifier" in d["reason"]


def test_union_smuggling_is_refused():
    d = _decision("TPCH", "CUSTOMER' UNION SELECT C_PHONE, '1' FROM TPCH.CUSTOMER --")
    assert d["decision"] == "DENY"


def test_statement_termination_is_refused():
    d = _decision("TPCH; DROP TABLE AIRLOCK.LEDGER", "X")
    assert d["decision"] == "DENY"


def test_whitespace_and_newlines_are_refused():
    assert not _IDENT.match("TPCH CUSTOMER")
    assert not _IDENT.match("TPCH\nCUSTOMER")
    # \Z rather than $, so a trailing newline cannot smuggle a second line.
    assert not _IDENT.match("CUSTOMER\n-- ")


def test_empty_is_refused():
    assert not _IDENT.match("")
    assert _decision("", "CUSTOMER")["decision"] == "DENY"
