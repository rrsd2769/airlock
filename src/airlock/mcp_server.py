"""The Airlock MCP server.

Presents the tool surface an agent expects from a database MCP server, but every
call is routed through the airlock. An agent cannot tell the difference until a
policy stops it -- and when one does, it gets a reason it can act on rather than
an opaque failure.

    uv run airlock-mcp
"""
from __future__ import annotations

import json
import re

from mcp.server.mcpserver import MCPServer

from . import ledger
from .db import connect
from .gateway import Airlock

mcp = MCPServer("airlock")

_conn = None
_airlock: Airlock | None = None

# Schema and table names are pasted into catalog SQL as literals. They cannot be
# bound as parameters -- the gateway takes a statement, not a statement plus
# arguments -- so anything that is not a plain identifier is refused outright
# rather than escaped. An agent asking about a table called `X' OR '1'='1` is
# not making a request worth honouring.
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*\Z")


def _gate() -> Airlock:
    global _conn, _airlock
    if _airlock is None:
        _conn = connect()
        _airlock = Airlock(_conn)
    return _airlock


def _reject(what: str, value: str) -> str:
    return json.dumps({
        "decision": "DENY",
        "reason": f"{what} is not a valid identifier: {value!r}",
        "rows": None,
    })


def _result(result) -> str:
    """One shape for every gated call, so an agent parses one thing.

    The measurements travel with the verdict on purpose. A refusal that says
    only "denied" teaches an agent nothing; one that says the smallest group was
    3 rows against a k of 20 tells it to widen the query itself.
    """
    return json.dumps({
        "decision": result.decision,
        "reason": result.reason,
        "ledger_seq": result.seq,
        "affected_rows": result.affected_rows,
        "min_group": result.min_group,
        "taint_max": result.taint_max,
        "rollback_sql": result.rollback_sql,
        "rows": result.rows,
        "truncated": result.truncated,
    }, default=str)


@mcp.tool()
def list_schemas() -> str:
    """List the schemas this agent is permitted to see."""
    return _result(_gate().submit(
        "SELECT SCHEMA_NAME FROM SYS.EXA_ALL_SCHEMAS ORDER BY SCHEMA_NAME"
    ))


@mcp.tool()
def describe_table(schema: str, table: str) -> str:
    """Describe a table's columns, with policy-protected columns marked."""
    if not _IDENT.match(schema):
        return _reject("schema", schema)
    if not _IDENT.match(table):
        return _reject("table", table)
    return _result(_gate().submit(
        "SELECT COLUMN_NAME, COLUMN_TYPE FROM SYS.EXA_ALL_COLUMNS "
        f"WHERE COLUMN_SCHEMA = '{schema.upper()}' "
        f"AND COLUMN_TABLE = '{table.upper()}' ORDER BY COLUMN_ORDINAL_POSITION"
    ))


@mcp.tool()
def run_query(sql: str) -> str:
    """Run a SQL statement through the airlock.

    Returns the rows if policy allows it, or the specific reason it was refused,
    along with whatever was measured to reach that verdict -- the blast radius,
    the smallest group, the worst taint score. Every call is recorded in the
    tamper-evident ledger either way.
    """
    return _result(_gate().submit(sql))


@mcp.tool()
def explain_refusal(ledger_seq: int) -> str:
    """Explain why a specific statement was refused, by ledger sequence number.

    Scoped to this agent's own session. The ledger is the record of every
    principal that came through the airlock, and one agent has no business
    reading another's statements just because it can name a sequence number.
    """
    gate = _gate()
    row = gate.conn.execute(
        "SELECT SEQ, DECISION, REASON, MATCHED_POLICIES, STMT_TEXT, "
        "EST_ROWS, MIN_GROUP, TAINT_MAX "
        "FROM AIRLOCK.LEDGER WHERE SEQ = {seq} AND SESSION_ID = {sid}",
        {"seq": ledger_seq, "sid": gate.session_id},
    ).fetchone()
    if row is None:
        return json.dumps({"error": f"no decision {ledger_seq} in this session"})
    return json.dumps(row, default=str)


@mcp.tool()
def verify_ledger() -> str:
    """Prove the audit trail has not been altered. Empty findings means intact."""
    findings = ledger.verify(_gate().conn)
    return json.dumps({"intact": not findings, "findings": findings}, default=str)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
