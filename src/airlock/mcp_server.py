"""The Airlock MCP server.

Presents the tool surface an agent expects from a database MCP server, but every
call is routed through the airlock. An agent cannot tell the difference until a
policy stops it -- and when one does, it gets a reason it can act on rather than
an opaque failure.
"""
from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from .db import connect
from .gateway import Airlock
from . import ledger

mcp = FastMCP("airlock")

_conn = None
_airlock: Airlock | None = None


def _gate() -> Airlock:
    global _conn, _airlock
    if _airlock is None:
        _conn = connect()
        _airlock = Airlock(_conn)
    return _airlock


@mcp.tool()
def list_schemas() -> str:
    """List the schemas this agent is permitted to see."""
    gate = _gate()
    result = gate.submit(
        "SELECT SCHEMA_NAME FROM SYS.EXA_ALL_SCHEMAS ORDER BY SCHEMA_NAME"
    )
    return json.dumps({"decision": result.decision, "rows": result.rows,
                       "reason": result.reason})


@mcp.tool()
def describe_table(schema: str, table: str) -> str:
    """Describe a table's columns, with policy-protected columns marked."""
    gate = _gate()
    result = gate.submit(
        "SELECT COLUMN_NAME, COLUMN_TYPE FROM SYS.EXA_ALL_COLUMNS "
        f"WHERE COLUMN_SCHEMA = '{schema.upper()}' "
        f"AND COLUMN_TABLE = '{table.upper()}' ORDER BY COLUMN_ORDINAL_POSITION"
    )
    return json.dumps({"decision": result.decision, "rows": result.rows,
                       "reason": result.reason})


@mcp.tool()
def run_query(sql: str) -> str:
    """Run a SQL statement through the airlock.

    Returns the rows if policy allows it, or the specific reason it was refused.
    Every call is recorded in the tamper-evident ledger either way.
    """
    result = _gate().submit(sql)
    return json.dumps({
        "decision": result.decision,
        "reason": result.reason,
        "ledger_seq": result.seq,
        "affected_rows": result.affected_rows,
        "rows": result.rows,
        "truncated": result.truncated,
    }, default=str)


@mcp.tool()
def explain_refusal(ledger_seq: int) -> str:
    """Explain why a specific statement was refused, by ledger sequence number."""
    conn = _gate().conn
    row = conn.execute(
        "SELECT SEQ, DECISION, REASON, MATCHED_POLICIES, STATEMENT "
        "FROM AIRLOCK.LEDGER WHERE SEQ = ?", [ledger_seq]
    ).fetchone()
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
