"""Tamper-evident audit ledger.

Each entry is hashed together with the hash of the entry before it. Editing or
deleting any historical row breaks every hash that follows, and the break is
detectable by LEDGER_VERIFY -- a UDF that runs inside the database, so the audit
never requires exporting the audit trail to be trusted.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import pyexasol

GENESIS = "0" * 64


def entry_hash(seq: int, session_id: str, ts: str, statement: str,
               decision: str, prev_hash: str) -> str:
    """Must stay byte-identical to LEDGER_VERIFY in sql/20_udfs.sql."""
    payload = "|".join([
        str(int(seq)), session_id or "", ts or "",
        statement or "", decision or "", prev_hash or "",
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class LedgerEntry:
    seq: int
    ts: str
    entry_hash: str
    prev_hash: str


def head(conn: pyexasol.ExaConnection) -> tuple[int, str]:
    """Latest sequence number and hash, or the genesis pair on an empty ledger."""
    row = conn.execute(
        "SELECT SEQ, ENTRY_HASH FROM AIRLOCK.LEDGER ORDER BY SEQ DESC LIMIT 1"
    ).fetchone()
    if not row:
        return 0, GENESIS
    return int(row["SEQ"]), row["ENTRY_HASH"]


def append(conn: pyexasol.ExaConnection, *, session_id: str, principal: str,
           stmt_kind: str, statement: str, features_json: str, decision: str,
           matched_policies: str, reason: str, est_rows: int | None,
           rollback_sql: str | None, taint_max: float | None,
           latency_ms: float | None) -> LedgerEntry:
    prev_seq, prev_hash = head(conn)
    seq = prev_seq + 1
    ts = conn.execute("SELECT TO_CHAR(SYSTIMESTAMP, "
                      "'YYYY-MM-DD HH24:MI:SS.FF6') AS T").fetchone()["T"]
    digest = entry_hash(seq, session_id, ts, statement, decision, prev_hash)

    conn.execute(
        """
        INSERT INTO AIRLOCK.LEDGER
            (SEQ, SESSION_ID, TS, PRINCIPAL, STMT_KIND, STATEMENT, FEATURES,
             DECISION, MATCHED_POLICIES, REASON, EST_ROWS, ROLLBACK_SQL,
             TAINT_MAX, LATENCY_MS, PREV_HASH, ENTRY_HASH)
        VALUES (?, ?, TO_TIMESTAMP(?, 'YYYY-MM-DD HH24:MI:SS.FF6'), ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [seq, session_id, ts, principal, stmt_kind, statement, features_json,
         decision, matched_policies, reason, est_rows, rollback_sql,
         taint_max, latency_ms, prev_hash, digest],
    )
    return LedgerEntry(seq=seq, ts=ts, entry_hash=digest, prev_hash=prev_hash)


def verify(conn: pyexasol.ExaConnection) -> list[dict[str, Any]]:
    """Run the in-database chain check. An empty list means the ledger is intact."""
    return conn.execute(
        """
        SELECT AIRLOCK.LEDGER_VERIFY(
                   SEQ, SESSION_ID,
                   TO_CHAR(TS, 'YYYY-MM-DD HH24:MI:SS.FF6'),
                   STATEMENT, DECISION, PREV_HASH, ENTRY_HASH
               ORDER BY SEQ)
        FROM AIRLOCK.LEDGER
        """
    ).fetchall()
