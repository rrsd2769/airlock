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


# Scale used to lift TAINT_MAX (DECIMAL(9,4)) onto an integer before hashing.
TAINT_SCALE = 10000


def _measure(value: float | None, scale: int = 1) -> str:
    """Render a measurement so Python and Exasol agree on the bytes.

    Exasol trims a scaled DECIMAL on the way to a string -- 0.8500 prints as
    '0.85' and 0.0000 as '0' -- and reproducing those rules in Python is more
    fragile than removing the decimal point from both sides. So a scaled column
    is lifted to an integer first and compared as one.

    NULL renders as the empty string, which is what Exasol's `||` does with a
    NULL operand anyway.
    """
    if value is None:
        return ""
    return str(round(float(value) * scale))


def entry_hash(seq: int, session_id: str, ts: str, principal: str,
               stmt_kind: str, statement: str, decision: str,
               matched_policies: str | None, reason: str | None,
               est_rows: int | None, min_group: int | None,
               taint_max: float | None, rollback_sql: str | None,
               prev_hash: str) -> str:
    """Must stay byte-identical to LEDGER_CHECK in sql/20_udfs.sql.

    The payload covers everything the decision consists of, not just the verdict:
    who ran the statement, which rules fired and why, and the measurements the
    verdict rested on. Those measurements are what `airlock.replay` re-decides
    from, so leaving them outside the hash would make the replay's inputs
    rewritable by anyone with UPDATE on the table.

    LATENCY_MS is deliberately outside it. It is telemetry, no decision was ever
    taken on it, and it is the one column that legitimately differs between two
    otherwise identical runs.
    """
    payload = "|".join([
        str(int(seq)), session_id or "", ts or "",
        principal or "", stmt_kind or "", statement or "", decision or "",
        matched_policies or "", reason or "",
        _measure(est_rows), _measure(min_group),
        _measure(taint_max, TAINT_SCALE),
        rollback_sql or "", prev_hash or "",
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
           min_group: int | None, rollback_sql: str | None,
           taint_max: float | None, latency_ms: float | None) -> LedgerEntry:
    prev_seq, prev_hash = head(conn)
    seq = prev_seq + 1
    ts = conn.execute("SELECT TO_CHAR(SYSTIMESTAMP, "
                      "'YYYY-MM-DD HH24:MI:SS.FF6') AS T").fetchone()["T"]
    digest = entry_hash(seq, session_id, ts, principal, stmt_kind, statement,
                        decision, matched_policies, reason, est_rows, min_group,
                        taint_max, rollback_sql, prev_hash)

    conn.execute(
        """
        INSERT INTO AIRLOCK.LEDGER
            (SEQ, SESSION_ID, TS, PRINCIPAL, STMT_KIND, STMT_TEXT, FEATURES,
             DECISION, MATCHED_POLICIES, REASON, EST_ROWS, MIN_GROUP,
             ROLLBACK_SQL, TAINT_MAX, LATENCY_MS, PREV_HASH, ENTRY_HASH)
        VALUES ({seq}, {session_id},
                TO_TIMESTAMP({ts}, 'YYYY-MM-DD HH24:MI:SS.FF6'),
                {principal}, {stmt_kind}, {stmt_text}, {features},
                {decision}, {matched}, {reason}, {est_rows}, {min_group},
                {rollback_sql}, {taint_max}, {latency_ms}, {prev_hash},
                {entry_hash})
        """,
        {
            "seq": seq, "session_id": session_id, "ts": ts,
            "principal": principal, "stmt_kind": stmt_kind,
            "stmt_text": statement, "features": features_json,
            "decision": decision, "matched": matched_policies,
            "reason": reason, "est_rows": est_rows, "min_group": min_group,
            "rollback_sql": rollback_sql, "taint_max": taint_max,
            "latency_ms": latency_ms, "prev_hash": prev_hash,
            "entry_hash": digest,
        },
    )
    return LedgerEntry(seq=seq, ts=ts, entry_hash=digest, prev_hash=prev_hash)


def verify(conn: pyexasol.ExaConnection) -> list[dict[str, Any]]:
    """Run the chain check. An empty list means the ledger is intact.

    This is a plain analytical query, not a UDF: Exasol's native HASH_SHA256
    recomputes each entry and a LAG window re-links the chain. No script
    language container is involved, so the audit works on a bare deployment.
    """
    return conn.execute(
        "SELECT SEQ, PROBLEM, EXPECTED, FOUND_HASH FROM AIRLOCK.LEDGER_BREAKS ORDER BY SEQ"
    ).fetchall()
