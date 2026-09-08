"""The approval loop: releasing a held statement back through the airlock.

REQUIRE_APPROVAL was a verdict with nowhere to go. The policy engine could hold
a statement, the console could count the holds, and nothing could ever let one
through -- so the demo's largest beat ended on a refusal and the undo AIRLOCK
advertises was never performed on camera.

A release re-enters `gateway.submit()`. It is not executed here and it is not
executed by whoever approved it, and that is the entire design:

  * the pre-image capture is gated on the verdict being ALLOW, so a statement
    run around the gateway would have no snapshot and no runnable rollback;
  * the blast radius is measured again, against the table as it is now rather
    than as it was when the hold was raised;
  * the release gets its own ledger entry, hash-chained onto the held one.

The held entry is never edited. A queue whose approvals rewrote history would
be asking the audit trail to vouch for a decision it had itself been changed to
agree with; the two entries side by side are what make the chain worth having.

An approval releases a hold. It never overrides a DENY -- see
`policy.Decision.apply`. A statement that was both held and denied comes back
denied, and its APPROVAL row still records that a human said yes: the approver
answered the question they were asked, and the second refusal is the ledger's
answer to a different one.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass

import pyexasol

from .gateway import Airlock, Approval, GatewayResult

PENDING = "PENDING"
APPROVED = "APPROVED"
REJECTED = "REJECTED"


@dataclass(frozen=True)
class Held:
    """One queued approval, with the ledger entry it is holding."""

    approval_id: int
    ledger_seq: int
    state: str
    requested_at: str
    principal: str
    session_id: str
    stmt_kind: str
    statement: str
    reason: str
    est_rows: int | None
    decided_by: str | None
    decided_at: str | None
    note: str | None
    result_seq: int | None


_SELECT = """
    SELECT a.APPROVAL_ID, a.LEDGER_SEQ, a.APPROVAL_STATE, a.REQUESTED_AT,
           a.DECIDED_BY, a.DECIDED_AT, a.NOTE, a.RESULT_SEQ,
           l.PRINCIPAL, l.SESSION_ID, l.STMT_KIND, l.STMT_TEXT, l.REASON,
           l.EST_ROWS
    FROM AIRLOCK.APPROVAL a
    JOIN AIRLOCK.LEDGER l ON l.SEQ = a.LEDGER_SEQ
"""


def _held(row: dict) -> Held:
    return Held(
        approval_id=int(row["APPROVAL_ID"]),
        ledger_seq=int(row["LEDGER_SEQ"]),
        state=row["APPROVAL_STATE"],
        requested_at=str(row["REQUESTED_AT"] or ""),
        principal=row["PRINCIPAL"] or "",
        session_id=row["SESSION_ID"] or "",
        stmt_kind=row["STMT_KIND"] or "",
        statement=row["STMT_TEXT"] or "",
        reason=row["REASON"] or "",
        est_rows=int(row["EST_ROWS"]) if row["EST_ROWS"] is not None else None,
        decided_by=row["DECIDED_BY"],
        decided_at=str(row["DECIDED_AT"]) if row["DECIDED_AT"] else None,
        result_seq=int(row["RESULT_SEQ"]) if row["RESULT_SEQ"] is not None else None,
        note=row["NOTE"],
    )


def pending(conn: pyexasol.ExaConnection) -> list[Held]:
    """The queue: everything held and not yet decided, oldest first."""
    rows = conn.execute(
        _SELECT + " WHERE a.APPROVAL_STATE = 'PENDING' ORDER BY a.APPROVAL_ID"
    ).fetchall()
    return [_held(r) for r in rows]


def recent(conn: pyexasol.ExaConnection, limit: int = 50) -> list[Held]:
    """The queue including what has already been decided, newest first."""
    # The limit is interpolated as an integer rather than bound: pyexasol
    # renders a bound parameter as a quoted string, and Exasol will not take
    # LIMIT '50'. int() is what keeps that safe.
    rows = conn.execute(
        _SELECT + f" ORDER BY a.APPROVAL_ID DESC LIMIT {int(limit)}"
    ).fetchall()
    return [_held(r) for r in rows]


def get(conn: pyexasol.ExaConnection, approval_id: int) -> Held:
    row = conn.execute(
        _SELECT + " WHERE a.APPROVAL_ID = {aid}", {"aid": approval_id}
    ).fetchone()
    if not row:
        raise LookupError(f"no approval #{approval_id}")
    return _held(row)


def approve(conn: pyexasol.ExaConnection, approval_id: int, approver: str,
            note: str | None = None) -> GatewayResult:
    """Release a held statement back through the airlock.

    Re-opened on the *original* session id and principal, so the release lands
    in the same agent session the hold came from. `Airlock.__init__` finds the
    existing AGENT_SESSION row and leaves it alone; a fresh uuid here would put
    the two halves of one decision in two different sessions on the console.

    The returned result is whatever the gateway made of the statement the second
    time, which is not necessarily ALLOW: a deny still denies, and a write whose
    radius grew past a hard cap in the meantime is refused on its own merits.
    Either way the queue row records that a human decided, and RESULT_SEQ points
    at the entry that says what came of it.
    """
    held = get(conn, approval_id)
    if held.state != PENDING:
        raise ValueError(f"approval #{approval_id} is already {held.state}")

    air = Airlock(conn, principal=held.principal, session_id=held.session_id)
    result = air.submit(held.statement,
                        approval=Approval(approval_id=approval_id, approver=approver))

    _decide(conn, approval_id, APPROVED, approver, note, result_seq=result.seq)
    return result


def reject(conn: pyexasol.ExaConnection, approval_id: int, approver: str,
           note: str | None = None) -> Held:
    """Refuse a held statement. Nothing runs and no ledger entry is written.

    The hold is already in the ledger, recorded at the moment it was raised.
    A rejection changes nothing about what the airlock did, so there is nothing
    further for the chain to record -- the decision lives on the queue row.
    """
    held = get(conn, approval_id)
    if held.state != PENDING:
        raise ValueError(f"approval #{approval_id} is already {held.state}")
    _decide(conn, approval_id, REJECTED, approver, note, result_seq=None)
    return get(conn, approval_id)


def _decide(conn: pyexasol.ExaConnection, approval_id: int, state: str,
            approver: str, note: str | None, result_seq: int | None) -> None:
    conn.execute(
        """
        UPDATE AIRLOCK.APPROVAL
           SET APPROVAL_STATE = {state}, DECIDED_BY = {by},
               DECIDED_AT = SYSTIMESTAMP, NOTE = {note},
               RESULT_SEQ = {result_seq}
         WHERE APPROVAL_ID = {aid}
        """,
        {"state": state, "by": approver, "note": note,
         "result_seq": result_seq, "aid": approval_id},
    )


def _print(held: Held) -> None:
    rows = f"{held.est_rows} rows" if held.est_rows is not None else "-"
    print(f"  #{held.approval_id:<4} seq {held.ledger_seq:<5} {held.state:<9} "
          f"{held.principal:<12} {held.stmt_kind:<7} {rows}")
    print(f"        {held.statement.strip()[:110]}")
    print(f"        held because: {held.reason[:110]}")
    if held.decided_by:
        print(f"        decided by {held.decided_by} at {held.decided_at}"
              + (f", ledger seq {held.result_seq}" if held.result_seq else ""))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m airlock.approval",
        description="Release or refuse statements the airlock is holding.")
    parser.add_argument("--list", action="store_true", help="show the queue")
    parser.add_argument("--all", action="store_true",
                        help="with --list, include decided approvals")
    parser.add_argument("--approve", type=int, metavar="ID")
    parser.add_argument("--reject", type=int, metavar="ID")
    parser.add_argument("--by", default="operator", help="who is deciding")
    parser.add_argument("--note", default=None)
    args = parser.parse_args()

    from .db import connect
    conn = connect()

    try:
        _run(conn, args)
    except (LookupError, ValueError) as exc:
        # A decision made twice and an id that never existed are both ordinary
        # answers, not crashes. A traceback here would read as a broken tool.
        raise SystemExit(f"error: {exc}") from None


def _run(conn: pyexasol.ExaConnection, args: argparse.Namespace) -> None:
    if args.approve is not None:
        result = approve(conn, args.approve, args.by, args.note)
        print(f"approval #{args.approve} released by {args.by}")
        print(f"  ledger seq {result.seq}: {result.decision}")
        print(f"  {result.reason}")
        if result.affected_rows is not None:
            print(f"  {result.affected_rows} rows")
        if result.rollback_sql:
            print(f"  undo: {result.rollback_sql[:160]}")
        return

    if args.reject is not None:
        held = reject(conn, args.reject, args.by, args.note)
        print(f"approval #{args.reject} rejected by {args.by}; nothing ran")
        _print(held)
        return

    queue = recent(conn) if args.all else pending(conn)
    if not queue:
        print("nothing is waiting for approval")
        return
    label = "approval(s)" if args.all else "pending approval(s)"
    print(f"{len(queue)} {label}:\n")
    for held in queue:
        _print(held)


if __name__ == "__main__":
    main()
