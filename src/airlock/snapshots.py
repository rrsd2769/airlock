"""Pre-image snapshots: naming, listing, and getting rid of them again.

A write that AIRLOCK allows through gets its affected rows copied first, so the
compensating statement recorded beside the decision has something to read back
from. That copy is a real table in the AIRLOCK schema, and tables that nothing
ever drops are a slow leak -- so the same module that names them knows how to
find them and how to age them out.

A snapshot is worth keeping for exactly as long as you might still reverse the
write it belongs to. That is a judgement about your data, not something the
gateway can infer, so retention is a decision you make here rather than a
constant compiled into the write path.
"""
from __future__ import annotations

import argparse
import uuid

import pyexasol

SCHEMA = "AIRLOCK"
PREFIX = "SNAP_"

# Default retention for --prune. A week is long enough that a write noticed on
# Monday can still be reversed on Friday, and short enough that the schema does
# not accumulate a copy of every row an agent has ever touched.
DEFAULT_KEEP_DAYS = 7


def new_name() -> str:
    """A fresh snapshot table name, qualified with the schema it lives in."""
    return f"{SCHEMA}.{PREFIX}{uuid.uuid4().hex[:12].upper()}"


def listing(conn: pyexasol.ExaConnection) -> list[dict]:
    """Every snapshot table, newest first, with the decision it belongs to.

    The owning SEQ is found by looking for the snapshot's name in the ledger's
    compensating statements. It is the thing you want before dropping one --
    "which write does this belong to" is the question retention actually turns
    on, and the ledger is the only place that answers it.
    """
    rows = conn.execute(
        "SELECT OBJECT_NAME AS NAME, CREATED FROM SYS.EXA_ALL_OBJECTS "
        "WHERE ROOT_NAME = {schema} AND OBJECT_TYPE = 'TABLE' "
        "AND OBJECT_NAME LIKE {pattern} ESCAPE '@' ORDER BY CREATED DESC",
        {"schema": SCHEMA, "pattern": f"{PREFIX[:-1]}@_%"},
    ).fetchall()

    owners = {}
    for entry in conn.execute(
        "SELECT SEQ, DECISION, ROLLBACK_SQL FROM AIRLOCK.LEDGER "
        "WHERE ROLLBACK_SQL LIKE {pattern} ESCAPE '@'",
        {"pattern": f"%{PREFIX[:-1]}@_%"},
    ).fetchall():
        for name in {r["NAME"] for r in rows}:
            if name in (entry["ROLLBACK_SQL"] or ""):
                owners[name] = (int(entry["SEQ"]), entry["DECISION"])

    out = []
    for r in rows:
        seq, decision = owners.get(r["NAME"], (None, None))
        out.append({"name": r["NAME"], "created": r["CREATED"],
                    "seq": seq, "decision": decision,
                    "rows": _row_count(conn, r["NAME"])})
    return out


def _row_count(conn: pyexasol.ExaConnection, name: str) -> int | None:
    try:
        row = conn.execute(f"SELECT COUNT(*) AS N FROM {SCHEMA}.{name}").fetchone()
    except Exception:  # noqa: BLE001 - a snapshot we cannot count is still listed
        return None
    return int(next(iter(row.values()))) if row else None


def prune(conn: pyexasol.ExaConnection, keep_days: int | None,
          dry_run: bool = False) -> list[str]:
    """Drop snapshots older than `keep_days`, or all of them when it is None.

    Returns the names dropped, so the caller can say what happened rather than
    reporting a count and leaving the reader to trust it.
    """
    # SYSTIMESTAMP, not CURRENT_TIMESTAMP: the catalog stamps CREATED on the
    # database clock, while CURRENT_TIMESTAMP is the session's timezone. Compared
    # against each other, every snapshot looks older or younger than it is by the
    # session's offset -- which on this host is two hours, and elsewhere is
    # whatever the client happens to be set to.
    cutoff = (
        "" if keep_days is None
        else f" AND CREATED < SYSTIMESTAMP - INTERVAL '{int(keep_days)}' DAY"
    )
    rows = conn.execute(
        "SELECT OBJECT_NAME AS NAME FROM SYS.EXA_ALL_OBJECTS "
        "WHERE ROOT_NAME = {schema} AND OBJECT_TYPE = 'TABLE' "
        f"AND OBJECT_NAME LIKE {{pattern}} ESCAPE '@'{cutoff} ORDER BY CREATED",
        {"schema": SCHEMA, "pattern": f"{PREFIX[:-1]}@_%"},
    ).fetchall()

    dropped = []
    for r in rows:
        name = r["NAME"]
        if not dry_run:
            conn.execute(f"DROP TABLE {SCHEMA}.{name}")
        dropped.append(name)
    return dropped


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m airlock.snapshots",
        description="List or age out the pre-image snapshots behind write rollbacks.")
    parser.add_argument("--prune", action="store_true",
                        help="drop snapshots instead of listing them")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--older-than", type=int, metavar="DAYS",
                       default=DEFAULT_KEEP_DAYS,
                       help=f"with --prune, age to keep (default {DEFAULT_KEEP_DAYS})")
    group.add_argument("--all", action="store_true",
                       help="with --prune, drop every snapshot regardless of age")
    parser.add_argument("--dry-run", action="store_true",
                        help="with --prune, say what would go and drop nothing")
    args = parser.parse_args()

    from .db import connect
    conn = connect()

    if not args.prune:
        found = listing(conn)
        if not found:
            print("no snapshots")
            return
        print(f"{len(found)} snapshot(s):\n")
        for s in found:
            owner = (f"decision #{s['seq']} ({s['decision']})" if s["seq"] is not None
                     else "no ledger entry references it")
            count = "unreadable" if s["rows"] is None else f"{s['rows']:,} rows"
            print(f"  {s['name']}  {s['created']}  {count:>14}  {owner}")
        return

    keep = None if args.all else args.older_than
    dropped = prune(conn, keep, dry_run=args.dry_run)
    verb = "would drop" if args.dry_run else "dropped"
    scope = "all ages" if keep is None else f"older than {keep} day(s)"
    if not dropped:
        print(f"nothing to prune ({scope})")
        return
    print(f"{verb} {len(dropped)} snapshot(s), {scope}:")
    for name in dropped:
        print(f"  {SCHEMA}.{name}")


if __name__ == "__main__":
    main()
