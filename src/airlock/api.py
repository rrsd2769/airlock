"""Read-only HTTP surface for the governance console.

Every endpoint here is a SELECT. There is no route that writes to POLICY, none
that appends to LEDGER, and none that executes agent SQL -- the console watches
the airlock, it is not a second door through it. Replay is exposed as a what-if
only (`persist=False`), so opening the console cannot alter the corpus the demo
numbers are drawn from.

    uv run airlock-api        # http://127.0.0.1:8000
"""
from __future__ import annotations

import os
import threading
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pyexasol
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import ledger, policy
from . import replay as replay_mod
from . import sessions as sessions_mod
from .config import settings
from .db import connect_console

CONSOLE_DIR = Path(__file__).resolve().parents[2] / "console"

app = FastAPI(title="AIRLOCK console", version="0.1.0",
              description="Read-only view of the airlock's ledger, policy set and taint inventory.")

# pyexasol connections are not thread-safe and FastAPI runs sync endpoints in a
# threadpool, so the single connection is serialised rather than shared. One
# console viewer issuing analytical scans does not need a pool.
_lock = threading.Lock()
_conn: pyexasol.ExaConnection | None = None


def _db() -> pyexasol.ExaConnection:
    """The shared connection, reconnecting if the server dropped it.

    A console left open overnight outlives its socket; the alternative is every
    endpoint failing until the process restarts.
    """
    global _conn
    if _conn is not None:
        try:
            _conn.execute("SELECT 1")
            return _conn
        except Exception:
            _conn = None
    _conn = connect_console()
    return _conn


def _clean(value: Any) -> Any:
    """Exasol's DECIMAL and TIMESTAMP types are not JSON, so make them JSON.

    DECIMAL(18,0) columns are counts and sequence numbers -- they come back as
    Decimal and must not reach the browser as "411.0000".
    """
    if isinstance(value, Decimal):
        as_float = float(value)
        return int(as_float) if as_float.is_integer() else as_float
    if isinstance(value, (datetime, date)):
        return value.isoformat(sep=" ", timespec="milliseconds") \
            if isinstance(value, datetime) else value.isoformat()
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def _rows(sql: str, params: dict | None = None) -> list[dict]:
    with _lock:
        return _clean(_db().execute(sql, params or {}).fetchall())


def _one(sql: str, params: dict | None = None) -> dict | None:
    with _lock:
        row = _db().execute(sql, params or {}).fetchone()
    return _clean(row) if row else None


@app.get("/api/overview")
def overview() -> dict:
    """The header strip: what the airlock has done and whether the trail holds."""
    counts = _rows("SELECT DECISION, COUNT(*) AS N FROM AIRLOCK.LEDGER "
                   "GROUP BY DECISION")
    by_decision = {r["DECISION"]: r["N"] for r in counts}

    stats = _one(
        """
        SELECT COUNT(*) AS TOTAL,
               COUNT(DISTINCT SESSION_ID) AS SESSIONS,
               COUNT(DISTINCT PRINCIPAL) AS PRINCIPALS,
               CAST(AVG(LATENCY_MS) AS DOUBLE) AS AVG_LATENCY,
               MAX(TS) AS LAST_SEEN,
               COUNT(MIN_GROUP) AS GROUPS_MEASURED,
               -- A negative TAINT_MAX is the sentinel for a scan that applied
               -- but could not be taken. It is not a scanned result set.
               COUNT(CASE WHEN TAINT_MAX >= 0 THEN 1 END) AS TAINT_SCANNED
        FROM AIRLOCK.LEDGER
        """
    ) or {}

    # The audit answers for itself: LEDGER_BREAKS is a query over the chain, so
    # "intact" is recomputed here rather than remembered from the last sweep.
    with _lock:
        breaks = ledger.verify(_db())
    with _lock:
        taint_rows = _db().execute(
            "SELECT COUNT(*) AS N, COUNT(DISTINCT TABLE_NAME || '.' || COLUMN_NAME) AS C, "
            "CAST(MAX(SCORE) AS DOUBLE) AS WORST FROM AIRLOCK.TAINT").fetchone()
    taint_rows = _clean(taint_rows) or {}

    withheld = _one("SELECT COUNT(*) AS N FROM AIRLOCK.LEDGER "
                    "WHERE TAINT_MAX >= 0 AND DECISION <> 'ALLOW'") or {}

    # Live, not historical. Exasol Personal has no SQL audit to reconcile
    # against, so "is anything going around us" is a question about now.
    with _lock:
        ungoverned = sessions_mod.ungoverned_count(_db())

    return {
        "total": stats.get("TOTAL", 0),
        "allow": by_decision.get("ALLOW", 0),
        "deny": by_decision.get("DENY", 0),
        "require_approval": by_decision.get("REQUIRE_APPROVAL", 0),
        "sessions": stats.get("SESSIONS", 0),
        "principals": stats.get("PRINCIPALS", 0),
        "avg_latency_ms": stats.get("AVG_LATENCY"),
        "last_seen": stats.get("LAST_SEEN"),
        "groups_measured": stats.get("GROUPS_MEASURED", 0),
        "taint_scanned": stats.get("TAINT_SCANNED", 0),
        "taint_withheld": withheld.get("N", 0),
        "chain_intact": not breaks,
        "chain_breaks": _clean(breaks),
        "taint_rows": taint_rows.get("N", 0),
        "taint_columns": taint_rows.get("C", 0),
        "taint_worst": taint_rows.get("WORST"),
        "ungoverned": ungoverned,
        "dsn": settings.dsn,
    }


@app.get("/api/ledger")
def ledger_list(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    decision: str | None = None,
    kind: str | None = None,
    q: str | None = None,
) -> dict:
    """The live decision feed, newest first."""
    where = ["1 = 1"]
    params: dict[str, Any] = {}
    if decision:
        where.append("DECISION = {decision}")
        params["decision"] = decision.upper()
    if kind:
        where.append("STMT_KIND = {kind}")
        params["kind"] = kind.upper()
    if q:
        where.append("UPPER(STMT_TEXT) LIKE {q}")
        params["q"] = f"%{q.upper()}%"
    clause = " AND ".join(where)

    total = _one(f"SELECT COUNT(*) AS N FROM AIRLOCK.LEDGER WHERE {clause}", params)

    # LIMIT will not take a bound parameter on Exasol -- it binds as a string and
    # the parser rejects it. Both values are already ints from Query().
    rows = _rows(
        f"""
        SELECT SEQ, TS, PRINCIPAL, STMT_KIND, DECISION, REASON,
               SUBSTR(STMT_TEXT, 1, 400) AS STMT_TEXT,
               EST_ROWS, MIN_GROUP, CAST(TAINT_MAX AS DOUBLE) AS TAINT_MAX,
               CAST(LATENCY_MS AS DOUBLE) AS LATENCY_MS
        FROM AIRLOCK.LEDGER
        WHERE {clause}
        ORDER BY SEQ DESC
        LIMIT {int(limit)} OFFSET {int(offset)}
        """,
        params,
    )
    return {"total": (total or {}).get("N", 0), "rows": rows}


@app.get("/api/ledger/{seq}")
def ledger_entry(seq: int) -> dict:
    """One decision in full, including the hash links either side of it."""
    row = _one(
        """
        SELECT SEQ, TS, SESSION_ID, PRINCIPAL, STMT_KIND, STMT_TEXT, FEATURES,
               DECISION, MATCHED_POLICIES, REASON, EST_ROWS, MIN_GROUP,
               ROLLBACK_SQL, CAST(TAINT_MAX AS DOUBLE) AS TAINT_MAX,
               CAST(LATENCY_MS AS DOUBLE) AS LATENCY_MS, PREV_HASH, ENTRY_HASH
        FROM AIRLOCK.LEDGER WHERE SEQ = {seq}
        """,
        {"seq": seq},
    )
    if not row:
        raise HTTPException(status_code=404, detail=f"no ledger entry {seq}")

    # Name the rules that fired, so the reason text is traceable to policy rows.
    ids = [int(x) for x in (row.get("MATCHED_POLICIES") or "").split(",")
           if x.strip().isdigit()]
    with _lock:
        row["POLICIES"] = _clean(policy.by_ids(_db(), ids))
    return row


@app.get("/api/approvals")
def approvals() -> dict:
    """The approval queue, read-only.

    The console says a statement is waiting and where it can be released; it
    cannot release one. That is the point of this route existing here as a
    SELECT while every deciding route lives on a different port behind a token
    -- see approve_api.py. A console left open on a screen must not be a second
    door through the airlock.

    Keyed by both sequence numbers, because a release is a separate ledger entry
    and the drawer has to be able to say "held, and released as #414" on one and
    "this is the release of #411" on the other.
    """
    rows = _rows(
        """
        SELECT APPROVAL_ID, LEDGER_SEQ, APPROVAL_STATE, REQUESTED_AT,
               DECIDED_BY, DECIDED_AT, NOTE, RESULT_SEQ
        FROM AIRLOCK.APPROVAL ORDER BY APPROVAL_ID DESC
        """
    )
    return {"pending": sum(1 for r in rows if r["APPROVAL_STATE"] == "PENDING"),
            "rows": rows}


@app.get("/api/policies")
def policies() -> list[dict]:
    """The rule set as it stands. The console never writes to this table."""
    with _lock:
        return _clean(policy.list_all(_db()))


@app.get("/api/taint")
def taint_inventory(limit: int = Query(50, ge=1, le=500)) -> dict:
    """What the sweep found sitting in the warehouse, worst first."""
    rows = _rows(
        "SELECT TABLE_NAME, COLUMN_NAME, ROW_KEY, CAST(SCORE AS DOUBLE) AS SCORE, "
        "PATTERNS, SAMPLE FROM AIRLOCK.TAINT "
        f"ORDER BY SCORE DESC, TABLE_NAME LIMIT {int(limit)}")
    by_column = _rows(
        """
        SELECT TABLE_NAME, COLUMN_NAME, COUNT(*) AS N, CAST(MAX(SCORE) AS DOUBLE) AS WORST
        FROM AIRLOCK.TAINT
        GROUP BY TABLE_NAME, COLUMN_NAME
        ORDER BY WORST DESC, N DESC
        """
    )
    return {"rows": rows, "by_column": by_column}


@app.get("/api/sessions")
def sessions() -> list[dict]:
    """Agent sessions with what each one actually got through the airlock."""
    return _rows(
        """
        SELECT s.SESSION_ID, s.PRINCIPAL, s.AGENT_NAME, s.STARTED_AT,
               COUNT(l.SEQ) AS STATEMENTS,
               SUM(CASE WHEN l.DECISION = 'ALLOW' THEN 1 ELSE 0 END) AS ALLOWED,
               SUM(CASE WHEN l.DECISION <> 'ALLOW' THEN 1 ELSE 0 END) AS STOPPED,
               MAX(l.TS) AS LAST_SEEN
        FROM AIRLOCK.AGENT_SESSION s
        LEFT JOIN AIRLOCK.LEDGER l ON l.SESSION_ID = s.SESSION_ID
        GROUP BY s.SESSION_ID, s.PRINCIPAL, s.AGENT_NAME, s.STARTED_AT
        ORDER BY LAST_SEEN DESC NULLS LAST
        """
    )


@app.get("/api/sessions/live")
def live_sessions() -> dict:
    """Every connection Exasol currently has, and which came through us.

    The tab's other table answers "what did the airlock allow"; this one answers
    "what is connected at all". The gap between them is the point.
    """
    with _lock:
        found = sessions_mod.live(_db())
    return {
        "total": len(found),
        "ungoverned": sum(1 for s in found if s.ungoverned),
        "rows": [
            {"session_id": s.session_id, "user_name": s.user_name,
             "status": s.status, "command": s.command, "client": s.client,
             "driver": s.driver, "login_time": s.login_time,
             "duration": s.duration, "encrypted": s.encrypted,
             "principal": s.principal, "kind": s.kind}
            for s in found
        ],
    }


class ReplayRequest(BaseModel):
    """A hypothetical rule set: thresholds to move, policies to drop, rules
    that don't exist yet to preview -- policy.add_rule()'s keyword shape, one
    dict per rule in `add`."""
    sets: dict[str, float] = Field(default_factory=dict)
    disable: list[str] = Field(default_factory=list)
    add: list[dict] = Field(default_factory=list)
    principal: str = "demo-agent"
    limit: int | None = None


@app.post("/api/replay")
def run_replay(req: ReplayRequest) -> dict:
    """Re-decide the whole ledger against an amended rule set.

    Never persisted and never written back to POLICY: the console asks what a
    change would have cost, it does not make the change.
    """
    with _lock:
        conn = _db()
        current = replay_mod.load_policies(conn, req.principal)
        known = {(p["NAME"] or "").lower() for p in current}
        for name in list(req.sets) + list(req.disable):
            if name.lower() not in known:
                raise HTTPException(status_code=400,
                                    detail=f"no such policy: {name}")
        try:
            replay_mod.check_new_rule_names(known, req.add)
            amended = replay_mod.amend(current, thresholds=req.sets,
                                       disable=set(req.disable), add=req.add)
        except (ValueError, KeyError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        diff = replay_mod.replay(conn, req.principal, policies=amended,
                                 limit=req.limit, persist=False)

    before = {(p["NAME"] or "").lower(): p["THRESHOLD"] for p in current}
    return {
        "total": diff.total,
        "changed": diff.changed,
        "newly_blocked": diff.newly_blocked,
        "newly_allowed": diff.newly_allowed,
        "examples": [{"seq": s, "old": o, "new": n, "reason": r}
                     for s, o, n, r in diff.examples],
        "amendments": (
            [{"name": k, "from": _clean(before.get(k.lower())), "to": v}
             for k, v in req.sets.items()]
            + [{"name": d, "from": _clean(before.get(d.lower())), "to": None}
               for d in req.disable]
        ),
        "added": [{"name": r["name"], "rule_kind": r["rule_kind"], "effect": r["effect"]}
                  for r in req.add],
    }


@app.get("/api/verify")
def verify() -> dict:
    """Recompute the hash chain inside the database and report any break."""
    with _lock:
        breaks = _clean(ledger.verify(_db()))
    return {"intact": not breaks, "breaks": breaks}


@app.exception_handler(Exception)
def unhandled(_request, exc: Exception) -> JSONResponse:
    # A dead database should read as a message in the console, not a blank page.
    return JSONResponse(status_code=500, content={"detail": str(exc)})


if CONSOLE_DIR.is_dir():
    # Mounted last so every /api route is matched before the static handler.
    app.mount("/", StaticFiles(directory=CONSOLE_DIR, html=True), name="console")


def main() -> None:
    import uvicorn

    host = os.getenv("AIRLOCK_API_HOST", "127.0.0.1")
    port = int(os.getenv("AIRLOCK_API_PORT", "8000"))
    if not CONSOLE_DIR.is_dir():
        print(f"warning: {CONSOLE_DIR} not found -- API only, no console UI")
    print(f"AIRLOCK console -> http://{host}:{port}  (reading {settings.dsn})")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
