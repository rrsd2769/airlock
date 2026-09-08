"""The approval desk: a separate door, on a separate port, behind a token.

Deliberately not part of the console. `api.py` is read-only by construction --
every route on it is a SELECT, and that property is what lets the console be
left open on a screen during a demo without being a second way through the
airlock. Releasing a held statement writes to the database and runs agent SQL,
so it does not belong on that surface at any URL.

    uv run airlock-approve        # http://127.0.0.1:8001

Authentication is one bearer token, read from AIRLOCK_APPROVAL_TOKEN, and if
that is unset a fresh one is generated and printed at startup so the desk is
never open by accident. Be clear about what that is: a demo boundary, not a
credential system. There are no accounts, no expiry and no audit of who holds
the token -- `--by` is whatever the caller says it is. What the ledger records
truthfully is that *an* approval released the statement and which one; who was
behind it is only as good as the token.
"""
from __future__ import annotations

import html
import os
import secrets
import threading

import pyexasol
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from . import approval
from .config import settings
from .db import connect

app = FastAPI(title="AIRLOCK approvals", version="0.1.0",
              description="Release or refuse statements the airlock is holding.")

_TOKEN = os.getenv("AIRLOCK_APPROVAL_TOKEN") or secrets.token_urlsafe(24)

# Same reasoning as the console API: pyexasol connections are not thread-safe
# and FastAPI runs sync endpoints in a threadpool. One approver does not need a
# pool, and serialising here also means two approvals of the same hold cannot
# interleave between the state check and the release.
_lock = threading.Lock()
_conn: pyexasol.ExaConnection | None = None


def _db() -> pyexasol.ExaConnection:
    """The gateway's identity, reconnecting if the server dropped the socket.

    AIRLOCK_SVC and not sys: a release re-enters `gateway.submit()`, and it must
    run under exactly the privileges the agent's own traffic runs under. An
    approval that quietly executed as a superuser would let a human wave through
    something Exasol itself refuses.
    """
    global _conn
    if _conn is not None:
        try:
            _conn.execute("SELECT 1")
            return _conn
        except Exception:  # noqa: BLE001 - any dead socket, reconnect and retry
            _conn = None
    _conn = connect()
    return _conn


def _authorise(authorization: str = Header(default="")) -> None:
    """Bearer token or nothing. Compared in constant time out of habit."""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(token, _TOKEN):
        raise HTTPException(status_code=401, detail="approval token required")


class Decided(BaseModel):
    """Who is deciding, and why. `by` is a label, not an identity -- see above."""

    by: str = "operator"
    note: str | None = None


def _as_dict(held: approval.Held) -> dict:
    return {
        "approval_id": held.approval_id, "ledger_seq": held.ledger_seq,
        "state": held.state, "requested_at": held.requested_at,
        "principal": held.principal, "stmt_kind": held.stmt_kind,
        "statement": held.statement, "reason": held.reason,
        "est_rows": held.est_rows, "decided_by": held.decided_by,
        "decided_at": held.decided_at, "note": held.note,
        "result_seq": held.result_seq,
    }


@app.get("/pending", dependencies=[Depends(_authorise)])
def pending() -> dict:
    with _lock:
        queue = approval.pending(_db())
    return {"count": len(queue), "rows": [_as_dict(h) for h in queue]}


@app.get("/approvals", dependencies=[Depends(_authorise)])
def approvals(limit: int = 50) -> dict:
    with _lock:
        queue = approval.recent(_db(), limit=limit)
    return {"count": len(queue), "rows": [_as_dict(h) for h in queue]}


@app.post("/approve/{approval_id}", dependencies=[Depends(_authorise)])
def approve(approval_id: int, req: Decided) -> dict:
    """Release the hold. The statement goes back through the gateway.

    The verdict returned is whatever the airlock made of it the second time,
    and it is not always ALLOW: an approval releases a hold, it does not
    overrule a DENY, and the radius is measured again against the table as it
    is now.
    """
    try:
        with _lock:
            result = approval.approve(_db(), approval_id, req.by, req.note)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "approval_id": approval_id, "decision": result.decision,
        "ledger_seq": result.seq, "reason": result.reason,
        "affected_rows": result.affected_rows,
        "rollback_sql": result.rollback_sql,
        "snapshot_table": result.snapshot_table,
    }


@app.post("/reject/{approval_id}", dependencies=[Depends(_authorise)])
def reject(approval_id: int, req: Decided) -> dict:
    try:
        with _lock:
            held = approval.reject(_db(), approval_id, req.by, req.note)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _as_dict(held)


_PAGE = """<!doctype html>
<title>AIRLOCK approvals</title>
<style>
 body {{ font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
        background: #0d1117; color: #c9d1d9; margin: 0; padding: 28px 32px; }}
 h1 {{ font-size: 15px; letter-spacing: .12em; text-transform: uppercase;
      color: #8b949e; margin: 0 0 4px; font-weight: 600; }}
 p.sub {{ color: #6e7681; margin: 0 0 24px; }}
 .held {{ border: 1px solid #30363d; border-left: 3px solid #d29922;
         border-radius: 6px; padding: 14px 16px; margin-bottom: 14px;
         background: #11161d; }}
 .id {{ color: #d29922; font-weight: 600; }}
 .meta {{ color: #6e7681; }}
 pre {{ white-space: pre-wrap; word-break: break-word; margin: 10px 0;
       color: #e6edf3; }}
 .why {{ color: #d29922; }}
 .cmd {{ color: #58a6ff; }}
 .empty {{ color: #3fb950; }}
</style>
<h1>AIRLOCK &mdash; awaiting approval</h1>
<p class="sub">{count} held statement(s). Releasing one sends it back through
the gateway, where it is measured again, snapshotted, and recorded as a second
ledger entry.</p>
{body}
"""

_HELD = """<div class="held">
 <span class="id">#{approval_id}</span>
 <span class="meta">ledger seq {ledger_seq} &middot; {principal} &middot;
  {stmt_kind} &middot; {rows} &middot; held {requested_at}</span>
 <pre>{statement}</pre>
 <div class="why">held because: {reason}</div>
 <pre class="cmd">curl -X POST localhost:{port}/approve/{approval_id} \\
  -H "Authorization: Bearer $AIRLOCK_APPROVAL_TOKEN" \\
  -H "Content-Type: application/json" -d '{{"by":"alice"}}'</pre>
</div>"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    """The queue, on one page, readable on camera.

    Unauthenticated on purpose and read-only on purpose: it shows what is
    waiting and the command that would release it. Every route that decides
    anything is behind the token.
    """
    with _lock:
        queue = approval.pending(_db())
    port = os.getenv("AIRLOCK_APPROVE_PORT", "8001")
    if not queue:
        body = '<p class="empty">Nothing is waiting. The airlock is holding no statements.</p>'
    else:
        body = "".join(
            _HELD.format(
                approval_id=h.approval_id, ledger_seq=h.ledger_seq,
                principal=html.escape(h.principal),
                stmt_kind=html.escape(h.stmt_kind),
                rows=f"{h.est_rows} rows" if h.est_rows is not None else "unmeasured",
                requested_at=html.escape(h.requested_at),
                statement=html.escape(h.statement.strip()),
                reason=html.escape(h.reason), port=port)
            for h in queue)
    return _PAGE.format(count=len(queue), body=body)


def main() -> None:
    import uvicorn

    host = os.getenv("AIRLOCK_APPROVE_HOST", "127.0.0.1")
    port = int(os.getenv("AIRLOCK_APPROVE_PORT", "8001"))
    print(f"AIRLOCK approvals -> http://{host}:{port}  "
          f"(as {settings.user} on {settings.dsn})")
    if not os.getenv("AIRLOCK_APPROVAL_TOKEN"):
        print(f"  generated token: {_TOKEN}")
        print("  export AIRLOCK_APPROVAL_TOKEN=... to keep one across restarts")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
