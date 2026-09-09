"""The rules desk: a third door, on a third port, behind a token.

Deliberately not part of the console or the approval desk. Adding or disabling
a POLICY row writes to the rules that bind every statement the gateway
decides, so it runs as its own identity -- AIRLOCK_RULES, not AIRLOCK_SVC. The
gateway must never hold write access to the rules that constrain it; see
sql/40_identities.sql.

    uv run airlock-rules        # http://127.0.0.1:8002

Authentication is one bearer token, read from AIRLOCK_RULES_TOKEN, and if that
is unset a fresh one is generated and printed at startup -- the same demo
boundary as the approval desk, not a credential system.
"""
from __future__ import annotations

import os
import secrets
import threading

import pyexasol
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from . import policy
from .config import settings
from .db import connect_rules

app = FastAPI(title="AIRLOCK rules", version="0.1.0",
              description="Add or disable AIRLOCK.POLICY rows.")

_TOKEN = os.getenv("AIRLOCK_RULES_TOKEN") or secrets.token_urlsafe(24)

# Same reasoning as the console and approval desk: one connection, serialised,
# because pyexasol is not thread-safe and one operator does not need a pool.
_lock = threading.Lock()
_conn: pyexasol.ExaConnection | None = None


def _db() -> pyexasol.ExaConnection:
    global _conn
    if _conn is not None:
        try:
            _conn.execute("SELECT 1")
            return _conn
        except Exception:  # noqa: BLE001 - any dead socket, reconnect and retry
            _conn = None
    _conn = connect_rules()
    return _conn


def _authorise(authorization: str = Header(default="")) -> None:
    """Bearer token or nothing. Compared in constant time out of habit."""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(token, _TOKEN):
        raise HTTPException(status_code=401, detail="rules token required")


class NewRule(BaseModel):
    """What add_rule() needs. Validated again in policy.py, not just here --
    the desk is not the only caller that will ever exist."""

    name: str
    rule_kind: str
    effect: str
    target_schema: str | None = None
    target_table: str | None = None
    target_column: str | None = None
    principal: str | None = None
    threshold: float | None = None
    note: str | None = None


@app.get("/rules", dependencies=[Depends(_authorise)])
def rules() -> list[dict]:
    with _lock:
        return policy.list_all(_db())


@app.post("/rules", dependencies=[Depends(_authorise)])
def add(rule: NewRule) -> dict:
    try:
        with _lock:
            policy_id = policy.add_rule(_db(), **rule.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"policy_id": policy_id}


@app.post("/rules/{policy_id}/disable", dependencies=[Depends(_authorise)])
def disable(policy_id: int) -> dict:
    with _lock:
        found = policy.disable_rule(_db(), policy_id)
    if not found:
        raise HTTPException(status_code=404, detail=f"no policy #{policy_id}")
    return {"policy_id": policy_id, "disabled": True}


def main() -> None:
    import uvicorn

    host = os.getenv("AIRLOCK_RULES_HOST", "127.0.0.1")
    port = int(os.getenv("AIRLOCK_RULES_PORT", "8002"))
    print(f"AIRLOCK rules -> http://{host}:{port}  "
          f"(as {settings.rules_user} on {settings.dsn})")
    if not os.getenv("AIRLOCK_RULES_TOKEN"):
        print(f"  generated token: {_TOKEN}")
        print("  export AIRLOCK_RULES_TOKEN=... to keep one across restarts")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
