"""Thin pyexasol wrapper. One connection per agent session."""
from __future__ import annotations

from typing import Any, Sequence

import pyexasol

from .config import settings


def connect(autocommit: bool = True) -> pyexasol.ExaConnection:
    return pyexasol.connect(
        dsn=settings.dsn,
        user=settings.user,
        password=settings.password,
        websocket_sslopt={"cert_reqs": 0} if not settings.certificate_validation else None,
        autocommit=autocommit,
        fetch_dict=True,
    )


def rows(conn: pyexasol.ExaConnection, sql: str, params: Sequence[Any] | None = None) -> list[dict]:
    return conn.execute(sql, params or []).fetchall()


def scalar(conn: pyexasol.ExaConnection, sql: str, params: Sequence[Any] | None = None) -> Any:
    result = conn.execute(sql, params or []).fetchone()
    if result is None:
        return None
    return next(iter(result.values()))
