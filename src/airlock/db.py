"""Thin pyexasol wrapper. One connection per agent session."""
from __future__ import annotations

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
