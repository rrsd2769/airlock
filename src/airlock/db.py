"""Thin pyexasol wrapper. One connection per agent session.

Three identities rather than one, because which of them a caller reaches for is
the privilege boundary. `connect()` is the gateway's, and it is the only one on
the agent's path: it can read the rule set and append to the ledger, and Exasol
refuses it everything else. `connect_console()` reads and cannot write anything
at all. `connect_admin()` is sys, and exists for applying DDL and creating the
other two -- nothing an agent submits ever travels on it.

The users and their grants are in sql/40_identities.sql.
"""
from __future__ import annotations

import pyexasol

from .config import settings


def _connect(user: str, password: str, autocommit: bool) -> pyexasol.ExaConnection:
    return pyexasol.connect(
        dsn=settings.dsn,
        user=user,
        password=password,
        websocket_sslopt={"cert_reqs": 0} if not settings.certificate_validation else None,
        autocommit=autocommit,
        fetch_dict=True,
    )


def connect(autocommit: bool = True) -> pyexasol.ExaConnection:
    """The gateway's identity. Least privilege; use this by default."""
    return _connect(settings.user, settings.password, autocommit)


def connect_console(autocommit: bool = True) -> pyexasol.ExaConnection:
    """Read-only. The console API's identity, which holds no write grant."""
    return _connect(settings.console_user, settings.console_password, autocommit)


def connect_admin(autocommit: bool = True) -> pyexasol.ExaConnection:
    """sys. Schema DDL, the taint sweep's whole-schema read, and nothing else."""
    return _connect(settings.admin_user, settings.admin_password, autocommit)
