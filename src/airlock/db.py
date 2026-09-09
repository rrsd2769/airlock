"""Thin pyexasol wrapper. One connection per agent session.

Four identities rather than one, because which of them a caller reaches for is
the privilege boundary. `connect()` is the gateway's, and it is the only one on
the agent's path: it can read the rule set and append to the ledger, and Exasol
refuses it everything else. `connect_console()` reads and cannot write anything
at all. `connect_rules()` can write AIRLOCK.POLICY and nothing beyond it -- a
separate identity from the gateway's, so the rules desk's write access is never
also the agent's. `connect_admin()` is sys, and exists for applying DDL and
creating the other three -- nothing an agent submits ever travels on it.

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


def connect_rules(autocommit: bool = True) -> pyexasol.ExaConnection:
    """The rules desk's identity. Writes AIRLOCK.POLICY and nothing else --
    not AIRLOCK_SVC, which must never hold write access to the rules that
    bind it."""
    return _connect(settings.rules_user, settings.rules_password, autocommit)


def connect_admin(autocommit: bool = True) -> pyexasol.ExaConnection:
    """sys. Schema DDL, the taint sweep's whole-schema read, and nothing else."""
    return _connect(settings.admin_user, settings.admin_password, autocommit)
