"""Every connection Exasol has, and which of them came through the airlock.

A governance layer that only sees its own traffic is grading its own homework.
The interesting question is not what the gateway allowed -- the ledger answers
that completely -- but whether anything reached the data without asking.

Exasol Personal cannot answer it historically. EXA_DBA_AUDIT_SQL,
EXA_DBA_AUDIT_SESSIONS and every EXA_SQL_* statistics view are listed in
SYS.EXA_SYSCAT and error with "object not found" when queried, so the first
instinct -- reconcile the ledger against the database's own audit log and find
the statements that were never recorded -- has nothing to reconcile against.

What does work is EXA_ALL_SESSIONS, which is live. So the question becomes
present tense: who is connected right now, and did we let them in. The gateway
writes Exasol's session id beside its own when it registers, and a live session
with no matching row is a connection that reached the database without passing
through the airlock.

Be clear about what this is. It **detects**; it does not prevent. Someone
holding sys credentials can still open a session, and this panel will show it
rather than stop it. What the privilege boundary in sql/40_identities.sql
removes is the ability to do anything useful once inside; what this removes is
the ability to do it unseen.
"""
from __future__ import annotations

from dataclasses import dataclass

import pyexasol

from .config import settings

# Came through the airlock: the gateway registered this session and every
# statement on it is in the ledger.
GOVERNED = "governed"
# The read-only console identity, watching. It holds no write grant at all.
CONSOLE = "console"
# Exasol's own housekeeping. LogServer is connected on an idle database and has
# nothing to do with an agent; flagging it would make the panel cry wolf from
# the moment it loads, and a monitor nobody believes is worse than none.
INTERNAL = "internal"
# Reached the database without asking us. This is the one that matters.
UNGOVERNED = "ungoverned"

_INTERNAL_CLIENTS = ("LogServer",)


@dataclass(frozen=True)
class LiveSession:
    """One live Exasol connection, and what AIRLOCK knows about it."""

    session_id: str
    user_name: str
    status: str
    command: str
    client: str
    driver: str
    login_time: str
    duration: str
    encrypted: bool
    principal: str | None
    airlock_session_id: str | None
    kind: str

    @property
    def ungoverned(self) -> bool:
        return self.kind == UNGOVERNED


def classify(user_name: str, client: str, governed: bool) -> str:
    """Which class a live connection falls into.

    A pure function rather than a CASE expression in the query, and the reason
    is the same one that put FakeCatalog behind the catalog: a rule embedded in
    SQL can only be tested by standing up a database and arranging for the
    condition to be true, and the conditions worth testing here -- a rogue
    connection, an internal one, the precedence between them -- are exactly the
    ones that are awkward to arrange on demand.

    The join stays in the database, because both sides of it are tables there.
    Only the verdict comes back to Python.

    Order matters. A registered session is governed whatever it connected as, so
    the join result is tested before any name or client is.
    """
    if governed:
        return GOVERNED
    if user_name.upper() == settings.console_user.upper():
        return CONSOLE
    if client in _INTERNAL_CLIENTS:
        return INTERNAL
    return UNGOVERNED


_QUERY = """
    SELECT s.SESSION_ID, s.USER_NAME, s.STATUS, s.COMMAND_NAME,
           s.CLIENT, s.DRIVER, s.LOGIN_TIME, s.DURATION, s.ENCRYPTED,
           a.PRINCIPAL, a.SESSION_ID AS AIRLOCK_SESSION_ID
    FROM SYS.EXA_ALL_SESSIONS s
    LEFT JOIN AIRLOCK.AGENT_SESSION a ON a.EXA_SESSION_ID = s.SESSION_ID
    ORDER BY s.LOGIN_TIME DESC
"""


def live(conn: pyexasol.ExaConnection) -> list[LiveSession]:
    """Every live connection, ungoverned ones first.

    Ordered that way because the panel is read at a glance on camera, and the
    answer to "is anything going around us" should not require scrolling.

    Read from EXA_ALL_SESSIONS, never EXA_DBA_SESSIONS: the DBA view needs
    SELECT ANY DICTIONARY, and nothing in AIRLOCK holds it. EXA_ALL_SESSIONS
    turns out to show every session to any user, so the console can answer this
    while holding no privilege beyond SELECT on its own schema.
    """
    found = []
    for r in conn.execute(_QUERY).fetchall():
        client = (r["CLIENT"] or "").strip()
        user_name = r["USER_NAME"] or ""
        found.append(LiveSession(
            session_id=str(r["SESSION_ID"]),
            user_name=user_name,
            status=r["STATUS"] or "",
            command=r["COMMAND_NAME"] or "",
            client=client,
            driver=(r["DRIVER"] or "").strip(),
            login_time=str(r["LOGIN_TIME"] or ""),
            duration=str(r["DURATION"] or ""),
            encrypted=bool(r["ENCRYPTED"]),
            principal=r["PRINCIPAL"],
            airlock_session_id=r["AIRLOCK_SESSION_ID"],
            kind=classify(user_name, client,
                          governed=r["AIRLOCK_SESSION_ID"] is not None),
        ))
    # Stable: the query already ordered by login time, so this only lifts the
    # ungoverned rows to the top without disturbing the rest.
    found.sort(key=lambda s: not s.ungoverned)
    return found


def ungoverned_count(conn: pyexasol.ExaConnection) -> int:
    """How many live connections did not come through the airlock."""
    return sum(1 for s in live(conn) if s.ungoverned)


def main() -> None:
    from .db import connect_console

    found = live(connect_console())
    if not found:
        print("no live sessions")
        return
    rogue = sum(1 for s in found if s.ungoverned)
    print(f"{len(found)} live session(s), {rogue} ungoverned:\n")
    for s in found:
        who = f"{s.principal}" if s.principal else s.user_name
        print(f"  {s.kind:<11} {s.session_id:>20}  {who:<14} "
              f"{s.client:<18} {s.status}")


if __name__ == "__main__":
    main()
