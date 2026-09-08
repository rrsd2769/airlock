"""The bypass monitor's classification, and the ordering the panel reads by.

The join lives in the database and is not tested here. What is tested is the
verdict, because the cases that matter -- a rogue connection, Exasol's own
housekeeping, and which of the two wins when both could apply -- are the ones
that are awkward to arrange against a live instance on demand.
"""
from __future__ import annotations

from airlock import sessions
from airlock.config import settings

CONSOLE_USER = settings.console_user


def row(session_id="1", user_name="DEMO_AGENT", client="PyExasol 2.3.2",
        airlock_session_id=None, principal=None, login_time="2026-09-08 09:00:00"):
    return {
        "SESSION_ID": session_id, "USER_NAME": user_name, "STATUS": "IDLE",
        "COMMAND_NAME": "NOT SPECIFIED", "CLIENT": client, "DRIVER": client,
        "LOGIN_TIME": login_time, "DURATION": "00:00:01", "ENCRYPTED": True,
        "PRINCIPAL": principal, "AIRLOCK_SESSION_ID": airlock_session_id,
    }


class FakeConn:
    """Returns whatever rows the test says the join produced."""

    def __init__(self, rows):
        self._rows = rows

    def execute(self, _sql, _params=None):
        rows = self._rows
        return type("Cur", (), {"fetchall": staticmethod(lambda: rows)})()


# -- the four classes ---------------------------------------------------------

def test_a_registered_session_is_governed():
    assert sessions.classify("AIRLOCK_SVC", "PyExasol", governed=True) \
        == sessions.GOVERNED


def test_the_console_identity_is_not_a_bypass():
    assert sessions.classify(CONSOLE_USER, "PyExasol", governed=False) \
        == sessions.CONSOLE


def test_exasols_own_housekeeping_is_not_a_bypass():
    """LogServer is connected on an idle instance. A monitor that flags it
    cries wolf from the moment it loads, and then nobody believes the one
    alarm that matters."""
    assert sessions.classify("SYS", "LogServer", governed=False) \
        == sessions.INTERNAL


def test_anything_else_reached_the_database_without_asking():
    assert sessions.classify("DEMO_AGENT", "PyExasol", governed=False) \
        == sessions.UNGOVERNED
    assert sessions.classify("SYS", "PyExasol", governed=False) \
        == sessions.UNGOVERNED


def test_registration_wins_over_every_other_test():
    """A governed session stays governed whatever it connected as -- otherwise
    the gateway's own connection would reclassify itself the day it started
    reporting a different client string."""
    assert sessions.classify(CONSOLE_USER, "LogServer", governed=True) \
        == sessions.GOVERNED


# -- what live() makes of them ------------------------------------------------

def test_an_unmatched_session_id_is_the_bypass():
    conn = FakeConn([row(airlock_session_id=None)])
    found = sessions.live(conn)
    assert [s.kind for s in found] == [sessions.UNGOVERNED]
    assert found[0].ungoverned


def test_a_matched_session_carries_its_principal_through():
    conn = FakeConn([row(airlock_session_id="abc123", principal="demo-agent")])
    found = sessions.live(conn)
    assert found[0].kind == sessions.GOVERNED
    assert found[0].principal == "demo-agent"


def test_ungoverned_sessions_sort_to_the_top():
    """The panel is read at a glance on camera, so the answer to "is anything
    going around us" must not be below the fold."""
    conn = FakeConn([
        row(session_id="1", user_name=CONSOLE_USER),
        row(session_id="2", user_name="SYS", client="LogServer"),
        row(session_id="3", user_name="DEMO_AGENT"),
    ])
    assert [s.session_id for s in sessions.live(conn)] == ["3", "1", "2"]


def test_the_rest_of_the_order_is_left_alone():
    """The query already ordered by login time; lifting the rogue rows must not
    reshuffle everything underneath them."""
    conn = FakeConn([
        row(session_id="1", user_name=CONSOLE_USER, login_time="2026-09-08 09:00:00"),
        row(session_id="2", user_name="SYS", client="LogServer",
            login_time="2026-09-08 08:00:00"),
    ])
    assert [s.session_id for s in sessions.live(conn)] == ["1", "2"]


def test_an_idle_instance_reports_no_bypass():
    conn = FakeConn([
        row(session_id="1", user_name=CONSOLE_USER),
        row(session_id="2", user_name="SYS", client="LogServer"),
    ])
    assert sessions.ungoverned_count(conn) == 0


def test_a_client_string_is_stripped_before_it_is_matched():
    """EXA_ALL_SESSIONS pads DRIVER and CLIENT; an unstripped 'LogServer '
    would fall through to ungoverned and flag Exasol's own connection."""
    conn = FakeConn([row(user_name="SYS", client="LogServer  ")])
    assert sessions.live(conn)[0].kind == sessions.INTERNAL
