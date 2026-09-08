"""Releasing a held statement, and the two things a release must never do.

REQUIRE_APPROVAL was inert: the engine could hold a statement and nothing could
let one through. What is pinned here is that releasing one goes back through the
gateway rather than around it, and that an approval answers a hold without
answering a prohibition.

The policy half needs nothing but the pure function. The gateway half uses a
fake connection, because what matters is which statements AIRLOCK issues -- one
ledger entry per attempt, never an edit of the first -- not what Exasol replies.
"""
import pytest

from airlock import policy
from airlock.analyze import analyze
from airlock.approval import APPROVED, PENDING, REJECTED, approve, get, pending, reject
from airlock.gateway import Airlock, Approval
from airlock.policy import ALLOW, DENY, REQUIRE_APPROVAL, evaluate
from tests.fakes import FakeCatalog

CUSTOMER_UPDATE = "UPDATE TPCH.CUSTOMER SET C_COMMENT = 'x' WHERE C_ACCTBAL > 0"


def rule(**kw):
    base = {"POLICY_ID": 1, "NAME": "p", "RULE_KIND": "COLUMN_ACCESS", "EFFECT": DENY,
            "TARGET_SCHEMA": None, "TARGET_TABLE": None, "TARGET_COLUMN": None,
            "PRINCIPAL": None, "THRESHOLD": None, "NOTE": None}
    base.update(kw)
    return base


HOLD_BIG_WRITES = rule(POLICY_ID=4, NAME="blast-radius", RULE_KIND="BLAST_RADIUS",
                       EFFECT=REQUIRE_APPROVAL, THRESHOLD=100)
NO_COMMENT = rule(POLICY_ID=2, NAME="pii-comment", TARGET_SCHEMA="TPCH",
                  TARGET_TABLE="CUSTOMER", TARGET_COLUMN="C_COMMENT", EFFECT=DENY)


# --------------------------------------------------------------------------
# what an approval means to the policy engine
# --------------------------------------------------------------------------

def test_approval_releases_a_hold():
    features = analyze(CUSTOMER_UPDATE)
    held = evaluate(features, [HOLD_BIG_WRITES], affected_rows=2729)
    released = evaluate(features, [HOLD_BIG_WRITES], affected_rows=2729, approved=True)
    assert held.effect == REQUIRE_APPROVAL
    assert released.effect == ALLOW


def test_approval_does_not_release_a_deny():
    """An approver is answering a hold, not overruling a prohibition. A
    statement that was held *and* denied is still denied afterwards."""
    features = analyze(CUSTOMER_UPDATE)
    d = evaluate(features, [HOLD_BIG_WRITES, NO_COMMENT],
                 affected_rows=2729, approved=True)
    assert d.effect == DENY
    assert "pii-comment" in d.reason_text


def test_an_unmeasurable_fact_is_a_hold_and_is_releasable_too():
    """The three branches that raise REQUIRE_APPROVAL as a literal rather than
    from a policy row's EFFECT go through the same demotion."""
    features = analyze(CUSTOMER_UPDATE)
    held = evaluate(features, [HOLD_BIG_WRITES], affected_rows=None)
    released = evaluate(features, [HOLD_BIG_WRITES], affected_rows=None, approved=True)
    assert held.effect == REQUIRE_APPROVAL
    assert released.effect == ALLOW
    assert "could not be measured" in released.reason_text


def test_the_reason_survives_the_demotion():
    """An approved entry still records which rules held it. What changed is
    that a human answered them, not that they stopped applying."""
    d = evaluate(analyze(CUSTOMER_UPDATE), [HOLD_BIG_WRITES],
                 affected_rows=2729, approved=True)
    assert "would modify 2729 rows" in d.reason_text
    assert d.matched == [4]


def test_an_approval_carries_who_gave_it():
    assert Approval(12, "alice").provenance == "approved: approval #12 by alice"


# --------------------------------------------------------------------------
# the fake database
# --------------------------------------------------------------------------

class FakeConn:
    """Answers by query shape and remembers everything it was asked.

    It holds one APPROVAL row so a release can be followed end to end: the
    gateway raises it, `approve` reads it back, and the UPDATE that closes it is
    visible in `statements` rather than inferred.
    """

    def __init__(self, *, affected=2729, policies=(), row=None):
        self.affected = affected
        self.policies = list(policies)
        self.row = row
        self.statements: list[str] = []
        self.calls: list[tuple[str, dict | None]] = []
        self.ledger_seq = 411
        self._answer = None

    def execute(self, query, params=None):
        self.statements.append(query)
        self.calls.append((query, params))
        upper = " ".join(query.split()).upper()
        if "FROM AIRLOCK.APPROVAL A" in upper:
            self._answer = [self.row] if self.row else []
        elif upper.startswith("UPDATE AIRLOCK.APPROVAL"):
            self.row = dict(self.row, APPROVAL_STATE=params["state"],
                            DECIDED_BY=params["by"], DECIDED_AT="2026-09-08 10:00:00",
                            NOTE=params["note"], RESULT_SEQ=params["result_seq"])
            self._answer = []
        elif "FROM AIRLOCK.POLICY" in upper:
            self._answer = list(self.policies)
        elif "FROM AIRLOCK.AGENT_SESSION" in upper:
            self._answer = [{"SESSION_ID": "held-session"}]
        elif "FROM AIRLOCK.LEDGER ORDER BY SEQ" in upper:
            self._answer = [{"SEQ": self.ledger_seq, "ENTRY_HASH": "a" * 64}]
        elif upper.startswith("INSERT INTO AIRLOCK.LEDGER"):
            self.ledger_seq += 1
            self._answer = []
        elif upper.startswith("SELECT COUNT(*)"):
            self._answer = [{"N": self.affected}]
        elif "SYSTIMESTAMP" in upper:
            self._answer = [{"T": "2026-09-08 10:00:00.000000"}]
        else:
            self._answer = []
        return self

    def fetchall(self):
        return self._answer

    def fetchone(self):
        return self._answer[0] if self._answer else None

    def fetchmany(self, n):
        return self._answer[:n]

    def rowcount(self):
        return self.affected

    def issued(self, needle):
        return [s for s in self.statements if needle in s]

    def ledger_entries(self):
        return [p for q, p in self.calls if "INSERT INTO AIRLOCK.LEDGER" in q]


def held_row(**kw):
    base = {"APPROVAL_ID": 1, "LEDGER_SEQ": 411, "APPROVAL_STATE": PENDING,
            "REQUESTED_AT": "2026-09-08 09:00:00", "DECIDED_BY": None,
            "DECIDED_AT": None, "NOTE": None, "RESULT_SEQ": None,
            "PRINCIPAL": "demo-agent", "SESSION_ID": "held-session",
            "STMT_KIND": "UPDATE", "STMT_TEXT": CUSTOMER_UPDATE,
            "REASON": "blast-radius: would modify 2729 rows, cap is 100",
            "EST_ROWS": 2729}
    base.update(kw)
    return base


def _gateway(conn):
    """An Airlock without __init__: constructing one registers a session."""
    gate = Airlock.__new__(Airlock)
    gate.conn = conn
    gate.principal = "demo-agent"
    gate.session_id = "held-session"
    gate.catalog = FakeCatalog(keys={"TPCH.CUSTOMER": ["C_CUSTKEY"]})
    return gate


# --------------------------------------------------------------------------
# raising the hold
# --------------------------------------------------------------------------

def test_a_held_statement_lands_on_the_queue():
    conn = FakeConn(policies=[HOLD_BIG_WRITES])
    result = _gateway(conn).submit(CUSTOMER_UPDATE)
    assert result.decision == REQUIRE_APPROVAL
    queued = conn.issued("INSERT INTO AIRLOCK.APPROVAL")
    assert len(queued) == 1
    assert conn.calls[[q for q, _ in conn.calls].index(queued[0])][1] == {"seq": 412}


def test_a_denied_statement_is_not_queued():
    """A queue that filled up with statements no approver may release would
    make the one that matters unfindable."""
    conn = FakeConn(policies=[NO_COMMENT])
    result = _gateway(conn).submit(CUSTOMER_UPDATE)
    assert result.decision == DENY
    assert conn.issued("INSERT INTO AIRLOCK.APPROVAL") == []


def test_an_allowed_statement_is_not_queued():
    conn = FakeConn(affected=3, policies=[HOLD_BIG_WRITES])
    result = _gateway(conn).submit(CUSTOMER_UPDATE)
    assert result.decision == ALLOW
    assert conn.issued("INSERT INTO AIRLOCK.APPROVAL") == []


# --------------------------------------------------------------------------
# releasing it
# --------------------------------------------------------------------------

def test_the_release_is_a_second_ledger_entry_and_the_held_one_is_untouched():
    """Rewriting the held entry to say ALLOW would ask the hash chain to vouch
    for a record it had itself been changed to agree with."""
    conn = FakeConn(policies=[HOLD_BIG_WRITES], row=held_row())
    result = approve(conn, 1, "alice")
    assert result.decision == ALLOW
    assert result.seq == 412
    assert len(conn.ledger_entries()) == 1
    assert conn.issued("UPDATE AIRLOCK.LEDGER") == []
    assert conn.issued("DELETE FROM AIRLOCK.LEDGER") == []


def test_the_release_runs_the_statement_through_the_gateway():
    """Not around it: the pre-image capture is gated on the verdict, so a
    statement executed directly by the approver would have no undo."""
    conn = FakeConn(policies=[HOLD_BIG_WRITES], row=held_row())
    result = approve(conn, 1, "alice")
    assert conn.issued("CREATE TABLE AIRLOCK_SNAP.SNAP_")
    # The undo reads the rows back out of the pre-image the release captured.
    assert result.snapshot_table in result.rollback_sql
    assert conn.statements.index(CUSTOMER_UPDATE) > 0


def test_the_release_records_who_approved_it_in_the_hashed_reason():
    conn = FakeConn(policies=[HOLD_BIG_WRITES], row=held_row())
    approve(conn, 1, "alice")
    entry = conn.ledger_entries()[0]
    assert "approved: approval #1 by alice" in entry["reason"]
    assert "would modify 2729 rows" in entry["reason"]


def test_the_queue_row_closes_pointing_at_the_entry_the_release_produced():
    conn = FakeConn(policies=[HOLD_BIG_WRITES], row=held_row())
    result = approve(conn, 1, "alice")
    closed = get(conn, 1)
    assert closed.state == APPROVED
    assert closed.decided_by == "alice"
    assert closed.result_seq == result.seq


def test_the_release_stays_in_the_session_the_hold_came_from():
    """Two halves of one decision in two sessions would split the console's
    session view down the middle of the story it is telling."""
    conn = FakeConn(policies=[HOLD_BIG_WRITES], row=held_row())
    approve(conn, 1, "alice")
    assert conn.ledger_entries()[0]["session_id"] == "held-session"
    assert conn.issued("INSERT INTO AIRLOCK.AGENT_SESSION") == []


def test_a_release_that_is_still_denied_is_recorded_as_approved_and_refused():
    """The approver answered the question they were asked. The second refusal
    is the ledger answering a different one."""
    conn = FakeConn(policies=[HOLD_BIG_WRITES, NO_COMMENT], row=held_row())
    result = approve(conn, 1, "alice")
    assert result.decision == DENY
    assert get(conn, 1).state == APPROVED
    assert CUSTOMER_UPDATE not in conn.statements[1:]


def test_a_release_is_not_queued_again():
    """It cannot be: every hold on it was demoted, so there is no hold left to
    raise -- and a queue that regrew a row per release would never empty."""
    conn = FakeConn(policies=[HOLD_BIG_WRITES], row=held_row())
    approve(conn, 1, "alice")
    assert conn.issued("INSERT INTO AIRLOCK.APPROVAL") == []


# --------------------------------------------------------------------------
# refusing it
# --------------------------------------------------------------------------

def test_a_rejection_runs_nothing_and_writes_no_ledger_entry():
    """The hold is already in the ledger, recorded when it was raised. A
    rejection changes nothing about what the airlock did."""
    conn = FakeConn(policies=[HOLD_BIG_WRITES], row=held_row())
    closed = reject(conn, 1, "alice", note="not this quarter")
    assert closed.state == REJECTED
    assert closed.note == "not this quarter"
    assert closed.result_seq is None
    assert conn.ledger_entries() == []
    assert CUSTOMER_UPDATE not in conn.statements


def test_a_decision_is_made_once():
    conn = FakeConn(policies=[HOLD_BIG_WRITES], row=held_row())
    reject(conn, 1, "alice")
    with pytest.raises(ValueError, match="already REJECTED"):
        approve(conn, 1, "bob")


def test_approving_something_that_was_never_held_is_an_error():
    with pytest.raises(LookupError):
        approve(FakeConn(), 99, "alice")


def test_the_queue_reads_back_what_was_held_and_why():
    conn = FakeConn(row=held_row())
    queue = pending(conn)
    assert len(queue) == 1
    assert queue[0].est_rows == 2729
    assert queue[0].stmt_kind == "UPDATE"
    assert "cap is 100" in queue[0].reason
    assert queue[0].state == PENDING


def test_policy_is_not_consulted_by_the_queue():
    """Reading the queue must not be able to run anything."""
    conn = FakeConn(row=held_row())
    pending(conn)
    assert conn.issued("FROM AIRLOCK.POLICY") == []
    assert policy.REQUIRE_APPROVAL == "REQUIRE_APPROVAL"
