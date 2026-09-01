"""The pre-image is what makes a rollback more than a nice-looking string.

The compensating statement AIRLOCK records reads from a snapshot of the rows a
write is about to change. If that snapshot is never taken, the statement is a
plausible-looking `MERGE` against a table that does not exist -- which is worse
than no rollback at all, because the ledger claims one.

These pin the three decisions that make the capture trustworthy: it happens
only for writes that will actually run, only when something will read it back,
and a write whose pre-image cannot be captured is refused rather than executed
without an undo.

A fake connection stands in for the database. What is being pinned is which
statements the gateway issues and in what order, not what Exasol replies.
"""
import pytest

from airlock import policy
from airlock.gateway import Airlock, Measurements
from airlock.policy import Decision
from airlock.statement import Statement
from tests.fakes import FakeCatalog

CUSTOMER_UPDATE = "UPDATE TPCH.CUSTOMER SET C_COMMENT = 'x' WHERE C_ACCTBAL > 0"


class FakeConn:
    """Answers by query shape and remembers everything it was asked.

    `fail_on` is a substring: any statement containing it raises, which is how
    a snapshot that cannot be taken is simulated without a database.

    It answers nothing about the catalog -- that is `FakeCatalog`'s job, handed
    to the gateway directly. What is pinned here is which statements AIRLOCK
    issues and in what order, not how the catalog phrases its lookups.
    """

    def __init__(self, *, affected=2729, policies=None, fail_on=None):
        self.affected = affected
        self.policies = policies if policies is not None else []
        self.fail_on = fail_on
        self.statements: list[str] = []
        self.calls: list[tuple[str, dict | None]] = []
        self._answer = None

    def execute(self, query, params=None):
        self.statements.append(query)
        self.calls.append((query, params))
        if self.fail_on and self.fail_on in query:
            raise RuntimeError("object AIRLOCK.SNAP_X already exists")
        upper = " ".join(query.split()).upper()
        if "FROM AIRLOCK.POLICY" in upper:
            self._answer = list(self.policies)
        elif upper.startswith("SELECT COUNT(*)"):
            self._answer = [{"N": self.affected}]
        elif "FROM AIRLOCK.LEDGER ORDER BY SEQ" in upper:
            self._answer = []
        elif "SYSTIMESTAMP" in upper:
            # The ledger's own timestamp, not a catalog lookup.
            self._answer = [{"T": "2026-09-01 12:00:00.000000"}]
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

    def recorded(self):
        """The parameters of the one INSERT into the ledger."""
        entries = [p for q, p in self.calls if "INSERT INTO AIRLOCK.LEDGER" in q]
        assert len(entries) == 1, f"expected one ledger entry, got {len(entries)}"
        return entries[0]


CUSTOMER_KEY = {"TPCH.CUSTOMER": ["C_CUSTKEY"]}


def _gateway(conn, keys=None):
    """An Airlock without __init__: constructing one registers a session."""
    gate = Airlock.__new__(Airlock)
    gate.conn = conn
    gate.principal = "demo-agent"
    gate.session_id = "test-session"
    gate.catalog = FakeCatalog(keys=CUSTOMER_KEY if keys is None else keys)
    return gate


def _blast(conn, sql, keys=None):
    gate = _gateway(conn, keys)
    return gate._measure_blast_radius(Statement.parse(sql))


# --------------------------------------------------------------------------
# which writes need a pre-image at all
# --------------------------------------------------------------------------

def test_an_update_with_a_key_needs_the_snapshot_its_merge_reads_from():
    affected, rollback, snapshot = _blast(FakeConn(), CUSTOMER_UPDATE)
    assert affected == 2729
    assert snapshot is not None
    assert snapshot in rollback


def test_an_insert_needs_no_snapshot_because_it_has_no_pre_image():
    """The rows did not exist to be copied. Naming a snapshot here would leave
    an empty table behind for every insert an agent is allowed to make."""
    _, rollback, snapshot = _blast(
        FakeConn(), "INSERT INTO TPCH.CUSTOMER (C_CUSTKEY) VALUES (1)")
    assert snapshot is None
    assert rollback is None or "SNAP_" not in rollback


def test_a_statement_we_cannot_probe_asks_for_nothing():
    _, rollback, snapshot = _blast(FakeConn(), "SELECT 1")
    assert (rollback, snapshot) == (None, None)


def test_a_keyless_target_still_captures_because_the_rollback_cites_it():
    """Without a key the compensating statement is prose rather than SQL, but it
    tells the reader the pre-image is in that table. Skipping the capture would
    make the explanation itself false."""
    _, rollback, snapshot = _blast(FakeConn(), CUSTOMER_UPDATE, keys={})
    assert snapshot is not None
    assert snapshot in rollback


# --------------------------------------------------------------------------
# taking it
# --------------------------------------------------------------------------

def test_the_capture_carries_the_writes_own_predicate():
    """A snapshot of the whole table would be a different, much more expensive
    promise than the one the rollback makes."""
    conn = FakeConn()
    gate = _gateway(conn)
    assert gate._capture_pre_image(
        Statement.parse(CUSTOMER_UPDATE), "AIRLOCK.SNAP_TEST") is None
    ctas = conn.issued("CREATE TABLE AIRLOCK.SNAP_TEST")
    assert len(ctas) == 1
    assert "C_ACCTBAL > 0" in ctas[0]
    assert "FROM TPCH.CUSTOMER" in ctas[0]


def test_a_capture_that_fails_says_why_instead_of_raising():
    conn = FakeConn(fail_on="CREATE TABLE")
    gate = _gateway(conn)
    failure = gate._capture_pre_image(
        Statement.parse(CUSTOMER_UPDATE), "AIRLOCK.SNAP_TEST")
    assert failure is not None
    assert "AIRLOCK.SNAP_TEST" in failure
    assert "already exists" in failure


# --------------------------------------------------------------------------
# where it sits in submit()
# --------------------------------------------------------------------------

def _submit(conn, sql=CUSTOMER_UPDATE):
    gate = _gateway(conn)
    return gate.submit(sql)


def test_the_snapshot_is_taken_before_the_write_runs():
    """Afterwards it would copy the rows the write already changed, which is not
    a pre-image of anything."""
    conn = FakeConn()
    result = _submit(conn)
    assert result.decision == policy.ALLOW
    order = [i for i, s in enumerate(conn.statements)
             if s.startswith("CREATE TABLE AIRLOCK.SNAP_") or s == CUSTOMER_UPDATE]
    assert len(order) == 2
    assert conn.statements[order[0]].startswith("CREATE TABLE")


def test_a_refused_write_leaves_no_table_behind():
    """Every denied write would otherwise cost a copy of the rows it was not
    allowed to touch."""
    deny = [{"POLICY_ID": 1, "NAME": "no-writes", "RULE_KIND": "COLUMN_ACCESS",
             "EFFECT": "DENY", "TARGET_SCHEMA": "TPCH", "TARGET_TABLE": "CUSTOMER",
             "TARGET_COLUMN": "C_COMMENT", "PRINCIPAL": None, "THRESHOLD": None,
             "NOTE": "no"}]
    conn = FakeConn(policies=deny)
    result = _submit(conn)
    assert result.decision == policy.DENY
    assert conn.issued("CREATE TABLE AIRLOCK.SNAP_") == []


def test_a_write_whose_pre_image_cannot_be_taken_is_refused_not_executed():
    """The alternative is a write that ran with a recorded undo nothing can
    perform -- the exact state this whole mechanism exists to prevent."""
    conn = FakeConn(fail_on="CREATE TABLE")
    result = _submit(conn)
    assert result.decision == policy.DENY
    assert "pre-image snapshot" in result.reason
    assert conn.statements[-1] != CUSTOMER_UPDATE


def test_the_refusal_is_what_goes_in_the_ledger():
    """An entry reading ALLOW for a statement we then declined to run would be
    the same untruth in a different table."""
    conn = FakeConn(fail_on="CREATE TABLE")
    _submit(conn)
    entry = conn.recorded()
    assert entry["decision"] == policy.DENY
    assert "pre-image snapshot" in entry["reason"]


def test_the_ledger_still_records_the_rollback_it_would_have_used():
    """The compensating statement is what the write would have needed. Dropping
    it from a refusal would lose the explanation for why the write was refused."""
    conn = FakeConn(fail_on="CREATE TABLE")
    _submit(conn)
    assert "MERGE INTO TPCH.CUSTOMER" in conn.recorded()["rollback_sql"]


def test_an_allowed_write_records_allow_and_the_measured_radius():
    conn = FakeConn()
    entry = (_submit(conn), conn.recorded())[1]
    assert entry["decision"] == policy.ALLOW
    assert entry["est_rows"] == 2729


def test_a_failed_capture_does_not_leave_a_snapshot_name_on_the_result():
    conn = FakeConn(fail_on="CREATE TABLE")
    assert _submit(conn).snapshot_table is None


def test_a_successful_capture_reports_the_table_it_wrote():
    conn = FakeConn()
    result = _submit(conn)
    assert result.snapshot_table is not None
    assert result.snapshot_table.startswith("AIRLOCK.SNAP_")
    assert result.snapshot_table in result.rollback_sql


@pytest.mark.parametrize("sql", [
    "SELECT C_NAME FROM TPCH.CUSTOMER",
    "INSERT INTO TPCH.CUSTOMER (C_CUSTKEY) VALUES (1)",
])
def test_statements_with_no_pre_image_never_reach_the_capture(sql):
    conn = FakeConn()
    _submit(conn, sql)
    assert conn.issued("CREATE TABLE AIRLOCK.SNAP_") == []



# --------------------------------------------------------------------------
# every exit reports every measurement
# --------------------------------------------------------------------------

MEASURED = Measurements(affected_rows=2729, rollback_sql="MERGE INTO TPCH.CUSTOMER t",
                        snapshot_table="AIRLOCK.SNAP_X", min_group=94, taint_max=0.42)


@pytest.mark.parametrize("exit_", [
    lambda m, d: m.refused(d, 7),
    lambda m, d: m.wrote(d, 7, 2729),
    lambda m, d: m.returned(d, 7, [], False),
], ids=["refused", "wrote", "returned"])
def test_every_exit_from_submit_reports_every_measurement(exit_):
    """These were three `GatewayResult(...)` calls with eight overlapping
    keyword arguments each, and nothing checked that they agreed. A measurement
    left off one of them returned None to the console and the MCP surface with
    no error anywhere."""
    result = exit_(MEASURED, Decision(effect=policy.ALLOW, reasons=["ok"]))
    assert result.affected_rows == 2729
    assert result.min_group == 94
    assert result.taint_max == 0.42
    assert result.rollback_sql == "MERGE INTO TPCH.CUSTOMER t"
    assert result.snapshot_table == "AIRLOCK.SNAP_X"
    assert result.seq == 7
    assert result.decision == policy.ALLOW


def test_a_write_reports_the_rows_it_actually_touched_not_the_estimate():
    """The measured radius is what policy decided on; the row count is what the
    write did. Reporting the estimate after execution would hide a difference
    between them that is worth seeing."""
    result = MEASURED.wrote(Decision(effect=policy.ALLOW), 7, 2731)
    assert result.affected_rows == 2731
