"""Adding and disabling POLICY rows.

A malformed rule does not error against the schema -- it inserts fine and then
never matches in evaluate(), which is a worse failure than a rejection at the
seam, and a worse moment to discover it than while writing the test. Nothing
here touches a database: what matters is which statements add_rule/disable_rule
issue, not what Exasol replies.
"""
import pytest

from airlock import policy
from airlock.policy import ALLOW, DENY, REQUIRE_APPROVAL


class FakeConn:
    """Records every statement. INSERT hands back a fixed next id, matching
    the NAME lookup add_rule() runs immediately after."""

    def __init__(self, *, next_id=8, update_rowcount=1):
        self._next_id = next_id
        self._update_rowcount = update_rowcount
        self.statements: list[str] = []
        self.calls: list[tuple[str, dict | None]] = []
        self._answer = None

    def execute(self, query, params=None):
        self.statements.append(query)
        self.calls.append((query, params))
        upper = " ".join(query.split()).upper()
        if upper.startswith("SELECT POLICY_ID FROM AIRLOCK.POLICY"):
            self._answer = [{"POLICY_ID": self._next_id}]
        else:
            self._answer = []
        return self

    def fetchall(self):
        return self._answer

    def fetchone(self):
        return self._answer[0] if self._answer else None

    def rowcount(self):
        return self._update_rowcount

    def issued(self, needle):
        return [s for s in self.statements if needle in s]


# --------------------------------------------------------------------------
# validation -- rejecting a rule that could never match
# --------------------------------------------------------------------------

def test_column_access_needs_a_target_column():
    with pytest.raises(ValueError, match="TARGET_COLUMN"):
        policy.add_rule(FakeConn(), name="x", rule_kind="COLUMN_ACCESS", effect=DENY)


def test_min_aggregation_needs_a_target_column_and_a_threshold():
    with pytest.raises(ValueError, match="TARGET_COLUMN"):
        policy.add_rule(FakeConn(), name="x", rule_kind="MIN_AGGREGATION",
                        effect=DENY, threshold=20)
    with pytest.raises(ValueError, match="THRESHOLD"):
        policy.add_rule(FakeConn(), name="x", rule_kind="MIN_AGGREGATION",
                        effect=DENY, target_column="C_ACCTBAL")


def test_blast_radius_needs_a_threshold():
    with pytest.raises(ValueError, match="THRESHOLD"):
        policy.add_rule(FakeConn(), name="x", rule_kind="BLAST_RADIUS",
                        effect=REQUIRE_APPROVAL)


def test_schema_deny_needs_a_target_schema():
    with pytest.raises(ValueError, match="TARGET_SCHEMA"):
        policy.add_rule(FakeConn(), name="x", rule_kind="SCHEMA_DENY", effect=DENY)


def test_schema_scope_must_be_allow():
    """evaluate() composes its allowed set only from EFFECT == ALLOW rows; a
    DENY SCHEMA_SCOPE row inserts fine and is never consulted."""
    with pytest.raises(ValueError, match="ALLOW"):
        policy.add_rule(FakeConn(), name="x", rule_kind="SCHEMA_SCOPE",
                        effect=DENY, target_schema="TPCH")


def test_unknown_rule_kind_is_rejected():
    with pytest.raises(ValueError, match="RULE_KIND"):
        policy.add_rule(FakeConn(), name="x", rule_kind="NOT_A_KIND", effect=DENY)


def test_unknown_effect_is_rejected():
    with pytest.raises(ValueError, match="EFFECT"):
        policy.add_rule(FakeConn(), name="x", rule_kind="SCHEMA_DENY",
                        effect="MAYBE", target_schema="TPCH")


def test_a_valid_rule_of_each_kind_is_accepted():
    conn = FakeConn()
    policy.add_rule(conn, name="a", rule_kind="SCHEMA_DENY", effect=DENY,
                    target_schema="AIRLOCK")
    policy.add_rule(conn, name="b", rule_kind="SCHEMA_SCOPE", effect=ALLOW,
                    target_schema="TPCH")
    policy.add_rule(conn, name="c", rule_kind="TAINT_BLOCK", effect=DENY, threshold=0.7)
    policy.add_rule(conn, name="d", rule_kind="MIN_AGGREGATION", effect=DENY,
                    target_schema="TPCH", target_table="CUSTOMER",
                    target_column="C_ACCTBAL", threshold=20)
    policy.add_rule(conn, name="e", rule_kind="COLUMN_ACCESS", effect=DENY,
                    target_column="C_PHONE")
    policy.add_rule(conn, name="f", rule_kind="BLAST_RADIUS",
                    effect=REQUIRE_APPROVAL, threshold=500)


# --------------------------------------------------------------------------
# the insert itself
# --------------------------------------------------------------------------

def test_add_rule_inserts_and_returns_the_new_id():
    conn = FakeConn(next_id=8)
    policy_id = policy.add_rule(conn, name="no-fax", rule_kind="COLUMN_ACCESS",
                                effect=DENY, target_schema="TPCH",
                                target_table="CUSTOMER", target_column="C_PHONE")
    assert policy_id == 8
    assert conn.issued("INSERT INTO AIRLOCK.POLICY")


def test_add_rule_never_deletes_or_updates_anything():
    conn = FakeConn()
    policy.add_rule(conn, name="a", rule_kind="TAINT_BLOCK", effect=DENY, threshold=0.5)
    assert conn.issued("DELETE") == []
    assert conn.issued("UPDATE") == []


# --------------------------------------------------------------------------
# disabling -- never a delete
# --------------------------------------------------------------------------

def test_disable_rule_flips_is_enabled_not_deletes():
    conn = FakeConn()
    found = policy.disable_rule(conn, 3)
    assert found is True
    assert conn.issued("UPDATE AIRLOCK.POLICY")
    assert conn.calls[-1][1] == {"pid": 3}
    assert conn.issued("DELETE") == []


def test_disable_rule_reports_when_nothing_matched():
    conn = FakeConn(update_rowcount=0)
    assert policy.disable_rule(conn, 999) is False
