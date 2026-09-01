"""The airlock itself: the single governed path from an agent to the data.

    analyse -> policy -> measure blast radius -> re-check -> record -> execute

Nothing reaches the database except through here.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

import pyexasol

from . import ledger, policy, preflight, snapshots
from .catalog import Catalog
from .config import settings
from .statement import Statement


def _needs_group_measurement(features, policies: list[dict]) -> bool:
    """True when some k-anonymity rule applies to this aggregate query."""
    if not features.has_aggregate:
        return False
    return any(p["RULE_KIND"] == "MIN_AGGREGATION" and policy._touches_column(features, p)
               for p in policies)


# The catalog is not where injections live. An agent browsing SYS to find out
# what tables exist is not carrying a payload out of a customer's free text, and
# SCAN_TAINT cannot read a system view anyway -- so a scan is not applicable
# there rather than failed, and must not hold the statement.
SYSTEM_SCHEMAS = ("SYS", "EXA_STATISTICS")


def _wants_taint_scan(features, policies: list[dict]) -> bool:
    """True when a taint rule is in force and this query could carry text out.

    An aggregate returns numbers; there is nothing for an injection to ride out
    on, so there is nothing to scan.
    """
    if features.kind != "SELECT" or features.has_aggregate:
        return False
    return any(p["RULE_KIND"] == "TAINT_BLOCK" for p in policies)


@dataclass
class GatewayResult:
    decision: str
    reason: str
    seq: int
    affected_rows: int | None = None
    min_group: int | None = None
    taint_max: float | None = None
    rows: list[dict[str, Any]] | None = None
    truncated: bool = False
    rollback_sql: str | None = None
    snapshot_table: str | None = None


@dataclass
class Measurements:
    """What AIRLOCK measured about a statement before it decided.

    One value rather than five locals threaded through `submit`, because every
    exit from `submit` has to report all of them and nothing was checking that
    they did. `snapshot_table` was added as the fifth measurement in the commit
    that made rollbacks runnable, and had to be carried to three separate
    `GatewayResult(...)` calls by hand -- one missed would have returned None
    silently. There is one call now.
    """

    affected_rows: int | None = None
    rollback_sql: str | None = None
    snapshot_table: str | None = None
    min_group: int | None = None
    taint_max: float | None = None

    def _result(self, decision, seq: int, *, affected_rows: int | None = None,
                rows: list[dict[str, Any]] | None = None,
                truncated: bool = False) -> GatewayResult:
        return GatewayResult(
            decision=decision.effect, reason=decision.reason_text, seq=seq,
            affected_rows=self.affected_rows if affected_rows is None
            else affected_rows,
            min_group=self.min_group, taint_max=self.taint_max,
            rollback_sql=self.rollback_sql, snapshot_table=self.snapshot_table,
            rows=rows, truncated=truncated)

    def refused(self, decision, seq: int) -> GatewayResult:
        """Policy did not allow it. Nothing ran, and the radius stays the
        measured one -- what the write *would* have touched is the reason."""
        return self._result(decision, seq)

    def wrote(self, decision, seq: int, affected_rows: int | None) -> GatewayResult:
        """A write that ran. Its real row count replaces the measured one."""
        return self._result(decision, seq, affected_rows=affected_rows)

    def returned(self, decision, seq: int, rows: list[dict[str, Any]],
                 truncated: bool) -> GatewayResult:
        """A query that ran and produced a result set."""
        return self._result(decision, seq, rows=rows, truncated=truncated)


class Airlock:
    def __init__(self, conn: pyexasol.ExaConnection, principal: str | None = None,
                 session_id: str | None = None,
                 catalog: Catalog | None = None) -> None:
        self.conn = conn
        self.principal = principal or settings.principal
        self.session_id = session_id or uuid.uuid4().hex
        # Taken rather than made, so a test can answer the catalog's four
        # questions without standing up a database to answer them from.
        self.catalog = catalog or Catalog(conn)
        self._register_session()

    def _register_session(self) -> None:
        existing = self.conn.execute(
            "SELECT SESSION_ID FROM AIRLOCK.AGENT_SESSION WHERE SESSION_ID = {sid}",
            {"sid": self.session_id},
        ).fetchone()
        if existing:
            return
        self.conn.execute(
            "INSERT INTO AIRLOCK.AGENT_SESSION (SESSION_ID, PRINCIPAL) "
            "VALUES ({sid}, {principal})",
            {"sid": self.session_id, "principal": self.principal},
        )

    def submit(self, sql: str, max_rows: int = 200) -> GatewayResult:
        started = time.perf_counter()
        stmt = Statement.parse(sql)
        features = stmt.features
        policies = policy.load_policies(self.conn, self.principal)

        # First pass: everything decidable from the statement alone.
        decision = policy.evaluate(features, policies)

        measured_facts = Measurements()
        if decision.effect != policy.DENY and features.kind in {"UPDATE", "DELETE",
                                                                "INSERT", "MERGE"}:
            (measured_facts.affected_rows, measured_facts.rollback_sql,
             measured_facts.snapshot_table) = self._measure_blast_radius(stmt)
            # Second pass, now that the radius is a measured fact.
            decision = policy.evaluate(features, policies,
                                       affected_rows=measured_facts.affected_rows)
        elif decision.effect != policy.DENY and features.kind == "SELECT":
            measured = False
            # k-anonymity is a claim about group sizes, so measure them rather
            # than trusting that an aggregate is automatically anonymous.
            if _needs_group_measurement(features, policies):
                measured_facts.min_group = self._measure_min_group(stmt)
                measured = True
            # Scan the rows on their way out, not the prompt on the way in.
            if _wants_taint_scan(features, policies):
                measured_facts.taint_max = self._measure_taint(stmt)
                measured = measured_facts.taint_max is not None or measured
            if measured:
                decision = policy.evaluate(features, policies,
                                           min_group=measured_facts.min_group,
                                           taint_max=measured_facts.taint_max)

        # The compensating statement reads from a pre-image, so take it before the
        # write runs -- and only once the verdict is ALLOW, or every refused write
        # would leave a table behind. A capture we cannot take is not a pass: the
        # write is refused rather than executed without an undo, and the refusal
        # goes in the ledger, because an entry that says ALLOW for a statement we
        # then declined to run would be the same lie in a different place.
        if decision.effect == policy.ALLOW and measured_facts.snapshot_table:
            failure = self._capture_pre_image(stmt, measured_facts.snapshot_table)
            if failure is not None:
                measured_facts.snapshot_table = None
                decision.effect = policy.DENY
                decision.reasons.append(failure)

        elapsed = (time.perf_counter() - started) * 1000
        entry = ledger.append(
            self.conn,
            session_id=self.session_id,
            principal=self.principal,
            stmt_kind=features.kind,
            statement=sql,
            features_json=features.to_json(),
            decision=decision.effect,
            matched_policies=decision.matched_csv,
            reason=decision.reason_text,
            est_rows=measured_facts.affected_rows,
            min_group=measured_facts.min_group,
            rollback_sql=measured_facts.rollback_sql,
            taint_max=measured_facts.taint_max,
            latency_ms=elapsed,
        )

        if decision.effect != policy.ALLOW:
            return measured_facts.refused(decision, entry.seq)

        cursor = self.conn.execute(sql)

        # Only queries produce a result set; a write reports its row count.
        if features.kind != "SELECT":
            return measured_facts.wrote(decision, entry.seq, cursor.rowcount())

        rows = cursor.fetchmany(max_rows + 1)
        truncated = len(rows) > max_rows
        return measured_facts.returned(decision, entry.seq, rows[:max_rows], truncated)

    def _text_columns(self, stmt: Statement) -> tuple[list[str], bool]:
        """The free-text columns this query would return, and whether we know.

        The second element is False when the query's shape means we cannot tell
        what text it returns. An empty list with False is "could not be
        determined", which holds the statement; an empty list with True is
        "nothing text-bearing comes back", which does not.

        Resolved from the catalog rather than a hardcoded list, so a new table
        needs no change here. A `SELECT *` returns all of them; anything else
        returns only what it names.

        Which tables to ask about come out of the agent's own statement, so the
        binding that keeps a quoted table name from rewriting the predicate is
        the catalog's job, not this one's.
        """
        features = stmt.features
        targets = [t for t in features.tables
                   if "." in t and t.split(".", 1)[0] not in SYSTEM_SCHEMAS]
        if not targets:
            return [], True
        derived = stmt.reads_derived_source
        available = []
        for column in self.catalog.text_columns(tables=targets):
            if column.name not in available:
                available.append(column.name)
        named = [c for c in available if c in features.columns]
        if not features.select_star:
            return named, True
        if not derived:
            return available, True
        # A `*` over a CTE or subquery: the catalog knows the base table's text
        # columns, not which the derived source passes through. Fall back to the
        # ones the statement names -- and if it names none, say so rather than
        # scan nothing and call the result clean.
        return named, bool(named)

    def _measure_taint(self, stmt: Statement) -> float | None:
        """The worst taint score in what this query would return.

        Three outcomes, and the difference between the last two is the whole
        point: None means no scan applied -- nothing text-bearing comes back.
        policy.TAINT_UNMEASURED means a scan applied and could not be taken,
        which holds the statement rather than letting it through. Anything else
        is a real score.

        The sentinel travels in the ledger's TAINT_MAX alongside real scores, so
        replay re-decides an unmeasurable statement exactly the way the gateway
        did rather than having to guess at a state the ledger never stored.
        """
        columns, resolvable = self._text_columns(stmt)
        if not columns:
            return None if resolvable else policy.TAINT_UNMEASURED

        probe = preflight.build_taint_probe(stmt, columns)
        if probe is None:
            return policy.TAINT_UNMEASURED
        try:
            row = self.conn.execute(probe).fetchone()
        except Exception:  # noqa: BLE001 - a scan we could not take is not a pass
            return policy.TAINT_UNMEASURED
        if not row:
            return policy.TAINT_UNMEASURED
        value = next(iter(row.values()))
        # MAX over an empty result set is NULL: the query returns no rows, so
        # there is no text in it to be tainted.
        return float(value) if value is not None else 0.0

    def _measure_min_group(self, stmt: Statement) -> int | None:
        probe = preflight.build_group_probe(stmt)
        if probe is None:
            return None
        try:
            row = self.conn.execute(probe).fetchone()
        except Exception:
            return None
        if not row:
            return None
        value = next(iter(row.values()))
        return int(value) if value is not None else None

    def _measure_blast_radius(
            self, stmt: Statement) -> tuple[int | None, str | None, str | None]:
        """Measured row count, the compensating statement, and the pre-image it needs.

        The third element is the snapshot table to capture, and it is only a name
        when the compensating statement actually reads from one. An INSERT has no
        pre-image, and a target with no usable key gets a rollback that explains
        itself instead of a runnable statement -- in both cases there is nothing
        to capture, and returning None here is what keeps `submit` from creating
        a table nothing will ever read.
        """
        probe = preflight.build_probe(stmt)
        if probe is None:
            return None, None, None
        try:
            row = self.conn.execute(probe).fetchone()
            affected = int(next(iter(row.values()))) if row else None
        except Exception:
            return None, None, None
        snapshot = snapshots.new_name()
        rollback = preflight.build_rollback(
            stmt, snapshot,
            key_columns=self.catalog.primary_key(stmt.target_table))
        needed = snapshot if rollback and snapshot in rollback else None
        return affected, rollback, needed

    def _capture_pre_image(self, stmt: Statement, snapshot: str) -> str | None:
        """Copy the rows a write is about to change. None on success, else why not.

        The CTAS carries the write's own predicate, so the snapshot holds exactly
        the rows the compensating statement will read back -- not the whole table.
        """
        ctas = preflight.snapshot_sql(stmt, snapshot)
        if ctas is None:
            # build_rollback named a snapshot for a statement snapshot_sql will
            # not capture. That is a bug in one of the two rather than a runtime
            # condition, and refusing the write is how it surfaces.
            return (f"pre-image snapshot: no capture could be built for a "
                    f"{stmt.kind} whose rollback reads from {snapshot}")
        try:
            self.conn.execute(ctas)
        except Exception as exc:  # noqa: BLE001 - the reason belongs in the ledger
            first = str(exc).strip().splitlines()[0][:200]
            return f"pre-image snapshot into {snapshot} failed: {first}"
        return None
