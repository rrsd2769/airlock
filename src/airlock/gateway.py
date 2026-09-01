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

from . import ledger, policy, preflight, taint
from .analyze import analyze
from .config import settings


def _needs_group_measurement(features, policies: list[dict]) -> bool:
    """True when some k-anonymity rule applies to this aggregate query."""
    if not features.has_aggregate:
        return False
    return any(p["RULE_KIND"] == "MIN_AGGREGATION" and policy._touches_column(features, p)
               for p in policies)


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


class Airlock:
    def __init__(self, conn: pyexasol.ExaConnection, principal: str | None = None,
                 session_id: str | None = None) -> None:
        self.conn = conn
        self.principal = principal or settings.principal
        self.session_id = session_id or uuid.uuid4().hex
        self._key_cache: dict[str, list[str]] = {}
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
        features = analyze(sql)
        policies = policy.load_policies(self.conn, self.principal)

        # First pass: everything decidable from the statement alone.
        decision = policy.evaluate(features, policies)

        affected = None
        rollback = None
        min_group = None
        taint_max = None
        if decision.effect != policy.DENY and features.kind in {"UPDATE", "DELETE",
                                                                "INSERT", "MERGE"}:
            affected, rollback = self._measure_blast_radius(sql, features)
            # Second pass, now that the radius is a measured fact.
            decision = policy.evaluate(features, policies, affected_rows=affected)
        elif decision.effect != policy.DENY and features.kind == "SELECT":
            measured = False
            # k-anonymity is a claim about group sizes, so measure them rather
            # than trusting that an aggregate is automatically anonymous.
            if _needs_group_measurement(features, policies):
                min_group = self._measure_min_group(sql)
                measured = True
            # Scan the rows on their way out, not the prompt on the way in.
            if _wants_taint_scan(features, policies):
                taint_max = self._measure_taint(sql, features)
                measured = taint_max is not None or measured
            if measured:
                decision = policy.evaluate(features, policies, min_group=min_group,
                                           taint_max=taint_max)

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
            est_rows=affected,
            min_group=min_group,
            rollback_sql=rollback,
            taint_max=taint_max,
            latency_ms=elapsed,
        )

        if decision.effect != policy.ALLOW:
            return GatewayResult(decision=decision.effect, reason=decision.reason_text,
                                 seq=entry.seq, affected_rows=affected,
                                 min_group=min_group, taint_max=taint_max,
                                 rollback_sql=rollback)

        stmt = self.conn.execute(sql)

        # Only queries produce a result set; a write reports its row count.
        if features.kind != "SELECT":
            return GatewayResult(decision=policy.ALLOW, reason=decision.reason_text,
                                 seq=entry.seq, affected_rows=stmt.rowcount(),
                                 min_group=min_group, taint_max=taint_max,
                                 rollback_sql=rollback)

        rows = stmt.fetchmany(max_rows + 1)
        truncated = len(rows) > max_rows
        return GatewayResult(decision=policy.ALLOW, reason=decision.reason_text,
                             seq=entry.seq, rows=rows[:max_rows], truncated=truncated,
                             affected_rows=affected, min_group=min_group,
                             taint_max=taint_max, rollback_sql=rollback)

    def _text_columns(self, features) -> list[str]:
        """The free-text columns this query would actually return.

        Resolved from the catalog rather than a hardcoded list, so a new table
        needs no change here. A `SELECT *` returns all of them; anything else
        returns only what it names.
        """
        tables = [t for t in features.tables if "." in t]
        if not tables:
            return []
        pairs = [tuple(t.split(".", 1)) for t in tables]
        predicate = " OR ".join(
            f"(COLUMN_SCHEMA = '{s}' AND COLUMN_TABLE = '{t}')" for s, t in pairs)
        rows = self.conn.execute(
            f"SELECT DISTINCT COLUMN_NAME AS C FROM SYS.EXA_ALL_COLUMNS "
            f"WHERE ({predicate}) AND COLUMN_TYPE LIKE 'VARCHAR%' "
            f"AND COLUMN_MAXSIZE >= {taint.MIN_TEXT_WIDTH}"
        ).fetchall()
        available = [r["C"] for r in rows]
        if features.select_star:
            return available
        return [c for c in available if c in features.columns]

    def _measure_taint(self, sql: str, features) -> float | None:
        probe = preflight.build_taint_probe(sql, self._text_columns(features))
        if probe is None:
            return None
        try:
            row = self.conn.execute(probe).fetchone()
        except Exception:
            return None
        if not row:
            return None
        value = next(iter(row.values()))
        return float(value) if value is not None else None

    def _measure_min_group(self, sql: str) -> int | None:
        probe = preflight.build_group_probe(sql)
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

    def _measure_blast_radius(self, sql: str, features) -> tuple[int | None, str | None]:
        probe = preflight.build_probe(sql)
        if probe is None:
            return None, None
        try:
            row = self.conn.execute(probe).fetchone()
            affected = int(next(iter(row.values()))) if row else None
        except Exception:
            return None, None
        snapshot = f"AIRLOCK.SNAP_{uuid.uuid4().hex[:12].upper()}"
        rollback = preflight.build_rollback(
            sql, features, snapshot,
            key_columns=self._key_columns(features.target_table))
        return affected, rollback

    def _key_columns(self, table: str | None) -> list[str]:
        """Primary key of a write's target, in key order, from the catalog.

        The compensating statement has to match each snapshotted pre-image row
        back to the row the write changed, and the key is what does that. Read
        from the catalog rather than configured, so a new table needs no change
        here; cached because a session tends to write to the same few tables.
        """
        if not table or "." not in table:
            return []
        if table in self._key_cache:
            return self._key_cache[table]
        schema, name = table.split(".", 1)
        try:
            rows = self.conn.execute(
                "SELECT COLUMN_NAME AS C FROM SYS.EXA_ALL_CONSTRAINT_COLUMNS "
                "WHERE CONSTRAINT_SCHEMA = {schema} AND CONSTRAINT_TABLE = {tbl} "
                "AND CONSTRAINT_TYPE = 'PRIMARY KEY' ORDER BY ORDINAL_POSITION",
                {"schema": schema, "tbl": name},
            ).fetchall()
        except Exception:  # noqa: BLE001 - no key found means a narrower rollback
            return []
        keys = [r["C"] for r in rows]
        self._key_cache[table] = keys
        return keys
