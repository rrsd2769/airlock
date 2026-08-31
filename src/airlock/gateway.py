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

from . import ledger, policy, preflight
from .analyze import analyze
from .config import settings


@dataclass
class GatewayResult:
    decision: str
    reason: str
    seq: int
    affected_rows: int | None = None
    rows: list[dict[str, Any]] | None = None
    truncated: bool = False
    rollback_sql: str | None = None


class Airlock:
    def __init__(self, conn: pyexasol.ExaConnection, principal: str | None = None,
                 session_id: str | None = None) -> None:
        self.conn = conn
        self.principal = principal or settings.principal
        self.session_id = session_id or uuid.uuid4().hex
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
        if decision.effect != policy.DENY and features.kind in {"UPDATE", "DELETE",
                                                                "INSERT", "MERGE"}:
            affected, rollback = self._measure_blast_radius(sql, features)
            # Second pass, now that the radius is a measured fact.
            decision = policy.evaluate(features, policies, affected_rows=affected)

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
            rollback_sql=rollback,
            taint_max=None,
            latency_ms=elapsed,
        )

        if decision.effect != policy.ALLOW:
            return GatewayResult(decision=decision.effect, reason=decision.reason_text,
                                 seq=entry.seq, affected_rows=affected,
                                 rollback_sql=rollback)

        stmt = self.conn.execute(sql)

        # Only queries produce a result set; a write reports its row count.
        if features.kind != "SELECT":
            return GatewayResult(decision=policy.ALLOW, reason=decision.reason_text,
                                 seq=entry.seq, affected_rows=stmt.rowcount(),
                                 rollback_sql=rollback)

        rows = stmt.fetchmany(max_rows + 1)
        truncated = len(rows) > max_rows
        return GatewayResult(decision=policy.ALLOW, reason=decision.reason_text,
                             seq=entry.seq, rows=rows[:max_rows], truncated=truncated,
                             affected_rows=affected, rollback_sql=rollback)

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
        rollback = preflight.build_rollback(sql, features, snapshot)
        return affected, rollback
