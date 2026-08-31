"""The policy engine.

Decisions are made by matching statement features against rows in AIRLOCK.POLICY.
Deterministic, sub-millisecond, versioned, and replayable. Deliberately not a
model call: you do not govern an autonomous agent with another autonomous agent.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pyexasol

from .analyze import Features

ALLOW = "ALLOW"
DENY = "DENY"
REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

# Most restrictive wins.
_RANK = {ALLOW: 0, REQUIRE_APPROVAL: 1, DENY: 2}


@dataclass
class Decision:
    effect: str = ALLOW
    reasons: list[str] = field(default_factory=list)
    matched: list[int] = field(default_factory=list)

    def apply(self, effect: str, reason: str, policy_id: int) -> None:
        if _RANK[effect] > _RANK[self.effect]:
            self.effect = effect
        self.reasons.append(reason)
        if policy_id not in self.matched:
            self.matched.append(policy_id)

    @property
    def reason_text(self) -> str:
        return " | ".join(self.reasons) if self.reasons else "no policy matched"

    @property
    def matched_csv(self) -> str:
        return ",".join(str(m) for m in self.matched)


def load_policies(conn: pyexasol.ExaConnection, principal: str) -> list[dict]:
    return conn.execute(
        """
        SELECT POLICY_ID, NAME, RULE_KIND, EFFECT, TARGET_SCHEMA, TARGET_TABLE,
               TARGET_COLUMN, PRINCIPAL, THRESHOLD, NOTE
        FROM AIRLOCK.POLICY
        WHERE ENABLED = TRUE
          AND (PRINCIPAL IS NULL OR PRINCIPAL = ?)
        ORDER BY POLICY_ID
        """,
        [principal],
    ).fetchall()


def evaluate(features: Features, policies: list[dict], *,
             affected_rows: int | None = None,
             taint_max: float | None = None) -> Decision:
    """Pure function: features + policy set -> decision.

    Pure on purpose. Replay feeds historical features and a new policy set
    through this same function to answer 'what would this change have blocked?'
    """
    d = Decision()

    # An unparseable statement is never waved through.
    if features.parse_error:
        d.apply(DENY, f"statement could not be parsed: {features.parse_error}", 0)
        return d

    scope_policies = [p for p in policies if p["RULE_KIND"] == "SCHEMA_SCOPE"]
    if scope_policies:
        allowed = {p["TARGET_SCHEMA"] for p in scope_policies if p["EFFECT"] == ALLOW}
        outside = [s for s in features.schemas if s not in allowed]
        if outside:
            pid = scope_policies[0]["POLICY_ID"]
            d.apply(DENY, f"principal is scoped to {sorted(allowed)}; "
                          f"statement reaches {outside}", pid)

    for p in policies:
        kind = p["RULE_KIND"]

        if kind == "COLUMN_ACCESS":
            if _touches_column(features, p):
                d.apply(p["EFFECT"],
                        f"{p['NAME']}: {p['TARGET_COLUMN']} is not readable by an agent",
                        p["POLICY_ID"])

        elif kind == "MIN_AGGREGATION":
            if _touches_column(features, p):
                if not features.has_aggregate:
                    d.apply(p["EFFECT"],
                            f"{p['NAME']}: {p['TARGET_COLUMN']} is aggregate-only "
                            f"(k={int(p['THRESHOLD'])}), statement selects it raw",
                            p["POLICY_ID"])
                # Group-size check is measured at preflight; see gateway.

        elif kind == "BLAST_RADIUS":
            if features.kind in {"UPDATE", "DELETE", "INSERT", "MERGE"}:
                cap = int(p["THRESHOLD"])
                if affected_rows is None:
                    d.apply(REQUIRE_APPROVAL,
                            f"{p['NAME']}: blast radius could not be measured",
                            p["POLICY_ID"])
                elif affected_rows > cap:
                    d.apply(p["EFFECT"],
                            f"{p['NAME']}: would modify {affected_rows} rows, cap is {cap}",
                            p["POLICY_ID"])

        elif kind == "TAINT_BLOCK":
            if taint_max is not None and taint_max >= float(p["THRESHOLD"]):
                d.apply(p["EFFECT"],
                        f"{p['NAME']}: result set contains injected instructions "
                        f"(taint {taint_max:.2f})",
                        p["POLICY_ID"])

    # DDL from an agent is never in scope for this gateway.
    if features.kind in {"CREATE", "DROP", "ALTER", "TRUNCATE", "OTHER"}:
        d.apply(DENY, f"{features.kind} is not permitted through the airlock", 0)

    return d


def _touches_column(features: Features, policy: dict) -> bool:
    target_table = policy["TARGET_TABLE"]
    target_col = policy["TARGET_COLUMN"]
    if target_table:
        schema = policy["TARGET_SCHEMA"]
        qualified = f"{schema}.{target_table}" if schema else target_table
        if qualified not in features.tables:
            return False
        # SELECT * over the protected table pulls the column implicitly.
        if features.select_star:
            return True
    return bool(target_col) and target_col in features.columns
