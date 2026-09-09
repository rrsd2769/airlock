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

# Recorded in the ledger's TAINT_MAX when a scan applied but could not be taken.
# Real scores are 0..1, so a negative is unambiguous, and it travels with the
# entry -- which is what lets replay re-decide the statement exactly rather than
# meeting a NULL it cannot tell apart from "no scan applied".
TAINT_UNMEASURED = -1.0

# Most restrictive wins.
_RANK = {ALLOW: 0, REQUIRE_APPROVAL: 1, DENY: 2}


@dataclass
class Decision:
    effect: str = ALLOW
    reasons: list[str] = field(default_factory=list)
    matched: list[int] = field(default_factory=list)
    # A human has released this statement's holds. See apply().
    approved: bool = False

    def apply(self, effect: str, reason: str, policy_id: int) -> None:
        """Fold one matched rule into the verdict. Most restrictive wins.

        An approval is honoured here rather than at the call sites because
        REQUIRE_APPROVAL arrives from two directions -- as a policy row's own
        EFFECT, on any rule kind, and as the literal verdict the three
        unmeasurable-fact branches raise -- and a demotion written at each of
        those would be a list to keep in step with every rule added later. It
        is one rule here: an approved hold becomes an allowance, and DENY never
        passes through this branch at all.

        The reason survives the demotion. An approved statement's ledger entry
        still says which rules held it and why; what changed is that a human
        answered them, not that they stopped applying.
        """
        if self.approved and effect == REQUIRE_APPROVAL:
            effect = ALLOW
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


# The one column list for a POLICY row. Every reader below shares it, so a new
# column is typed out once rather than drifting across four independent SELECTs.
_COLUMNS = (
    "POLICY_ID, NAME, VERSION, IS_ENABLED, RULE_KIND, EFFECT, "
    "TARGET_SCHEMA, TARGET_TABLE, TARGET_COLUMN, PRINCIPAL, "
    "CAST(THRESHOLD AS DOUBLE) AS THRESHOLD, NOTE"
)


def load_policies(conn: pyexasol.ExaConnection, principal: str) -> list[dict]:
    """The rule set as the gateway decides against: enabled, scoped to one principal."""
    return conn.execute(
        f"""
        SELECT {_COLUMNS}
        FROM AIRLOCK.POLICY
        WHERE IS_ENABLED = TRUE
          AND (PRINCIPAL IS NULL OR PRINCIPAL = {{principal}})
        ORDER BY POLICY_ID
        """,
        {"principal": principal},
    ).fetchall()


def list_all(conn: pyexasol.ExaConnection) -> list[dict]:
    """The rule set as it stands, unfiltered -- what the console shows."""
    return conn.execute(f"SELECT {_COLUMNS} FROM AIRLOCK.POLICY ORDER BY POLICY_ID").fetchall()


def by_ids(conn: pyexasol.ExaConnection, ids: list[int]) -> list[dict]:
    """Specific rows by primary key, for naming the rules behind one decision."""
    if not ids:
        return []
    listed = ",".join(str(int(i)) for i in ids)
    return conn.execute(
        f"SELECT {_COLUMNS} FROM AIRLOCK.POLICY WHERE POLICY_ID IN ({listed}) "
        f"ORDER BY POLICY_ID"
    ).fetchall()


def denied_columns(conn: pyexasol.ExaConnection) -> dict[tuple[str, str], set[str]]:
    """Columns each table's enabled COLUMN_ACCESS DENY rules withhold.

    A different question from the readers above -- not "which policies apply"
    but "which columns are denied" -- so it keeps its own WHERE clause rather
    than filtering a general row list after the fact.
    """
    rows = conn.execute(
        "SELECT TARGET_SCHEMA AS S, TARGET_TABLE AS T, TARGET_COLUMN AS C "
        "FROM AIRLOCK.POLICY "
        "WHERE RULE_KIND = 'COLUMN_ACCESS' AND EFFECT = 'DENY' "
        "AND IS_ENABLED AND TARGET_SCHEMA IS NOT NULL "
        "AND TARGET_TABLE IS NOT NULL AND TARGET_COLUMN IS NOT NULL"
    ).fetchall()

    out: dict[tuple[str, str], set[str]] = {}
    for row in rows:
        key = (row["S"].upper(), row["T"].upper())
        out.setdefault(key, set()).add(row["C"].upper())
    return out


# Which RULE_KIND needs which fields to ever match in evaluate() below. A rule
# missing one of these does not error against the schema -- it inserts fine
# and then never fires, which is a worse failure than a rejection at the seam.
_RULE_KINDS = {"COLUMN_ACCESS", "MIN_AGGREGATION", "BLAST_RADIUS",
               "SCHEMA_SCOPE", "SCHEMA_DENY", "TAINT_BLOCK"}
_NEEDS_TARGET_COLUMN = {"COLUMN_ACCESS", "MIN_AGGREGATION"}  # see _touches_column
_NEEDS_TARGET_SCHEMA = {"SCHEMA_DENY", "SCHEMA_SCOPE"}
_NEEDS_THRESHOLD = {"MIN_AGGREGATION", "BLAST_RADIUS", "TAINT_BLOCK"}


def _validate_new_rule(rule_kind: str, effect: str, target_schema: str | None,
                        target_column: str | None, threshold: float | None) -> None:
    if rule_kind not in _RULE_KINDS:
        raise ValueError(f"unknown RULE_KIND {rule_kind!r}")
    if effect not in (ALLOW, DENY, REQUIRE_APPROVAL):
        raise ValueError(f"unknown EFFECT {effect!r}")
    if rule_kind in _NEEDS_TARGET_COLUMN and not target_column:
        raise ValueError(f"{rule_kind} needs TARGET_COLUMN -- evaluate() never "
                         f"matches without one")
    if rule_kind in _NEEDS_TARGET_SCHEMA and not target_schema:
        raise ValueError(f"{rule_kind} needs TARGET_SCHEMA")
    if rule_kind == "SCHEMA_SCOPE" and effect != ALLOW:
        # evaluate() only reads EFFECT == ALLOW rows to compose the allowed
        # set (see the SCHEMA_SCOPE branch below) -- a DENY row here inserts
        # cleanly and is never consulted.
        raise ValueError("SCHEMA_SCOPE only composes its allowed set from "
                         "ALLOW rows; a DENY row here never matches")
    if rule_kind in _NEEDS_THRESHOLD and threshold is None:
        raise ValueError(f"{rule_kind} needs THRESHOLD")


def add_rule(conn: pyexasol.ExaConnection, *, name: str, rule_kind: str, effect: str,
             target_schema: str | None = None, target_table: str | None = None,
             target_column: str | None = None, principal: str | None = None,
             threshold: float | None = None, note: str | None = None) -> int:
    """Insert a new POLICY row, after validating it can ever match.

    Runs on the rules desk's own identity (sql/40_identities.sql), never
    AIRLOCK_SVC -- the gateway must never hold write access to the rules that
    bind it. The caller is expected to serialise writes (rules_api.py does,
    the same way api.py and approve_api.py serialise theirs), which is what
    makes the NAME lookup below safe from a concurrent insert of the same name.
    """
    _validate_new_rule(rule_kind, effect, target_schema, target_column, threshold)
    conn.execute(
        """
        INSERT INTO AIRLOCK.POLICY
            (NAME, RULE_KIND, EFFECT, TARGET_SCHEMA, TARGET_TABLE, TARGET_COLUMN,
             PRINCIPAL, THRESHOLD, NOTE)
        VALUES ({name}, {rule_kind}, {effect}, {target_schema}, {target_table},
                {target_column}, {principal}, {threshold}, {note})
        """,
        {"name": name, "rule_kind": rule_kind, "effect": effect,
         "target_schema": target_schema, "target_table": target_table,
         "target_column": target_column, "principal": principal,
         "threshold": threshold, "note": note},
    )
    row = conn.execute(
        "SELECT POLICY_ID FROM AIRLOCK.POLICY WHERE NAME = {name} "
        "ORDER BY POLICY_ID DESC",
        {"name": name},
    ).fetchone()
    return int(row["POLICY_ID"])


def disable_rule(conn: pyexasol.ExaConnection, policy_id: int) -> bool:
    """Turn a rule off. Never a DELETE -- a disabled rule stays visible to
    anyone reading history, the same append-over-mutate posture already used
    for the ledger and the approval queue. Returns whether a row existed.
    """
    cursor = conn.execute(
        "UPDATE AIRLOCK.POLICY SET IS_ENABLED = FALSE WHERE POLICY_ID = {pid}",
        {"pid": policy_id},
    )
    return cursor.rowcount() > 0


def evaluate(features: Features, policies: list[dict], *,
             affected_rows: int | None = None,
             min_group: int | None = None,
             taint_max: float | None = None,
             approved: bool = False) -> Decision:
    """Pure function: features + policy set -> decision.

    Pure on purpose. Replay feeds historical features and a new policy set
    through this same function to answer 'what would this change have blocked?'

    `approved` says a human has released this statement's holds. It demotes
    matched REQUIRE_APPROVAL rules to ALLOW and leaves DENY exactly where it
    was -- an approver is releasing a hold, not overruling a prohibition, and a
    statement that was held *and* denied stays denied. That asymmetry is the
    whole reason approval is a parameter here rather than a check the gateway
    does to the verdict afterwards: from the outside, a decision can only be
    read as one effect, and 'ALLOW unless something also denied it' is not a
    thing a caller can reconstruct from it.
    """
    d = Decision(approved=approved)

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

        if kind == "SCHEMA_DENY":
            if p["TARGET_SCHEMA"] in features.schemas:
                d.apply(p["EFFECT"],
                        f"{p['NAME']}: {p['TARGET_SCHEMA']} is not reachable by an agent",
                        p["POLICY_ID"])

        elif kind == "COLUMN_ACCESS":
            if _touches_column(features, p):
                d.apply(p["EFFECT"],
                        f"{p['NAME']}: {p['TARGET_COLUMN']} is not readable by an agent",
                        p["POLICY_ID"])

        elif kind == "MIN_AGGREGATION":
            # k-anonymity governs what an agent can *see*, so it applies to
            # projections, not to a predicate in a write's WHERE clause.
            if features.kind == "SELECT" and _touches_column(features, p):
                k = int(p["THRESHOLD"])
                if not features.has_aggregate:
                    d.apply(p["EFFECT"],
                            f"{p['NAME']}: {p['TARGET_COLUMN']} is aggregate-only "
                            f"(k={k}), statement selects it raw",
                            p["POLICY_ID"])
                elif min_group is None:
                    # An aggregate whose group sizes we could not measure is not
                    # evidence of anonymity. Same posture as an unmeasured write.
                    d.apply(REQUIRE_APPROVAL,
                            f"{p['NAME']}: group size could not be measured",
                            p["POLICY_ID"])
                elif min_group < k:
                    d.apply(p["EFFECT"],
                            f"{p['NAME']}: smallest group is {min_group} rows, "
                            f"k={k} required",
                            p["POLICY_ID"])

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
            if taint_max is None:
                pass  # No scan applied: nothing text-bearing comes back.
            elif taint_max < 0:
                # A result set we could not scan is not evidence that it is
                # clean. Same posture as an unmeasured write or group size --
                # this rule used to be the one that let it through.
                d.apply(REQUIRE_APPROVAL,
                        f"{p['NAME']}: result set could not be scanned for "
                        f"injected instructions",
                        p["POLICY_ID"])
            elif taint_max >= float(p["THRESHOLD"]):
                d.apply(p["EFFECT"],
                        f"{p['NAME']}: result set contains injected instructions "
                        f"(taint {taint_max:.2f})",
                        p["POLICY_ID"])

    # Self-protection is structural, not merely a policy row: an agent must not
    # be able to erase its own audit trail by deleting the policy that stops it.
    if "AIRLOCK" in features.schemas:
        d.apply(DENY, "AIRLOCK's own schema is never reachable through the airlock", 0)

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
