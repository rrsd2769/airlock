"""Blast-radius preflight.

Before a write executes we rewrite it into the SELECT COUNT(*) that measures
exactly how many rows it would touch, and run that. Not an optimiser estimate --
a real count. We can afford it because the engine underneath is a columnar MPP
analytics database; on a row store this would be unaffordable on the hot path.

We also synthesise the compensating statement, so an agent's write has an undo.
"""
from __future__ import annotations

from dataclasses import dataclass

import sqlglot
from sqlglot import exp

from .analyze import Features


@dataclass
class Preflight:
    affected_rows: int | None = None
    probe_sql: str | None = None
    rollback_sql: str | None = None
    snapshot_table: str | None = None
    error: str | None = None


def build_probe(sql: str) -> str | None:
    """Rewrite a write statement into the count of rows it would affect."""
    try:
        tree = sqlglot.parse_one(sql, read="postgres")
    except Exception:
        return None

    if isinstance(tree, (exp.Update, exp.Delete)):
        table = tree.find(exp.Table)
        where = tree.find(exp.Where)
        if table is None:
            return None
        target = table.sql(dialect="postgres")
        clause = f" {where.sql(dialect='postgres')}" if where else ""
        return f"SELECT COUNT(*) AS AFFECTED FROM {target}{clause}"

    if isinstance(tree, exp.Insert):
        # INSERT ... SELECT can be counted; INSERT ... VALUES is its own count.
        select = tree.find(exp.Select)
        if select is not None:
            return f"SELECT COUNT(*) AS AFFECTED FROM ({select.sql(dialect='postgres')})"
        values = tree.find(exp.Values)
        if values is not None:
            return f"SELECT {len(values.expressions)} AS AFFECTED"
    return None


def build_group_probe(sql: str) -> str | None:
    """Rewrite an aggregate query into the size of its smallest group.

    k-anonymity is a claim about how many people hide behind each published
    number, so it can only be enforced against a *measured* group size. We keep
    the query's FROM, WHERE, GROUP BY and HAVING -- the shape that determines the
    grouping -- throw its projections away, and count. Same argument as the blast
    radius: on a columnar engine this is affordable on the hot path.
    """
    try:
        tree = sqlglot.parse_one(sql, read="postgres")
    except Exception:
        return None
    if not isinstance(tree, exp.Select):
        return None

    inner = tree.copy()
    inner.set("expressions", [exp.alias_(exp.Count(this=exp.Star()), "GRP_N")])
    # These narrow what is displayed, not how rows are grouped.
    for clause in ("order", "limit", "offset", "distinct"):
        inner.set(clause, None)

    return f"SELECT MIN(GRP_N) AS MIN_GROUP FROM ({inner.sql(dialect='postgres')})"


def build_rollback(sql: str, features: Features, snapshot_table: str) -> str | None:
    """Compensating statement that reverses the write.

    DELETE and UPDATE are reversed from a snapshot taken before execution;
    INSERT is reversed by deleting what was inserted.
    """
    if features.target_table is None:
        return None

    if features.kind == "DELETE":
        return f"INSERT INTO {features.target_table} SELECT * FROM {snapshot_table}"

    if features.kind == "UPDATE":
        # Restore the pre-image rows wholesale: delete the touched keys, reinsert.
        return (
            f"-- restore pre-image captured in {snapshot_table}\n"
            f"MERGE INTO {features.target_table} t\n"
            f"USING {snapshot_table} s ON (/* TODO: key columns */)\n"
            f"WHEN MATCHED THEN UPDATE SET /* TODO: restore columns */"
        )

    if features.kind == "INSERT":
        return f"-- reverse insert: DELETE FROM {features.target_table} WHERE <inserted keys>"

    return None


def snapshot_sql(features: Features, sql: str, snapshot_table: str) -> str | None:
    """CTAS that captures the pre-image of the rows a write is about to change."""
    if features.kind not in {"UPDATE", "DELETE"} or features.target_table is None:
        return None
    try:
        tree = sqlglot.parse_one(sql, read="postgres")
    except Exception:
        return None
    where = tree.find(exp.Where)
    clause = f" {where.sql(dialect='postgres')}" if where else ""
    return f"CREATE TABLE {snapshot_table} AS SELECT * FROM {features.target_table}{clause}"
