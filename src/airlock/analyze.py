"""Static analysis of an agent's statement.

Turns SQL into a structured description of what it would touch. This is the
input to the policy engine -- no LLM is involved in deciding anything.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict

import sqlglot
from sqlglot import exp

READ_KINDS = {"SELECT"}
WRITE_KINDS = {"INSERT", "UPDATE", "DELETE", "MERGE"}
DDL_KINDS = {"CREATE", "DROP", "ALTER", "TRUNCATE"}


@dataclass
class Features:
    kind: str = "OTHER"
    tables: list[str] = field(default_factory=list)       # SCHEMA.TABLE, uppercased
    schemas: list[str] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)      # bare column names
    qualified_columns: list[str] = field(default_factory=list)
    has_aggregate: bool = False
    group_by: list[str] = field(default_factory=list)
    has_where: bool = False
    select_star: bool = False
    target_table: str | None = None                       # for writes
    join_count: int = 0
    parse_error: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


def _norm(name: str | None) -> str:
    return (name or "").upper()


DIALECT = "postgres"


def parse_sql(sql: str) -> tuple[exp.Expression | None, str | None]:
    """Parse an agent's statement into a tree, or say why not.

    The single call to sqlglot on an agent's SQL. Everything that needs the tree
    -- the probes, the compensating statement, the pre-image capture -- takes it
    from `statement.Statement` rather than parsing again, so that "what if it
    will not parse" is answered once, here, and denied upstream by the policy
    engine rather than re-decided per builder.
    """
    try:
        tree = sqlglot.parse_one(sql, read=DIALECT)
    except Exception as exc:  # noqa: BLE001 - any parse failure is a deny
        return None, str(exc)[:500]
    if tree is None:
        return None, "empty statement"
    return tree, None


def analyze(sql: str, default_schema: str | None = None) -> Features:
    """Parse a statement into policy-relevant features.

    A statement we cannot parse is not waved through -- it comes back as
    kind=OTHER with parse_error set, and the policy engine denies by default.

    Callers on the gateway's hot path want `statement.Statement.parse` instead,
    which keeps the tree as well. This stays for the callers that only ever
    needed the features: `policy.evaluate` is a pure function of them.
    """
    tree, error = parse_sql(sql)
    if tree is None:
        return Features(parse_error=error)
    return features_from_tree(tree, default_schema)


def features_from_tree(tree: exp.Expression,
                       default_schema: str | None = None) -> Features:
    """Everything policy needs to know about a statement, from its tree."""
    f = Features()
    f.kind = _statement_kind(tree)

    for tbl in tree.find_all(exp.Table):
        schema = _norm(tbl.db) or _norm(default_schema)
        name = _norm(tbl.name)
        if not name:
            continue
        qualified = f"{schema}.{name}" if schema else name
        if qualified not in f.tables:
            f.tables.append(qualified)
        if schema and schema not in f.schemas:
            f.schemas.append(schema)

    for col in tree.find_all(exp.Column):
        bare = _norm(col.name)
        if bare and bare not in f.columns:
            f.columns.append(bare)
        table_ref = _norm(col.table)
        if table_ref:
            q = f"{table_ref}.{bare}"
            if q not in f.qualified_columns:
                f.qualified_columns.append(q)

    f.has_aggregate = any(tree.find_all(exp.AggFunc))
    f.group_by = [_norm(g.name) for g in tree.find_all(exp.Group) for g in g.expressions] \
        if tree.find(exp.Group) else []
    f.has_where = tree.find(exp.Where) is not None
    # Only a bare '*' in the projection counts. COUNT(*) also contains a Star
    # node, and treating that as SELECT * blocks every aggregate query.
    f.select_star = any(
        _is_star_projection(projection)
        for select in tree.find_all(exp.Select)
        for projection in select.expressions
    )
    f.join_count = len(list(tree.find_all(exp.Join)))

    if f.kind in WRITE_KINDS:
        f.target_table = _write_target(tree, default_schema)

    return f


def _is_star_projection(node: exp.Expression) -> bool:
    """Bare `*` or a qualified `t.*`, but not the Star inside COUNT(*)."""
    if isinstance(node, exp.Star):
        return True
    return isinstance(node, exp.Column) and isinstance(node.this, exp.Star)


def _statement_kind(tree: exp.Expression) -> str:
    mapping = {
        exp.Select: "SELECT",
        exp.Insert: "INSERT",
        exp.Update: "UPDATE",
        exp.Delete: "DELETE",
        exp.Merge: "MERGE",
        exp.Create: "CREATE",
        exp.Drop: "DROP",
        exp.Alter: "ALTER",
    }
    for node_type, kind in mapping.items():
        if isinstance(tree, node_type):
            return kind
    if isinstance(tree, exp.With) or tree.find(exp.Select):
        return "SELECT"
    return "OTHER"


def _write_target(tree: exp.Expression, default_schema: str | None) -> str | None:
    node = tree.find(exp.Table)
    if node is None:
        return None
    schema = _norm(node.db) or _norm(default_schema)
    name = _norm(node.name)
    return f"{schema}.{name}" if schema else name
