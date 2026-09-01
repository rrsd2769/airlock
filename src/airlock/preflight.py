"""Blast-radius preflight.

Before a write executes we rewrite it into the SELECT COUNT(*) that measures
exactly how many rows it would touch, and run that. Not an optimiser estimate --
a real count. We can afford it because the engine underneath is a columnar MPP
analytics database; on a row store this would be unaffordable on the hot path.

We also synthesise the compensating statement, so an agent's write has an undo,
and the CTAS that captures the pre-image it reads back.

Every builder here takes a `Statement`, never raw SQL. The tree arrived already
parsed, so none of them can fail to parse -- and none of them gets its own
opinion about what an unparseable statement means. One that did not parse has
`tree is None` and `kind == "OTHER"`, which the policy engine denied before
anything here was called.
"""
from __future__ import annotations

from sqlglot import exp

from .analyze import DIALECT
from .statement import Statement


def build_probe(stmt: Statement) -> str | None:
    """Rewrite a write statement into the count of rows it would affect."""
    tree = stmt.tree
    if tree is None:
        return None

    if isinstance(tree, (exp.Update, exp.Delete)):
        table = tree.find(exp.Table)
        if table is None:
            return None
        target = table.sql(dialect=DIALECT)
        return f"SELECT COUNT(*) AS AFFECTED FROM {target}{stmt.where_sql()}"

    if isinstance(tree, exp.Insert):
        # INSERT ... SELECT can be counted; INSERT ... VALUES is its own count.
        select = tree.find(exp.Select)
        if select is not None:
            return f"SELECT COUNT(*) AS AFFECTED FROM ({select.sql(dialect=DIALECT)})"
        values = tree.find(exp.Values)
        if values is not None:
            return f"SELECT {len(values.expressions)} AS AFFECTED"
    return None


def build_group_probe(stmt: Statement) -> str | None:
    """Rewrite an aggregate query into the size of its smallest group.

    k-anonymity is a claim about how many people hide behind each published
    number, so it can only be enforced against a *measured* group size. We keep
    the query's FROM, WHERE, GROUP BY and HAVING -- the shape that determines the
    grouping -- throw its projections away, and count. Same argument as the blast
    radius: on a columnar engine this is affordable on the hot path.
    """
    if not isinstance(stmt.tree, exp.Select):
        return None

    inner = stmt.tree.copy()
    inner.set("expressions", [exp.alias_(exp.Count(this=exp.Star()), "GRP_N")])
    # These narrow what is displayed, not how rows are grouped.
    for clause in ("order", "limit", "offset", "distinct"):
        inner.set(clause, None)

    return f"SELECT MIN(GRP_N) AS MIN_GROUP FROM ({inner.sql(dialect=DIALECT)})"


def _scan_projections(text_columns: list[str]) -> list[exp.Expression] | None:
    """SCAN_TAINT(col) AS RAW_i, one per column we care about.

    The parse here is of our own generated call, not of the agent's statement --
    the column names come from the catalog. It stays guarded because a name the
    catalog returns and sqlglot will not accept must produce no probe rather than
    a malformed one, and the gateway reads "no probe" as a reason to hold.
    """
    projections = []
    for i, column in enumerate(text_columns):
        try:
            call = exp.maybe_parse(f"AIRLOCK.SCAN_TAINT({column})", dialect=DIALECT)
        except Exception:  # noqa: BLE001 - an unscannable column means no probe
            return None
        projections.append(exp.alias_(call, f"RAW_{i}"))
    return projections


def _scan_rewrite(node: exp.Expression, text_columns: list[str]) -> exp.Expression | None:
    """Replace a query's projections with taint scores, through set operations.

    A UNION is rewritten branch by branch rather than skipped. That matters:
    the projections are what the rewrite throws away, so a query the gateway
    would otherwise refuse can be handed back unmeasured just by wrapping it in
    `UNION ALL SELECT ... WHERE 1 = 0`.
    """
    if isinstance(node, exp.SetOperation):
        rewritten = node.copy()
        left = _scan_rewrite(node.this, text_columns)
        right = _scan_rewrite(node.expression, text_columns)
        if left is None or right is None:
            return None
        rewritten.set("this", left)
        rewritten.set("expression", right)
        for clause in ("order", "limit", "offset"):
            rewritten.set(clause, None)
        return rewritten

    if not isinstance(node, exp.Select):
        return None

    projections = _scan_projections(text_columns)
    if projections is None:
        return None
    rewritten = node.copy()
    rewritten.set("expressions", projections)
    for clause in ("order", "limit", "offset", "distinct"):
        rewritten.set(clause, None)
    return rewritten


def build_taint_probe(stmt: Statement, text_columns: list[str]) -> str | None:
    """Rewrite a query into the worst taint score among the rows it would return.

    The sweep in `airlock.taint` says where the poison is in the warehouse. This
    asks the narrower question the gateway actually needs answered: does *this*
    result set contain it? Same shape as the other two probes -- keep the query's
    FROM and WHERE, throw its projections away, and measure.

    The LIMIT is deliberately dropped. A LIMIT without an ORDER BY returns an
    arbitrary slice, so probing with it would scan rows the real execution might
    not return, and miss rows it would. We score every candidate row instead.

    Aggregates are skipped by the caller: they return numbers, and an injection
    needs text to ride out on.

    Returning None here does not mean "allow": the gateway treats a scan it
    wanted but could not take as a reason to hold the statement.
    """
    if not text_columns or stmt.tree is None:
        return None

    inner = _scan_rewrite(stmt.tree, text_columns)
    if inner is None:
        return None

    # SCAN_TAINT returns "score|patterns"; the score is everything before the bar.
    scores = [f"TO_NUMBER(SUBSTR(RAW_{i}, 1, INSTR(RAW_{i}, '|') - 1))"
              for i in range(len(text_columns))]
    worst = scores[0] if len(scores) == 1 else f"GREATEST({', '.join(scores)})"
    return f"SELECT MAX({worst}) AS TAINT_MAX FROM ({inner.sql(dialect=DIALECT)})"


def _assigned_columns(tree: exp.Update) -> list[str]:
    """The columns an UPDATE writes to, in the order it names them."""
    columns = []
    for assignment in tree.expressions:
        if isinstance(assignment, exp.EQ) and isinstance(assignment.this, exp.Column):
            name = assignment.this.name.upper()
            if name not in columns:
                columns.append(name)
    return columns


def build_rollback(stmt: Statement, snapshot_table: str,
                   key_columns: list[str] | None = None) -> str | None:
    """Compensating statement that reverses the write.

    DELETE and UPDATE are reversed from a snapshot taken before execution;
    INSERT has no pre-image to reverse from.

    `key_columns` is the target's primary key, read from the catalog by the
    caller. An UPDATE's compensating statement has to match each pre-image row
    back to the row the write changed, and the key is the only thing that does
    that reliably -- so what we can generate depends on whether the table has
    one. We would rather emit a narrower statement, or say plainly that we
    cannot, than emit a plausible one that restores the wrong rows.
    """
    target = stmt.target_table
    if target is None:
        return None

    if stmt.kind == "DELETE":
        return f"INSERT INTO {target} SELECT * FROM {snapshot_table}"

    if stmt.kind == "UPDATE":
        return _update_rollback(stmt, snapshot_table, key_columns)

    if stmt.kind == "INSERT":
        # An insert has no pre-image: the rows did not exist to be snapshotted,
        # and which ones are new is only known once the statement has run.
        return (f"-- reverse insert: no pre-image exists. Reversing requires the keys\n"
                f"-- of the rows {target} gains, which are only known\n"
                f"-- after execution.")

    return None


def _update_rollback(stmt: Statement, snapshot_table: str,
                     key_columns: list[str] | None) -> str | None:
    tree = stmt.tree
    if not isinstance(tree, exp.Update):
        return None

    target = stmt.target_table
    assigned = _assigned_columns(tree)
    if not assigned:
        return None

    if key_columns:
        # Restore only the columns the write touched. Everything else in the
        # snapshot is already what it was.
        on = " AND ".join(f"t.{k} = s.{k}" for k in key_columns)
        restore = ", ".join(f"t.{c} = s.{c}" for c in assigned)
        return (f"MERGE INTO {target} t\n"
                f"USING {snapshot_table} s ON ({on})\n"
                f"WHEN MATCHED THEN UPDATE SET {restore}")

    # No key. The affected rows can still be replaced wholesale from the
    # snapshot, but only if the write's own predicate still selects the same
    # rows after it has run -- which it does exactly when the predicate reads
    # no column the write changes.
    where = stmt.where()
    predicate_columns = ({c.name.upper() for c in where.find_all(exp.Column)}
                         if where else set())
    if predicate_columns & set(assigned):
        overlap = ", ".join(sorted(predicate_columns & set(assigned)))
        # No semicolons in the comment text -- these strings are pasted into
        # clients that split a script on them.
        return (f"-- {target} has no primary key, and this write reads a column it\n"
                f"-- also changes ({overlap}), so the rows it touched cannot be\n"
                f"-- identified again once it has run. The pre-image is in\n"
                f"-- {snapshot_table}, but reversing it needs a key.")

    return (f"-- {target} has no primary key. The predicate does not read what\n"
            f"-- this write changes, so it still selects exactly the affected rows.\n"
            f"DELETE FROM {target}{stmt.where_sql()};\n"
            f"INSERT INTO {target} SELECT * FROM {snapshot_table}")


def snapshot_sql(stmt: Statement, snapshot_table: str) -> str | None:
    """CTAS that captures the pre-image of the rows a write is about to change."""
    if stmt.kind not in {"UPDATE", "DELETE"} or stmt.target_table is None:
        return None
    if stmt.tree is None:
        return None
    return (f"CREATE TABLE {snapshot_table} AS "
            f"SELECT * FROM {stmt.target_table}{stmt.where_sql()}")
