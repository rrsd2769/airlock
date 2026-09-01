"""The agent's statement, parsed once.

Everything downstream needs the same tree: the policy features, the three
probes, the compensating statement, the pre-image capture. Parsing per caller
meant seven parses of one string -- and, worse, seven independent answers to
"what if it will not parse", which disagreed. An unparseable statement made one
builder measure nothing and run, another hold, and a third deny as a bug.

There is one answer now and it is made here. A statement that does not parse has
no tree, comes out as kind=OTHER with parse_error set, and `policy.evaluate`
denies it by default before any probe is reached. The `tree is None` guards in
`preflight` are what make that unreachable rather than merely unlikely; they are
not a second opinion.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlglot import exp

from .analyze import DIALECT, Features, features_from_tree, parse_sql


@dataclass
class Statement:
    """An agent's SQL, its parse tree, and what policy needs to know about it.

    `tree` is None exactly when the statement did not parse, which is the same
    condition as `features.parse_error` being set. Callers check one or the
    other, never re-parse.
    """

    sql: str
    tree: exp.Expression | None
    features: Features

    @classmethod
    def parse(cls, sql: str, default_schema: str | None = None) -> Statement:
        """The only place an agent's statement is turned into a tree."""
        tree, error = parse_sql(sql)
        if tree is None:
            return cls(sql=sql, tree=None, features=Features(parse_error=error))
        return cls(sql=sql, tree=tree,
                   features=features_from_tree(tree, default_schema))

    @property
    def kind(self) -> str:
        return self.features.kind

    @property
    def target_table(self) -> str | None:
        return self.features.target_table

    @property
    def parse_error(self) -> str | None:
        return self.features.parse_error

    @property
    def reads_derived_source(self) -> bool:
        """True when the query selects from a CTE or a subquery rather than a table.

        It matters for `SELECT *`: the catalog can list a base table's text
        columns, but not which of them a derived source passes through, and
        scanning one it does not expose makes the probe fail. A statement we
        could not parse is treated as derived -- we cannot see through it either.
        """
        if self.tree is None:
            return True
        if self.tree.find(exp.With) is not None:
            return True
        froms = list(self.tree.find_all(exp.From)) + list(self.tree.find_all(exp.Join))
        return any(isinstance(node.this, exp.Subquery) for node in froms)

    def where(self) -> exp.Where | None:
        """The statement's WHERE clause, or None when it has none."""
        return self.tree.find(exp.Where) if self.tree is not None else None

    def where_sql(self) -> str:
        """The WHERE clause rendered with its leading space, or empty string.

        Every probe that narrows a statement to the rows it touches carries the
        statement's own predicate, and they all rendered it the same way.
        """
        where = self.where()
        return f" {where.sql(dialect=DIALECT)}" if where else ""
