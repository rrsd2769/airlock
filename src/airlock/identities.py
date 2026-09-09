"""Safe views, derived from the rule set rather than written beside it.

Exasol grants are table-level. There is no `GRANT SELECT (C_NAME)` -- so the
only way to withhold one column from a database identity is to give it a view
that never projects the column and no grant on the table underneath.

Which columns to withhold is already written down. `sql/10_policies.sql` says
`no-raw-pii-phone` and `no-raw-pii-addr` deny C_PHONE and C_ADDRESS on
TPCH.CUSTOMER, and the gateway enforces exactly that for traffic coming through
it. A second hand-maintained column list here would be the same claim written
twice, and the two would drift the first time somebody added a rule -- leaving a
policy the gateway enforces and the grants do not, which is worse than having no
views at all because it reads as protection.

So the views are generated from AIRLOCK.POLICY. Adding a COLUMN_ACCESS DENY and
re-running `--apply` is the whole change; there is no second place to edit.

    uv run python -m airlock.identities            # print the DDL
    uv run python -m airlock.identities --apply    # and run it

Run as sys: this creates objects in AIRLOCK over base tables in another schema.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass

import pyexasol

from . import policy

# The identity the safe views exist for: the agent's own database login, used
# when it connects around the gateway rather than through it.
AGENT_USER = "DEMO_AGENT"

SCHEMA = "AIRLOCK"


@dataclass(frozen=True)
class SafeView:
    """One base table, minus the columns the rule set denies."""

    base_schema: str
    base_table: str
    denied: tuple[str, ...]
    projected: tuple[str, ...]

    @property
    def name(self) -> str:
        # Qualified with the base schema, because the rule set is free to deny a
        # column on a CUSTOMER table in two different schemas and two views
        # called V_CUSTOMER would silently be one view.
        return f"{SCHEMA}.V_{self.base_schema}_{self.base_table}"

    @property
    def ddl(self) -> str:
        columns = ",\n       ".join(self.projected)
        return (f"CREATE OR REPLACE VIEW {self.name} AS\n"
                f"SELECT {columns}\n"
                f"  FROM {self.base_schema}.{self.base_table}")

    @property
    def grant(self) -> str:
        return f"GRANT SELECT ON {self.name} TO {AGENT_USER}"


def safe_views(conn: pyexasol.ExaConnection) -> list[SafeView]:
    """A view per table the rule set denies a column on, widest scope first.

    Column order comes from the catalog rather than from the rule set, so the
    view's shape matches the table's -- a `SELECT *` against the view reads the
    way a reader of the base table expects, minus the withheld columns.
    """
    views = []
    for (schema, table), denied in sorted(policy.denied_columns(conn).items()):
        rows = conn.execute(
            "SELECT COLUMN_NAME AS C FROM SYS.EXA_ALL_COLUMNS "
            "WHERE COLUMN_SCHEMA = {schema} AND COLUMN_TABLE = {tbl} "
            "ORDER BY COLUMN_ORDINAL_POSITION",
            {"schema": schema, "tbl": table},
        ).fetchall()
        projected = tuple(r["C"] for r in rows if r["C"].upper() not in denied)
        if not projected:
            # Every column denied. A view of nothing is not a safe view, it is a
            # table the agent has no business reaching at all -- so leave it
            # without one and let the missing grant say so.
            continue
        views.append(SafeView(base_schema=schema, base_table=table,
                              denied=tuple(sorted(denied)), projected=projected))
    return views


def apply(conn: pyexasol.ExaConnection) -> list[SafeView]:
    """Create the views and grant the agent identity SELECT on each."""
    views = safe_views(conn)
    for view in views:
        conn.execute(view.ddl)
        conn.execute(view.grant)
    return views


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m airlock.identities",
        description="Generate the safe views the agent identity reads through.")
    parser.add_argument("--apply", action="store_true",
                        help="run the DDL instead of printing it")
    args = parser.parse_args()

    from .db import connect_admin
    conn = connect_admin()

    views = apply(conn) if args.apply else safe_views(conn)
    if not views:
        print("no COLUMN_ACCESS DENY rules -- nothing to project around")
        return

    verb = "created" if args.apply else "would create"
    print(f"{verb} {len(views)} safe view(s):\n")
    for view in views:
        print(f"  {view.name}")
        print(f"    withholds {', '.join(view.denied)} "
              f"({len(view.projected)} column(s) projected)")
        if not args.apply:
            print("\n" + view.ddl + ";\n" + view.grant + ";\n")


if __name__ == "__main__":
    main()
