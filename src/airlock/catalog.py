"""What the database knows about itself.

Four things in AIRLOCK need the Exasol catalog: the gateway resolves which text
columns a query would return and which key its compensating statement can match
on, the taint sweep finds every free-text column in a schema, and snapshot
retention finds the pre-image tables and how old they are.

Written per caller, those four re-derive the same handful of facts every time --
that catalog names are uppercase, that a schema qualifier is required, which
aliases come back, that names taken from an agent's statement must be bound
rather than pasted, and that `CREATED` is stamped on a different clock from
`CURRENT_TIMESTAMP`. That last one was a real bug: retention read every snapshot
as two hours older than it was, because the session's timezone is not the
database's. Fixing it in one function fixed one function.

So the rule lives here now, once, behind four verbs. The MCP surface's catalog
queries are deliberately *not* here: those are statements an agent asked for,
and they go through `submit()` so that policy sees them and the ledger records
them. This module is for lookups AIRLOCK makes on its own behalf.
"""
from __future__ import annotations

from dataclasses import dataclass

import pyexasol

# An injection needs somewhere to sit. Columns narrower than this hold codes and
# flags -- phone numbers, priorities, ship modes -- not sentences.
MIN_TEXT_WIDTH = 20


@dataclass(frozen=True)
class TextColumn:
    """A free-text column, wide enough to hide an instruction in."""

    schema: str
    table: str
    name: str
    width: int

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.table}.{self.name}"


@dataclass(frozen=True)
class CatalogTable:
    """A table and when the database says it was created."""

    name: str
    created: object = None


class Catalog:
    """The catalog, as the four questions AIRLOCK actually asks it.

    Holds a connection and a key cache; a session tends to write to the same few
    tables, and the primary key of one does not change underneath it.
    """

    def __init__(self, conn: pyexasol.ExaConnection) -> None:
        self.conn = conn
        self._key_cache: dict[str, list[str]] = {}

    # -- columns ------------------------------------------------------------

    def text_columns(self, *, tables: list[str] | None = None,
                     schema: str | None = None,
                     min_width: int = MIN_TEXT_WIDTH) -> list[TextColumn]:
        """Free-text columns, either in named tables or across a whole schema.

        `tables` are `SCHEMA.TABLE` strings, and they may come out of an agent's
        own statement -- so they are bound as parameters, never pasted. A quote
        in a table name would otherwise rewrite the predicate and return every
        VARCHAR column in the database, AIRLOCK's own included.

        Widest first, which is the order the taint sweep wants and the order
        nobody else cares about.
        """
        params: dict[str, object] = {"min_width": int(min_width)}
        if tables is not None:
            pairs = [t.split(".", 1) for t in tables if "." in t]
            if not pairs:
                return []
            clauses = []
            for i, (owner, name) in enumerate(pairs):
                clauses.append(f"(COLUMN_SCHEMA = {{s{i}}} AND COLUMN_TABLE = {{t{i}}})")
                params[f"s{i}"], params[f"t{i}"] = owner.upper(), name.upper()
            predicate = " OR ".join(clauses)
        elif schema is not None:
            predicate = "COLUMN_SCHEMA = {schema}"
            params["schema"] = schema.upper()
        else:
            raise ValueError("text_columns needs either tables or a schema")

        rows = self.conn.execute(
            "SELECT COLUMN_SCHEMA AS SCH, COLUMN_TABLE AS TBL, "
            "COLUMN_NAME AS COL, COLUMN_MAXSIZE AS WIDTH "
            "FROM SYS.EXA_ALL_COLUMNS "
            f"WHERE ({predicate}) AND COLUMN_TYPE LIKE 'VARCHAR%' "
            "AND COLUMN_MAXSIZE >= {min_width} "
            "ORDER BY COLUMN_MAXSIZE DESC, COLUMN_TABLE, COLUMN_NAME",
            params,
        ).fetchall()
        return [TextColumn(schema=r["SCH"], table=r["TBL"],
                           name=r["COL"], width=int(r["WIDTH"])) for r in rows]

    # -- keys ---------------------------------------------------------------

    def primary_key(self, table: str | None) -> list[str]:
        """Primary key of a table, in key order. Empty when it has none.

        The compensating statement has to match each snapshotted pre-image row
        back to the row the write changed, and the key is what does that. Read
        from the catalog rather than configured, so a new table needs no change
        here.
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
                {"schema": schema.upper(), "tbl": name.upper()},
            ).fetchall()
        except Exception:  # noqa: BLE001 - no key found means a narrower rollback
            return []
        keys = [r["C"] for r in rows]
        self._key_cache[table] = keys
        return keys

    # -- tables -------------------------------------------------------------

    def tables(self, schema: str, *, prefix: str | None = None,
               older_than_days: int | None = None) -> list[CatalogTable]:
        """Tables in a schema, newest first, optionally by name and by age.

        `older_than_days` is compared against SYSTIMESTAMP, not
        CURRENT_TIMESTAMP. The catalog stamps CREATED on the database clock
        while CURRENT_TIMESTAMP is the session's timezone; compared against each
        other, every table looks older or younger than it is by the session's
        offset -- two hours on the host this was found on, and whatever the
        client happens to be set to anywhere else.

        This is the only place in AIRLOCK that compares a catalog timestamp to
        now, which is the point: there is no second place to get it wrong.
        """
        params: dict[str, object] = {"schema": schema.upper()}
        name_filter = ""
        if prefix is not None:
            # '_' is a LIKE wildcard, and every snapshot name contains one.
            name_filter = " AND OBJECT_NAME LIKE {pattern} ESCAPE '@'"
            params["pattern"] = f"{prefix.replace('_', '@_')}%"
        age_filter = ("" if older_than_days is None
                      else f" AND CREATED < SYSTIMESTAMP - INTERVAL "
                           f"'{int(older_than_days)}' DAY")
        rows = self.conn.execute(
            "SELECT OBJECT_NAME AS NAME, CREATED FROM SYS.EXA_ALL_OBJECTS "
            "WHERE ROOT_NAME = {schema} AND OBJECT_TYPE = 'TABLE'"
            f"{name_filter}{age_filter} ORDER BY CREATED DESC",
            params,
        ).fetchall()
        return [CatalogTable(name=r["NAME"], created=r.get("CREATED")) for r in rows]
