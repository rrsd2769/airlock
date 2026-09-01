"""Test doubles.

`FakeCatalog` is the second adapter at the catalog seam, and the reason the seam
is worth having. Before it, a test that needed the gateway to see a primary key
had to teach a fake connection to recognise the SQL the catalog happened to emit
-- `"EXA_ALL_CONSTRAINT_COLUMNS" in query`. Reword the query and the fake fell
through to its empty branch, the key came back missing, the compensating
statement quietly degraded to its keyless form, and the test still passed while
pinning the wrong behaviour.

Now a test says which columns and keys exist, in Python, and never sees catalog
SQL at all.
"""
from __future__ import annotations

from airlock.catalog import CatalogTable, TextColumn


class FakeCatalog:
    """An in-memory answer to the catalog's four questions."""

    def __init__(self, *, columns=(), keys=None, tables=()):
        self._columns = list(columns)
        self._keys = dict(keys or {})
        self._tables = list(tables)
        self.asked: list[tuple] = []

    def text_columns(self, *, tables=None, schema=None, min_width=20):
        self.asked.append(("text_columns", tuple(tables or ()), schema))
        wanted = {t.upper() for t in (tables or ())}
        out = []
        for c in self._columns:
            if c.width < min_width:
                continue
            if tables is not None and f"{c.schema}.{c.table}" not in wanted:
                continue
            if schema is not None and c.schema != schema.upper():
                continue
            out.append(c)
        return out

    def primary_key(self, table):
        self.asked.append(("primary_key", table))
        return list(self._keys.get(table, []))

    def tables(self, schema, *, prefix=None, older_than_days=None):
        self.asked.append(("tables", schema, prefix, older_than_days))
        return [t for t in self._tables
                if prefix is None or t.name.startswith(prefix)]


def text(schema, table, name, width=200) -> TextColumn:
    """A free-text column, for readability at the call site."""
    return TextColumn(schema=schema, table=table, name=name, width=width)


def table(name, created=None) -> CatalogTable:
    return CatalogTable(name=name, created=created)
