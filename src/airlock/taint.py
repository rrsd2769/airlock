"""The data-side sweep.

Everyone scans the prompt. Almost nobody scans the rows coming back -- which is
where injection against a database agent actually lives, planted months earlier
in a column that legitimately accepts free text from outside.

This sweeps every free-text column in a schema through AIRLOCK.SCAN_TAINT and
records what scores above zero in AIRLOCK.TAINT. It is catalog-driven: point it
at a schema and it finds the columns itself, so a new table does not need anyone
to remember to add it here.

The whole sweep is a single INSERT ... SELECT per column. The scoring runs
*inside* the database, next to the data, on an engine built to read one column
of a hundred thousand rows -- so the inventory is a scan, not an export.

    uv run python -m airlock.taint --schema TPCH
"""
from __future__ import annotations

import argparse
import time

import pyexasol

from .db import connect

# An injection needs somewhere to sit. Columns narrower than this hold codes and
# flags -- phone numbers, priorities, ship modes -- not sentences.
MIN_TEXT_WIDTH = 20


def text_columns(conn: pyexasol.ExaConnection, schema: str) -> list[dict]:
    """Every free-text column in the schema, widest first."""
    return conn.execute(
        """
        SELECT COLUMN_TABLE AS TBL, COLUMN_NAME AS COL, COLUMN_MAXSIZE AS WIDTH
        FROM SYS.EXA_ALL_COLUMNS
        WHERE COLUMN_SCHEMA = {schema}
          AND COLUMN_TYPE LIKE 'VARCHAR%'
          AND COLUMN_MAXSIZE >= {min_width}
        ORDER BY COLUMN_MAXSIZE DESC, COLUMN_TABLE, COLUMN_NAME
        """,
        {"schema": schema.upper(), "min_width": MIN_TEXT_WIDTH},
    ).fetchall()


def sweep_column(conn: pyexasol.ExaConnection, schema: str, table: str,
                 column: str) -> int:
    """Score one column and record everything that scores above zero.

    ROWID identifies the row without needing to know the table's key, which is
    what keeps this catalog-driven rather than a hand-maintained registry.
    """
    conn.execute(
        f"""
        INSERT INTO AIRLOCK.TAINT
            (SCHEMA_NAME, TABLE_NAME, COLUMN_NAME, ROW_KEY, SCORE, PATTERNS, SAMPLE)
        SELECT '{schema}', '{table}', '{column}', RK,
               TO_NUMBER(SUBSTR(S, 1, INSTR(S, '|') - 1)),
               SUBSTR(S, INSTR(S, '|') + 1),
               SUBSTR(TXT, 1, 4000)
        FROM (
            SELECT ROWID AS RK,
                   {column} AS TXT,
                   AIRLOCK.SCAN_TAINT({column}) AS S
            FROM {schema}.{table}
        )
        WHERE TO_NUMBER(SUBSTR(S, 1, INSTR(S, '|') - 1)) > 0
        """
    )
    return conn.last_statement().rowcount()


def sweep(conn: pyexasol.ExaConnection, schema: str,
          verbose: bool = False) -> tuple[int, int, float]:
    """Rescan the schema from scratch. Returns (columns, rows_found, seconds)."""
    conn.execute("DELETE FROM AIRLOCK.TAINT WHERE SCHEMA_NAME = {s}",
                 {"s": schema.upper()})

    started = time.perf_counter()
    columns = text_columns(conn, schema)
    found = 0
    for c in columns:
        n = sweep_column(conn, schema.upper(), c["TBL"], c["COL"])
        found += n
        if verbose and n:
            print(f"    {c['TBL'] + '.' + c['COL']:<28} {n} tainted")
    conn.commit()
    return len(columns), found, time.perf_counter() - started


def worst(conn: pyexasol.ExaConnection, limit: int = 10) -> list[dict]:
    return conn.execute(
        "SELECT TABLE_NAME, COLUMN_NAME, ROW_KEY, SCORE, PATTERNS, SAMPLE "
        f"FROM AIRLOCK.TAINT ORDER BY SCORE DESC, TABLE_NAME LIMIT {int(limit)}"
    ).fetchall()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m airlock.taint",
        description="Sweep a schema's free text for instructions aimed at an agent.")
    parser.add_argument("--schema", default="TPCH")
    parser.add_argument("--top", type=int, default=10)
    args = parser.parse_args()

    conn = connect()
    print(f"Sweeping {args.schema.upper()} ...")
    n_cols, n_found, seconds = sweep(conn, args.schema, verbose=True)

    scanned = conn.execute(
        "SELECT COUNT(*) AS N FROM AIRLOCK.TAINT WHERE SCHEMA_NAME = {s}",
        {"s": args.schema.upper()}).fetchone()["N"]

    print("\n" + "=" * 78)
    print(f"  {n_cols} free-text columns swept in {seconds:.2f}s")
    print(f"  {scanned} rows carry instructions aimed at whatever reads them next")
    print("=" * 78)

    rows = worst(conn, args.top)
    if not rows:
        print("\n  nothing found -- run sql/30_taint_seed.sql to plant the demo payloads")
        return

    print(f"\n  worst {len(rows)}:\n")
    for r in rows:
        print(f"    {float(r['SCORE']):.2f}  {r['TABLE_NAME']}.{r['COLUMN_NAME']}")
        print(f"          {r['SAMPLE'][:88]}")
        print(f"          matched: {r['PATTERNS'][:88]}")
    print()


if __name__ == "__main__":
    main()
