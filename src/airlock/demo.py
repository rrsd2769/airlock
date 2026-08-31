"""Scripted walk-through of what the airlock actually stops.

    uv run python -m airlock.demo
"""
from __future__ import annotations

import textwrap

from .db import connect
from .gateway import Airlock
from . import ledger

SCENARIOS: list[tuple[str, str]] = [
    ("A reasonable question the agent should be allowed to ask",
     "SELECT N_NAME, COUNT(*) AS CUSTOMERS FROM TPCH.CUSTOMER c "
     "JOIN TPCH.NATION n ON c.C_NATIONKEY = n.N_NATIONKEY GROUP BY N_NAME"),

    ("Agent reaches for raw contact details",
     "SELECT C_NAME, C_PHONE, C_ADDRESS FROM TPCH.CUSTOMER LIMIT 50"),

    ("SELECT * pulls the protected columns implicitly",
     "SELECT * FROM TPCH.CUSTOMER LIMIT 10"),

    ("Balance requested raw, not aggregated (k-anonymity)",
     "SELECT C_CUSTKEY, C_ACCTBAL FROM TPCH.CUSTOMER ORDER BY C_ACCTBAL DESC LIMIT 5"),

    ("Same column, aggregated into groups large enough to hide in",
     "SELECT C_MKTSEGMENT, AVG(C_ACCTBAL) AS AVG_BAL, COUNT(*) AS N "
     "FROM TPCH.CUSTOMER GROUP BY C_MKTSEGMENT"),

    ("Aggregated, but sliced until the groups are too small to hide in",
     "SELECT C_NATIONKEY, C_MKTSEGMENT, AVG(C_ACCTBAL) AS AVG_BAL "
     "FROM TPCH.CUSTOMER GROUP BY C_NATIONKEY, C_MKTSEGMENT"),

    ("Agent reads customer notes -- one of them is addressed to the agent",
     "SELECT C_NAME, C_COMMENT FROM TPCH.CUSTOMER WHERE C_CUSTKEY BETWEEN 400 AND 420"),

    ("The same column, on a slice with nothing planted in it",
     "SELECT C_NAME, C_COMMENT FROM TPCH.CUSTOMER WHERE C_NATIONKEY = 3"),

    ("A write whose blast radius is small",
     "UPDATE TPCH.CUSTOMER SET C_COMMENT = 'reviewed' WHERE C_CUSTKEY = 1"),

    ("A write that would rewrite most of the table",
     "UPDATE TPCH.CUSTOMER SET C_COMMENT = 'reviewed' WHERE C_ACCTBAL > 0"),

    ("Agent tries to cover its tracks",
     "DELETE FROM AIRLOCK.LEDGER"),
]


def main() -> None:
    conn = connect()
    gate = Airlock(conn, principal="demo-agent")

    for title, sql in SCENARIOS:
        print("\n" + "=" * 78)
        print(title)
        print("-" * 78)
        print(textwrap.fill(sql, 76, subsequent_indent="  "))
        result = gate.submit(sql)
        marker = {"ALLOW": "ALLOWED", "DENY": "BLOCKED",
                  "REQUIRE_APPROVAL": "HELD FOR APPROVAL"}[result.decision]
        print(f"\n  -> {marker}   (ledger #{result.seq})")
        print(f"     {result.reason}")
        if result.affected_rows is not None:
            print(f"     measured blast radius: {result.affected_rows} rows")
        if result.min_group is not None:
            print(f"     measured smallest group: {result.min_group} rows")
        if result.taint_max is not None:
            print(f"     worst taint in the result set: {result.taint_max:.2f}")
        if result.rows:
            print(f"     returned {len(result.rows)} rows")

    print("\n" + "=" * 78)
    print("Ledger integrity")
    print("-" * 78)
    findings = ledger.verify(conn)
    print("  chain intact" if not findings else f"  TAMPERING DETECTED: {findings}")


if __name__ == "__main__":
    main()
