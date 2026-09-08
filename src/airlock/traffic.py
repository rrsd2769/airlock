"""Synthetic agent traffic.

Replay is only interesting against a history worth replaying, so this drives a
realistic mix of agent statements through the airlock: analytics an agent should
be allowed to run, questions that quietly reach for identifying data, writes of
wildly different blast radius, and the occasional attempt on the airlock itself.

Nothing here bypasses the gateway. Every statement takes the same path a real
MCP client's would, which is what makes the resulting ledger real evidence
rather than fixture data.

    uv run python -m airlock.traffic --count 400
"""
from __future__ import annotations

import argparse
import random
from dataclasses import dataclass

from .approval import approve, pending
from .db import connect
from .gateway import Airlock

SEGMENTS = ["BUILDING", "AUTOMOBILE", "MACHINERY", "HOUSEHOLD", "FURNITURE"]
PRIORITIES = ["1-URGENT", "2-HIGH", "3-MEDIUM", "4-NOT SPECIFIED", "5-LOW"]
SHIPMODES = ["AIR", "RAIL", "SHIP", "TRUCK", "MAIL", "FOB", "REG AIR"]


def _reads(rng: random.Random) -> list[str]:
    """Ordinary analytics. Allowed, and the bulk of what an agent really does."""
    return [
        "SELECT N_NAME, COUNT(*) AS CUSTOMERS FROM TPCH.CUSTOMER c "
        "JOIN TPCH.NATION n ON c.C_NATIONKEY = n.N_NATIONKEY GROUP BY N_NAME",

        f"SELECT O_ORDERPRIORITY, COUNT(*) AS N FROM TPCH.ORDERS "
        f"WHERE O_ORDERSTATUS = '{rng.choice(['O', 'F', 'P'])}' GROUP BY O_ORDERPRIORITY",

        "SELECT L_SHIPMODE, SUM(L_QUANTITY) AS QTY FROM TPCH.LINEITEM GROUP BY L_SHIPMODE",

        f"SELECT P_BRAND, AVG(P_RETAILPRICE) AS AVG_PRICE FROM TPCH.PART "
        f"WHERE P_SIZE > {rng.randint(1, 30)} GROUP BY P_BRAND",

        "SELECT R_NAME, COUNT(*) AS NATIONS FROM TPCH.NATION n "
        "JOIN TPCH.REGION r ON n.N_REGIONKEY = r.R_REGIONKEY GROUP BY R_NAME",

        f"SELECT L_RETURNFLAG, L_LINESTATUS, COUNT(*) AS N, SUM(L_EXTENDEDPRICE) AS REV "
        f"FROM TPCH.LINEITEM WHERE L_SHIPMODE = '{rng.choice(SHIPMODES)}' "
        f"GROUP BY L_RETURNFLAG, L_LINESTATUS",

        "SELECT C_MKTSEGMENT, COUNT(*) AS N FROM TPCH.CUSTOMER GROUP BY C_MKTSEGMENT",
    ]


def _k_anon_reads(rng: random.Random) -> list[str]:
    """Aggregates over the protected balance column.

    Deliberately spread across group sizes -- coarse groupings are comfortably
    anonymous, finer ones are not -- so that moving k actually moves decisions.
    """
    return [
        # ~600 customers per group: safe at any plausible k.
        "SELECT C_MKTSEGMENT, AVG(C_ACCTBAL) AS AVG_BAL FROM TPCH.CUSTOMER "
        "GROUP BY C_MKTSEGMENT",

        # ~120 per group: safe at k=20, still safe at k=100.
        "SELECT C_NATIONKEY, AVG(C_ACCTBAL) AS AVG_BAL, COUNT(*) AS N "
        "FROM TPCH.CUSTOMER GROUP BY C_NATIONKEY",

        # ~24 per group: safe at k=20, NOT safe at k=100.
        "SELECT C_NATIONKEY, C_MKTSEGMENT, AVG(C_ACCTBAL) AS AVG_BAL "
        "FROM TPCH.CUSTOMER GROUP BY C_NATIONKEY, C_MKTSEGMENT",

        # Filtered further: small groups, blocked even at k=20.
        f"SELECT C_NATIONKEY, C_MKTSEGMENT, AVG(C_ACCTBAL) AS AVG_BAL "
        f"FROM TPCH.CUSTOMER WHERE C_ACCTBAL > {rng.randint(4000, 8000)} "
        f"GROUP BY C_NATIONKEY, C_MKTSEGMENT",

        f"SELECT C_NATIONKEY, MAX(C_ACCTBAL) AS TOP_BAL FROM TPCH.CUSTOMER "
        f"WHERE C_MKTSEGMENT = '{rng.choice(SEGMENTS)}' GROUP BY C_NATIONKEY",
    ]


def _text_reads(rng: random.Random) -> list[str]:
    """Free-text reads -- notes, comments, descriptions.

    This is how an agent meets a prompt injection: not in its prompt, but in a
    column somebody was allowed to write to. Some of these slices contain the
    payloads planted by sql/30_taint_seed.sql and some do not.
    """
    lo = rng.choice([1, 200, 400, 900, 1500, 1800, 2400, 2500])
    return [
        f"SELECT C_NAME, C_COMMENT FROM TPCH.CUSTOMER "
        f"WHERE C_CUSTKEY BETWEEN {lo} AND {lo + 20}",

        f"SELECT C_COMMENT FROM TPCH.CUSTOMER WHERE C_NATIONKEY = {rng.randint(0, 24)}",

        f"SELECT O_COMMENT FROM TPCH.ORDERS WHERE O_ORDERKEY BETWEEN {lo * 2} "
        f"AND {lo * 2 + 500}",

        "SELECT S_NAME, S_COMMENT FROM TPCH.SUPPLIER",

        f"SELECT P_NAME, P_COMMENT FROM TPCH.PART WHERE P_SIZE = {rng.randint(1, 50)}",

        f"SELECT L_COMMENT FROM TPCH.LINEITEM WHERE L_ORDERKEY = "
        f"{rng.choice([1863, 1863, rng.randint(1, 6000)])}",

        "SELECT N_NAME, N_COMMENT FROM TPCH.NATION",
    ]


def _identifying_reads(rng: random.Random) -> list[str]:
    """Questions that reach for the individual. All of these should be refused."""
    return [
        f"SELECT C_NAME, C_PHONE FROM TPCH.CUSTOMER LIMIT {rng.randint(5, 50)}",
        "SELECT C_NAME, C_ADDRESS, C_ACCTBAL FROM TPCH.CUSTOMER "
        "ORDER BY C_ACCTBAL DESC LIMIT 10",
        f"SELECT * FROM TPCH.CUSTOMER WHERE C_CUSTKEY = {rng.randint(1, 3000)}",
        "SELECT C_CUSTKEY, C_ACCTBAL FROM TPCH.CUSTOMER ORDER BY C_ACCTBAL DESC LIMIT 5",
        f"SELECT C_PHONE FROM TPCH.CUSTOMER WHERE C_NATIONKEY = {rng.randint(0, 24)}",
    ]


def _wide_writes(rng: random.Random) -> list[str]:
    """Writes that touch far too much. Measured, then held for approval."""
    return [
        f"UPDATE TPCH.CUSTOMER SET C_COMMENT = 'bulk-tagged' "
        f"WHERE C_ACCTBAL > {rng.randint(0, 2000)}",
        f"UPDATE TPCH.ORDERS SET O_ORDERPRIORITY = '{rng.choice(PRIORITIES)}' "
        f"WHERE O_ORDERSTATUS = '{rng.choice(['O', 'F'])}'",
        f"DELETE FROM TPCH.LINEITEM WHERE L_SHIPMODE = '{rng.choice(SHIPMODES)}'",
        # A whole nation is ~120 customers here, which is under the 500-row cap:
        # this used to be allowed, execute, and rewrite the very column the
        # k-anonymity demo measures its group sizes over. Widen the predicate so
        # the statement is what this function says it is -- held, not run.
        f"UPDATE TPCH.CUSTOMER SET C_MKTSEGMENT = '{rng.choice(SEGMENTS)}' "
        f"WHERE C_NATIONKEY < {rng.randint(8, 20)}",
    ]


def _narrow_writes(rng: random.Random) -> list[str]:
    """Single-row corrections. Small enough to pass, and they really execute.

    Because they execute, they must not land on a row the demo depends on.
    sql/30_taint_seed.sql plants payloads at C_CUSTKEY 412, 1877 and 2504, so
    the range starts above the last of them -- otherwise a traffic run can
    quietly overwrite a payload the taint inventory still claims is there.
    """
    key = rng.randint(2600, 3000)
    return [
        f"UPDATE TPCH.CUSTOMER SET C_COMMENT = 'verified by agent' "
        f"WHERE C_CUSTKEY = {key}",
    ]


def _releasable_writes(rng: random.Random) -> list[str]:
    """Wide writes that are held for radius and are safe to actually run.

    The corpus is only evidence of an approval loop if some of its holds were
    really released, which means really executed -- a snapshot table with rows
    in it and a MERGE somebody could run. Every other wide write above is
    unsafe to release for a reason that has nothing to do with policy: they
    rewrite a comment column carrying a planted taint payload, or the market
    segment the k-anonymity groups are counted over, and letting one through
    would quietly invalidate a figure the README quotes. These touch
    O_SHIPPRIORITY, which nothing here reads and nothing in the docs measures,
    on a table with a declared primary key so the compensating MERGE can be
    synthesised at all.
    """
    lo = rng.choice([1, 20000, 48000, 76000, 100000])
    # Orderkeys run one per four in this dataset, so the span is ~1,000 rows.
    hi, pri = lo + 3999, rng.randint(2, 9)
    return [
        # 738 rows: comfortably over the 500-row cap, small enough that the
        # snapshot and its MERGE are readable on camera.
        "UPDATE TPCH.ORDERS SET O_SHIPPRIORITY = 1 WHERE O_ORDERSTATUS = 'P'",
        f"UPDATE TPCH.ORDERS SET O_SHIPPRIORITY = {pri} WHERE O_ORDERKEY BETWEEN {lo} AND {hi}",
    ]


def _attacks(rng: random.Random) -> list[str]:
    """The agent turning on the thing that governs it."""
    return [
        "DELETE FROM AIRLOCK.LEDGER",
        "UPDATE AIRLOCK.POLICY SET IS_ENABLED = FALSE",
        "DROP TABLE TPCH.CUSTOMER",
        "SELECT * FROM AIRLOCK.POLICY",
        "TRUNCATE TABLE AIRLOCK.LEDGER",
    ]


# (generator, weight) -- reads dominate, as they do in real agent traffic.
MIX = [
    (_reads, 26),
    (_k_anon_reads, 24),
    (_text_reads, 22),
    (_identifying_reads, 14),
    (_wide_writes, 8),
    (_narrow_writes, 3),
    (_releasable_writes, 2),
    (_attacks, 3),
]


@dataclass(frozen=True)
class Planned:
    """One generated statement, and whether it is safe to release and run.

    The flag travels with the statement rather than being recovered later by
    matching its text, because by the time a hold is on the queue the only
    thing left to match on is SQL a human could have written by hand.
    """

    sql: str
    releasable: bool = False


def generate(count: int, seed: int) -> list[Planned]:
    rng = random.Random(seed)
    pools, weights = zip(*MIX)
    out = []
    for _ in range(count):
        pool = rng.choices(pools, weights=weights, k=1)[0]
        out.append(Planned(rng.choice(pool(rng)),
                           releasable=pool is _releasable_writes))
    return out


def _release_some(conn, seqs: list[int], rate: float, approver: str,
                  seed: int) -> list[tuple[int, str]]:
    """Send a reproducible share of the run's safe holds back through the airlock.

    The releases go through `approval.approve`, which re-enters
    `gateway.submit`, so an approved statement in the corpus was measured
    twice, snapshotted, executed and chained exactly as it would have been on
    the day -- the same objection that makes the ledger evidence rather than
    fixture data applies to the approval history sitting beside it.
    """
    if not seqs or rate <= 0:
        return []
    chosen = sorted(random.Random(seed).sample(seqs, round(len(seqs) * rate)))
    by_seq = {h.ledger_seq: h.approval_id for h in pending(conn)}
    out = []
    for seq in chosen:
        approval_id = by_seq.get(seq)
        if approval_id is None:
            continue
        result = approve(conn, approval_id, approver,
                         note="released during corpus generation")
        out.append((approval_id, result.decision))
    return out


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m airlock.traffic",
        description="Drive synthetic agent traffic through the airlock.")
    parser.add_argument("--count", type=int, default=400)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--principal", default="demo-agent")
    parser.add_argument("--approve-rate", type=float, default=0.0, metavar="R",
                        help="release this share (0-1) of the holds that are "
                             "safe to execute, so the corpus carries real "
                             "approved writes")
    parser.add_argument("--approve-by", default="alice",
                        help="who the released holds are approved by")
    args = parser.parse_args()

    if not 0.0 <= args.approve_rate <= 1.0:
        raise SystemExit("error: --approve-rate must be between 0 and 1")

    conn = connect()
    gate = Airlock(conn, principal=args.principal)
    statements = generate(args.count, args.seed)

    tally: dict[str, int] = {}
    releasable_holds: list[int] = []
    for i, planned in enumerate(statements, 1):
        result = gate.submit(planned.sql, max_rows=5)
        tally[result.decision] = tally.get(result.decision, 0) + 1
        if planned.releasable and result.decision == "REQUIRE_APPROVAL":
            releasable_holds.append(result.seq)
        if i % 50 == 0:
            print(f"  {i}/{len(statements)} submitted")

    released = _release_some(conn, releasable_holds, args.approve_rate,
                             args.approve_by, args.seed)

    print("\n" + "=" * 78)
    print(f"{len(statements)} statements through the airlock as {args.principal}")
    for decision in ("ALLOW", "REQUIRE_APPROVAL", "DENY"):
        print(f"  {decision:<18} {tally.get(decision, 0)}")
    if released:
        print(f"  released by {args.approve_by:<6} {len(released)} "
              f"of {len(releasable_holds)} releasable holds")
        for approval_id, decision in released:
            print(f"    approval #{approval_id} -> {decision}")
    print("=" * 78)


if __name__ == "__main__":
    main()
