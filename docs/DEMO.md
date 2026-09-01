# Demo script (3 minutes)

The submission allows a maximum of 3 minutes. This is the running order.

## 0:00 — The setup (20s)

> "Exasol is building the agentic database. Agents connect over MCP and run SQL
> unattended. Exasol's own MCP server ships with a warning that those agents can
> leak, corrupt, or delete your data — and that you must bring your own
> governance. Nobody has. Once the agent is inside the database, nothing watches
> it."

## 0:20 — Ungoverned baseline (20s)

Agent connected to the stock MCP server. Ask it for customer contact details.
It complies instantly. Ask it to clean up some records. It rewrites 2,729 rows.
No record of either.

## 0:40 — Same agent, through AIRLOCK (40s)

Reconnect the agent to the AIRLOCK MCP server. Same two requests.

- Contact details → **BLOCKED**, with the policy name and the reason.
- `SELECT *` → still **BLOCKED**; the protected column can't be smuggled.
- Aggregate over the same column, grouped by market segment → **ALLOWED**.
  The point is precision, not a wall.
- The same aggregate sliced by nation *and* segment → **BLOCKED**: smallest
  group is 10 rows, k=20 required.

> "Aggregating is not the same as being anonymous. What hides a person is how
> many people share their bucket — so we measure the buckets."

## 1:20 — Blast radius (30s)

The cleanup write. AIRLOCK rewrites it into `SELECT COUNT(*)`, runs it, and
holds the statement: **2,729 rows, cap is 500**.

> "That's not an estimate from the query planner. We counted. We can afford to
> count on every single write because the thing underneath is a columnar MPP
> analytics engine — this is the one architecture where a real preflight is
> cheap."

Show the generated rollback statement.

## 1:50 — Taint (25s)

```bash
uv run python -m airlock.taint --schema TPCH
```

Eighteen free-text columns swept in half a second. Eight rows in the warehouse
are carrying instructions addressed to whatever model reads them next — the
worst is a supplier's own description containing forged chat delimiters and
`drop table AIRLOCK.LEDGER`.

Then ask the agent for customer notes across the range that holds one:

- `SELECT C_NAME, C_COMMENT ... WHERE C_CUSTKEY BETWEEN 400 AND 420` →
  **BLOCKED**, taint 0.85.
- The same columns on a clean slice → **ALLOWED**, taint 0.00.

> "Everyone scans the prompt. The attack isn't in the prompt — it's in a row
> somebody was allowed to write two years ago. So we scan the rows on the way
> out. Scoring all three text columns of a 120,000-row table is 185
> milliseconds, because the scoring happens next to the data."

## 2:15 — The ledger (20s)

Every decision, hash-chained. Run `verify_ledger` → intact.

Then edit one historical row directly in SQL — as an insider would — and run it
again. The chain breaks at exactly that sequence number, and every entry after
it is flagged. The verification runs *inside* Exasol; the audit trail never
leaves to be trusted.

## 2:35 — Replay (20s)

```bash
uv run python -m airlock.replay --set acctbal-k-anon=100
```

Nothing is written to `AIRLOCK.POLICY` — this asks what the change *would* have
cost before anyone lives with it.

> "Sixteen queries we allowed would be blocked under the tighter rule — each
> one a group of 94 people where we now want 100. Loosen it to k=5 instead and 49
> statements we refused would have passed. That's the entire decision history
> re-decided, and it comes back instantly."

The reverse direction reads just as well, and is a good one to have ready if a
judge asks:

```bash
uv run python -m airlock.replay --set write-blast-radius=100   # 10 more writes held
uv run python -m airlock.replay --set block-tainted-rows=0.4   #  8 more withheld
uv run python -m airlock.replay --disable no-raw-pii-phone     # 17 refusals undone
```

Every threshold in the policy set is replayable, because every measurement the
decision rested on is in the ledger.

> "Replay works because the policy decision is a pure function and the ledger
> already stores what it needs. We never re-run the agent's SQL, and we never
> touch the customer tables."

## 2:55 — Close (5s)

> "The policy decision is a SQL query, not a model call. You don't govern an
> autonomous agent with another autonomous agent."

---

## Before recording

Generate a decision history worth replaying — a fresh ledger has nothing to
diff:

```bash
uv run python scripts/apply_sql.py sql/30_taint_seed.sql   # plant the payloads
uv run python -m airlock.taint --schema TPCH               # build the inventory
uv run python -m airlock.traffic --count 400               # build the history
```

`./scripts/bootstrap.sh` already does the first two.

Every statement goes through the real gateway, so the ledger is evidence rather
than fixture data. The numbers quoted above are from `--count 400 --seed 7`;
re-run the replay commands and use whatever you actually get.

## Recording notes

- Record at 1920×1080, terminal font ≥ 16pt.
- Two panes: agent chat on the left, AIRLOCK console on the right.
- No dead air while queries run — every step here is sub-second on this dataset.
