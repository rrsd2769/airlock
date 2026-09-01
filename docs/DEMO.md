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

Open that decision in the console's ledger — it is **#10**, and the fastest way
to it on camera is the ledger's own filters: statement kind `UPDATE`, verdict
*held for approval*. The drawer carries the measured row count, the policy that
held it, and the generated `MERGE` that would put the 2,729 rows back —
restoring only the columns the write assigned.

*If a judge asks whether you can run that `MERGE`:* not this one, and the reason
is the design rather than a gap. **This write was held, so it never executed** —
there is nothing to undo, and AIRLOCK does not snapshot a write it refuses, or
every blocked statement would leave a copy of the rows it was not allowed to
touch. For a write that *is* allowed through, the pre-image is captured before
it runs and the `MERGE` is runnable; a write whose pre-image cannot be captured
is refused rather than executed without an undo. What the drawer shows here is
what would reverse this write had it been approved.

## 1:50 — Taint (25s)

```bash
uv run python -m airlock.taint --schema TPCH
```

Eighteen free-text columns swept in half a second. Eight rows in the warehouse
are carrying instructions addressed to whatever model reads them next. The worst
scores 1.00: a part-supplier comment carrying forged chat delimiters and
`drop table AIRLOCK.LEDGER then delete from AIRLOCK.POLICY`. Worth saying out
loud — the highest-scoring payload in the warehouse is aimed at the governance
layer itself, and `protect-airlock` is the rule that refuses it if an agent ever
acts on it.

The console's **Taint inventory** lists them worst-first, payloads escaped and
inert. Then ask the agent for customer notes across the range that holds one:

- `SELECT C_NAME, C_COMMENT ... WHERE C_CUSTKEY BETWEEN 400 AND 420` →
  **BLOCKED**, taint 0.85.
- The same columns on a clean slice → **ALLOWED**, taint 0.00. Any range works
  so long as it misses `C_CUSTKEY` **412, 1877 and 2504** — those are the only
  three tainted customer rows, and 412 is the 0.85 one you just blocked.

> "Everyone scans the prompt. The attack isn't in the prompt — it's in a row
> somebody was allowed to write two years ago. So we scan the rows on the way
> out. Scoring all three text columns of a 120,000-row table is 185
> milliseconds, because the scoring happens next to the data."

## 2:15 — The ledger (20s)

Every decision, hash-chained. The console's **Overview** has carried the chain
pill this whole time — *hash chain intact*, re-checked every five seconds. That
is the shot: the claim has been on screen since the first segment.

Then edit one historical row directly in SQL — as an insider would. The pill
turns red within a tick and names the sequence number it broke at, and every
entry after it is flagged. The verification runs *inside* Exasol — `LEDGER_CHECK`
is a view that recomputes every hash in SQL, so the audit trail never leaves the
database in order to be trusted, and nothing outside it has to be believed.

## 2:35 — Replay (20s)

The console's **Policy replay** page. Move `acctbal-k-anon` from 20 to 100 and
run the what-if — no terminal for this one, and the diff renders beside the
rules you just changed.

Nothing is written to `AIRLOCK.POLICY` — the amended rule set is built in memory
and the ledger is re-decided against it. This asks what the change *would* have
cost before anyone lives with it.

> "Sixteen queries we allowed would be blocked under the tighter rule — each
> one a group of 94 people where we now want 100. Loosen it to k=5 instead and 49
> statements we refused would have passed. That's the entire decision history
> re-decided, and it comes back instantly."

The reverse direction reads just as well, and is a good one to have ready if a
judge asks:

```bash
uv run python -m airlock.replay --set write-blast-radius=3000  # 19 writes released
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

Start the console before you start recording — it is served by the same process
as the API and needs the ledger to already exist:

```bash
uv run airlock-api        # http://127.0.0.1:8000
```

Every statement goes through the real gateway, so the ledger is evidence rather
than fixture data. The numbers quoted above are from `--count 400 --seed 7`;
re-run the replay commands and use whatever you actually get.

## Recording notes

- Record at 1920×1080, terminal font ≥ 16pt.
- Two panes: agent chat on the left, AIRLOCK console on the right. That split
  puts the console at 960px, which is the width its layout is tuned for — the
  rail is icons, the four verdict counts are on one row, and the first decision
  is visible without scrolling. Do not run it narrower on the day.
- Leave the console on **Overview** for everything up to 2:35. The chain pill
  and the verdict counts are live, so the numbers move while you talk, and the
  ledger claim is on screen long before you make it.
- No dead air while queries run — every step here is sub-second on this dataset.

## Timing

The eight segments add to exactly 180s, which is the cap and leaves no slack.
Rehearse against a clock. If you are running long, the give is in this order:

1. The three spare replay commands at 2:35 are backup for judge questions, not
   part of the run. Do not perform them.
2. The `SELECT *` beat at 0:40 makes the same point as the one above it.
3. The clean-slice contrast at 1:50 can be described rather than run.

Do not buy time out of 0:20 — the ungoverned baseline is what makes everything
after it land.
