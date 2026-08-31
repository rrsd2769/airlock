# Demo script (3 minutes)

The submission allows a maximum of 3 minutes. This is the running order.

## 0:00 — The setup (20s)

> "Exasol is building the agentic database. Agents connect over MCP and run SQL
> unattended. Exasol's own MCP server ships with a warning that those agents can
> leak, corrupt, or delete your data — and that you must bring your own
> governance. Nobody has. Once the agent is inside the database, nothing watches
> it."

## 0:20 — Ungoverned baseline (25s)

Agent connected to the stock MCP server. Ask it for customer contact details.
It complies instantly. Ask it to clean up some records. It rewrites 2,900 rows.
No record of either.

## 0:45 — Same agent, through AIRLOCK (45s)

Reconnect the agent to the AIRLOCK MCP server. Same two requests.

- Contact details → **BLOCKED**, with the policy name and the reason.
- `SELECT *` → still **BLOCKED**; the protected column can't be smuggled.
- Aggregate over the same column → **ALLOWED**. The point is precision, not a wall.

## 1:30 — Blast radius (35s)

The cleanup write. AIRLOCK rewrites it into `SELECT COUNT(*)`, runs it, and
holds the statement: **2,900 rows, cap is 500**.

> "That's not an estimate from the query planner. We counted. We can afford to
> count on every single write because the thing underneath is a columnar MPP
> analytics engine — this is the one architecture where a real preflight is
> cheap."

Show the generated rollback statement.

## 2:05 — The ledger (25s)

Every decision, hash-chained. Run `verify_ledger` → intact.

Then edit one historical row directly in SQL — as an insider would — and run it
again. The chain breaks at exactly that sequence number, and every entry after
it is flagged. The verification runs *inside* Exasol; the audit trail never
leaves to be trusted.

## 2:30 — Replay (25s)

Tighten `acctbal-k-anon` from k=20 to k=100. Replay the full ledger.

> "Thirty-four queries we allowed last week would be blocked under the new
> policy. Six that we blocked would now pass. That's a scan over the whole
> decision history, and it comes back instantly."

## 2:55 — Close (5s)

> "The policy decision is a SQL query, not a model call. You don't govern an
> autonomous agent with another autonomous agent."

---

## Recording notes

- Record at 1920×1080, terminal font ≥ 16pt.
- Two panes: agent chat on the left, AIRLOCK console on the right.
- No dead air while queries run — every step here is sub-second on this dataset.
