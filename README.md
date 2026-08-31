# AIRLOCK

**A control tower for database agents.**

Exasol is being built as *the agentic database*: autonomous agents connect over
MCP and run SQL unattended. Exasol's own MCP server ships with a warning that
those agents can cause data leakage, unauthorized generation, and data
deletion — and that you must supply your own governance.

There isn't any. Once an agent is inside the database, nothing watches it.

AIRLOCK is that missing layer. It is the single controlled passage between an
untrusted agent and protected data. Every statement is analysed, checked against
policy that lives *inside* Exasol, measured for blast radius before it runs, and
written to a tamper-evident ledger.

> The policy decision is a SQL query, not a model call.
> You do not govern an autonomous agent with another autonomous agent.

---

## What it does

**1. Intent firewall.** Statements are parsed into structured features — tables,
columns, joins, aggregation level — and matched against declarative policies.
Column-level bans, principal scoping, and k-anonymity are enforced
deterministically in sub-millisecond time. An unparseable statement is denied,
never waved through.

k-anonymity is *measured*, not assumed. Aggregating is not the same as being
anonymous — what hides a person is how many people share their bucket — so
before releasing an aggregate over a protected column AIRLOCK rewrites the query
into the size of its smallest group and runs it. `AVG(C_ACCTBAL)` by market
segment (569 per group) passes; the same average sliced by nation *and* segment
(10 per group) does not.

**2. Blast-radius preflight.** Before any write executes, AIRLOCK rewrites it
into the `SELECT COUNT(*)` that measures exactly how many rows it would touch,
and runs it. Not an optimiser estimate — a real count, compared against a policy
budget. It also captures a pre-image snapshot and synthesises the compensating
statement, so an agent's write has an undo.

*This is only affordable because the engine underneath is a columnar MPP
analytics database.* On a row store, counting the blast radius of every write on
the hot path would be the slowest thing in the system.

**3. Data-side prompt-injection taint.** Everyone scans the prompt. Almost
nobody scans the rows coming back — which is where injection against a database
agent actually lives, planted months earlier in a column that legitimately
accepts free text from outside.

Two halves. A **sweep** scores every free-text column in a schema and records
what it finds in `AIRLOCK.TAINT` — catalog-driven, so a new table needs no
change to any list:

```bash
uv run python -m airlock.taint --schema TPCH
#   18 free-text columns swept in 0.47s
```

And a **per-query scan**: before an allowed `SELECT` releases its rows, AIRLOCK
rewrites it to measure the worst taint score among the rows it would return, and
withholds the result set if that crosses the policy threshold. Scoring all three
text columns of the 120,515-row `LINEITEM` table — 361,545 scores — takes 185 ms,
because the scoring runs next to the data instead of dragging it out.

Aggregates are skipped: they return numbers, and an injection needs text to ride
out on.

**4. Tamper-evident ledger + replay.** Every decision is hash-chained to the one
before it. Verification is a single analytical query — Exasol's native
`HASH_SHA256` recomputes each entry and a `LAG` window re-links the chain — so
the audit trail never has to leave the database to be trusted, and needs no
script language container at all.

Then: replay. Because the decision is a pure function of (features, policy set),
and the ledger already stores the features *and* the measurements, a proposed
rule change can be re-decided against the entire history without re-running a
single statement of the agent's SQL:

```bash
uv run python -m airlock.replay --set acctbal-k-anon=100
#   replayed 411 decisions: 22 would now be blocked, 0 would now be allowed
```

Nothing is written to `AIRLOCK.POLICY`. You find out what a rule change costs
before you have to live with it.

## Architecture

```
    agent (Claude / Cursor / any MCP client)
      │  MCP: run_query, describe_table, verify_ledger
      ▼
┌─────────────────────────────────────────────┐
│  AIRLOCK gateway            (src/airlock)   │
│  analyse → policy → preflight → record      │
└─────────────────────────────────────────────┘
      │  pyexasol
      ▼
┌─────────────────────────────────────────────┐
│  Exasol Personal                            │
│   AIRLOCK.POLICY    declarative rules       │
│   AIRLOCK.LEDGER    hash-chained decisions  │
│   AIRLOCK.TAINT     injection sweep results │
│   LEDGER_CHECK      SQL view: HASH_SHA256   │
│   LEDGER_BREAKS     SQL view: audit result  │
│   SCAN_TAINT()      LUA SCALAR script       │
│   STMT_KIND()       LUA SCALAR script       │
│   TPCH / ENERGY     the data being guarded  │
└─────────────────────────────────────────────┘
```

## Quick start

Requires [Exasol Personal](https://github.com/exasol/exasol-personal) running locally.

```bash
curl https://www.exasol.com/install/starter-kit.sh | sh   # database + sample data
./scripts/bootstrap.sh                                    # schema, scripts, policies
uv run python -m airlock.demo                             # see what it stops
uv run python -m airlock.taint --schema TPCH              # find the poisoned rows
uv run python -m airlock.traffic --count 400              # build a decision history
uv run python -m airlock.replay --set acctbal-k-anon=100  # what would that have cost?
```

No script language container is required: the in-database logic is SQL and Lua,
and Lua is compiled into Exasol itself.

## Repository layout

| Path | What's in it |
|---|---|
| `sql/00_schema.sql` | Policy, ledger, taint, session tables |
| `sql/10_policies.sql` | The seed policy set the demo argues about |
| `sql/30_taint_seed.sql` | Injected rows planted in TPC-H free text, for the demo |
| `sql/20_udfs.sql` | Chain-verification views + Lua scripts (no container needed) |
| `src/airlock/analyze.py` | SQL → policy-relevant features (sqlglot) |
| `src/airlock/policy.py` | Pure decision function, reused by replay |
| `src/airlock/preflight.py` | Blast-radius and group-size probes + rollback synthesis |
| `src/airlock/ledger.py` | Hash chain append and in-database verify |
| `src/airlock/taint.py` | Catalog-driven sweep of the warehouse's free text |
| `src/airlock/gateway.py` | The airlock itself |
| `src/airlock/replay.py` | What-if replay of the ledger against amended rules |
| `src/airlock/traffic.py` | Synthetic agent traffic, through the real gateway |
| `src/airlock/mcp_server.py` | Governed MCP surface for agents |
| `console/` | Live governance console |

## Built for

Exasol AI + Data Challenge 2026 — **AI Trust, Safety & Governance**.

## License

MIT
