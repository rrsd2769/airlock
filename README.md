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
budget. It also captures a pre-image of exactly the rows the write will change
and synthesises the compensating statement that reverses it — keyed on the
target's primary key, read from the catalog — so an agent's UPDATE or DELETE has
a real undo, recorded in the ledger beside the decision. Where the table has no
key to match the pre-image back by, AIRLOCK narrows the statement or says plainly
that it cannot generate one, rather than emitting SQL that would restore the
wrong rows.

The pre-image is taken only for a write that is actually going to run, so a
refused write costs nothing, and it is taken *before* the write, because
afterwards it would be a copy of the change rather than of what preceded it. A
write whose pre-image cannot be captured is refused rather than executed without
an undo — the ledger records that refusal and why. Snapshots are ordinary tables
in the `AIRLOCK_SNAP` schema, owned by the gateway's own identity so that
capturing a pre-image needs no rights over `AIRLOCK` itself;
`python -m airlock.snapshots` lists them with the decision each one belongs to,
and `--prune` ages them out.

The corpus in this repo carries **18 pre-image tables** and every compensating
statement in it is runnable. That is worth demonstrating rather than asserting:
scribble over a slice of the rows an allowed write touched, run the `MERGE` the
ledger recorded for it, and the table comes back — including rows whose "before"
value was itself the result of an earlier approved release.

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
#   18 free-text columns swept in 0.6s
```

And a **per-query scan**: before an allowed `SELECT` releases its rows, AIRLOCK
rewrites it to measure the worst taint score among the rows it would return, and
withholds the result set if that crosses the policy threshold. Scoring both of
the free-text columns wide enough to hide a payload in the 120,515-row
`LINEITEM` table — 241,030 scores — takes 132 ms, because the scoring runs next
to the data instead of dragging it out.

Aggregates are skipped: they return numbers, and an injection needs text to ride
out on.

**4. Tamper-evident ledger + replay.** Every decision is hash-chained to the one
before it. Verification is a single analytical query — Exasol's native
`HASH_SHA256` recomputes each entry and a `LAG` window re-links the chain — so
the audit trail never has to leave the database to be trusted, and needs no
script language container at all.

The hash covers the whole decision, not just its verdict: who ran the statement,
which rules fired and why, and the measurements the verdict rested on. That last
part matters because replay re-decides from those measurements — if they sat
outside the hash, anyone with `UPDATE` on the table could change what a replay
concludes without breaking a single link.

Then: replay. Because the decision is a pure function of (features, policy set),
and the ledger already stores the features *and* the measurements, a proposed
rule change can be re-decided against the entire history without re-running a
single statement of the agent's SQL:

```bash
uv run python -m airlock.replay --set acctbal-k-anon=100
#   replayed 405 decisions: 14 would now be blocked, 0 would now be allowed
```

Nothing is written to `AIRLOCK.POLICY`. You find out what a rule change costs
before you have to live with it.

An approval is the decision's third input, alongside the features and the rules,
so replay re-decides a released statement as released. Without that, every
approved write in the history would read as *newly blocked* under any amendment
at all — including amendments that cannot touch a write.

**5. A privilege boundary Exasol enforces, not AIRLOCK.** `protect-airlock` says
an agent must not edit the rules or erase the ledger that bind it. For most of
this project's life that rule was enforced only by the thing it protects: the
gateway ran as `sys`, and a superuser gateway asks the database for nothing it
could not simply take.

`sql/40_identities.sql` moves the enforcement into the database, where it holds
whether or not AIRLOCK's own code is correct:

| Identity | What it can do |
|---|---|
| `AIRLOCK_SVC` | The gateway. Reads the rules, appends to the ledger, and can do neither the other way round. Owns `AIRLOCK_SNAP`. |
| `AIRLOCK_CONSOLE` | The read-only observer behind the console API. Selects from everything, writes to nothing. |
| `DEMO_AGENT` | The agent's own database identity. Reaches the policy-derived safe views and nothing else. |

The agent's identity cannot read the ledger, cannot read the policy table, and
cannot read a customer's phone number — so an agent that connects *around* the
airlock is refused by Exasol rather than by us.

**Its scope, stated honestly: it constrains and detects. It does not make bypass
impossible for someone holding `sys`.** No boundary drawn inside a database can,
and claiming otherwise would be the same circularity this section removes. What
it adds is that bypassing AIRLOCK now requires credentials AIRLOCK never issues,
and that using them is visible:

**6. Live bypass monitor.** The console asks Exasol which sessions are connected
right now and matches each one against `AIRLOCK.AGENT_SESSION`, which the gateway
writes as it opens. A connection that came through the airlock is *governed*; the
database's own housekeeping is *internal*; anything else is **ungoverned**, on
screen, while it is still connected.

**7. Approval loop.** `REQUIRE_APPROVAL` used to be a verdict with nowhere to go:
the engine could hold a statement and nothing could ever let one through. A
release now re-enters `gateway.submit()` rather than being executed by whoever
approved it, which is the whole design — the pre-image capture is gated on the
verdict being `ALLOW`, so a statement run around the gateway would have no
snapshot and no undo. The blast radius is measured again, against the table as it
is now. The release gets its own ledger entry, chained onto the held one, and the
held entry is never edited: a queue whose approvals rewrote history would be
asking the audit trail to vouch for a decision it had itself been changed to
agree with.

An approval releases a hold. It never overrides a `DENY` — the demotion lives in
`Decision.apply()`, which `DENY` never reaches, so that is structural rather than
a convention.

```bash
AIRLOCK_APPROVAL_TOKEN=... uv run airlock-approve   # the approval desk, on :8001
uv run python -m airlock.approval --list
uv run python -m airlock.approval --approve 7 --by alice
```

The desk's read-only page at `/` is unauthenticated and shows what is waiting;
every deciding route is behind the bearer token, and a token is generated and
printed at startup if none is set, so the desk is never open by accident.

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
┌─────────────────────────────────────────────┐     ┌────────────────────┐
│  Exasol Personal                            │◀────│  console  :8000    │
│   AIRLOCK.POLICY    declarative rules       │ read│  ledger · taint    │
│   AIRLOCK.LEDGER    hash-chained decisions  │ only│  · replay what-if  │
│   AIRLOCK.TAINT     injection sweep results │     │  · live sessions   │
│   AIRLOCK.APPROVAL  the queue of holds      │     └────────────────────┘
│   AIRLOCK.AGENT_SESSION  who came through   │     ┌────────────────────┐
│   AIRLOCK_SNAP.*    pre-images, for the undo│◀────│  approval  :8001   │
│   LEDGER_CHECK      SQL view: HASH_SHA256   │ token  release a hold    │
│   LEDGER_BREAKS     SQL view: audit result  │     └────────────────────┘
│   SCAN_TAINT()      LUA SCALAR script       │
│   STMT_KIND()       LUA SCALAR script       │
│   TPCH / ENERGY     the data being guarded  │
└─────────────────────────────────────────────┘

  three identities, enforced by Exasol (sql/40_identities.sql):
    AIRLOCK_SVC · AIRLOCK_CONSOLE · DEMO_AGENT
```

## Quick start

Requires [Exasol Personal](https://github.com/exasol/exasol-personal) running locally.

```bash
curl https://www.exasol.com/install/starter-kit.sh | sh   # database + sample data
./scripts/bootstrap.sh                                    # schema, scripts, policies
uv run python -m airlock.demo                             # see what it stops
uv run python -m airlock.taint --schema TPCH              # find the poisoned rows
uv run python -m airlock.traffic --count 400 --approve-rate 0.5   # a history
uv run python -m airlock.replay --set acctbal-k-anon=100  # what would that have cost?
uv run airlock-api                                        # the console, on :8000
uv run airlock-approve                                    # the approval desk, :8001
```

`--approve-rate` releases a reproducible share of the holds that are safe to
execute, so the history carries real approved writes — with pre-images behind
them — rather than a queue nobody ever worked.

No script language container is required: the in-database logic is SQL and Lua,
and Lua is compiled into Exasol itself.

## Repository layout

| Path | What's in it |
|---|---|
| `sql/00_schema.sql` | Policy, ledger, taint, session tables |
| `sql/10_policies.sql` | The seed policy set the demo argues about |
| `sql/30_taint_seed.sql` | Injected rows planted in TPC-H free text, for the demo |
| `sql/40_identities.sql` | The privilege boundary: three identities, in one file |
| `sql/20_udfs.sql` | Chain-verification views + Lua scripts (no container needed) |
| `src/airlock/analyze.py` | SQL → policy-relevant features (sqlglot) |
| `src/airlock/policy.py` | Pure decision function, reused by replay |
| `src/airlock/preflight.py` | Blast-radius and group-size probes + rollback synthesis |
| `src/airlock/ledger.py` | Hash chain append and in-database verify |
| `src/airlock/taint.py` | Catalog-driven sweep of the warehouse's free text |
| `src/airlock/gateway.py` | The airlock itself |
| `src/airlock/snapshots.py` | Pre-image naming, listing and retention |
| `src/airlock/replay.py` | What-if replay of the ledger against amended rules |
| `src/airlock/traffic.py` | Synthetic agent traffic, through the real gateway |
| `src/airlock/approval.py` | The approval loop: releasing a hold back through the airlock |
| `src/airlock/sessions.py` | Live connections, classified against `AGENT_SESSION` |
| `src/airlock/identities.py` | The policy-derived safe views the agent identity sees |
| `src/airlock/mcp_server.py` | Governed MCP surface for agents |
| `src/airlock/api.py` | Read-only HTTP surface behind the console |
| `src/airlock/approve_api.py` | The approval desk on `:8001`, behind a bearer token |
| `console/` | Live governance console: ledger, taint, replay, live sessions |

## Built for

Exasol AI + Data Challenge 2026 — **AI Trust, Safety & Governance**.

## License

MIT
