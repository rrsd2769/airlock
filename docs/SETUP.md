# Setup

## Requirements

- macOS 15+ on Apple Silicon with 8 GB+ RAM (or Linux/Windows with Podman)
- ~20 GB free disk

## 1. Exasol Personal + sample data

```bash
curl https://www.exasol.com/install/starter-kit.sh | sh
```

Installs the database, `exapump`, `pyexasol`, and the official MCP server, then
loads sample datasets. Add `~/.local/bin` to your `PATH` if the installer says so.

Verify:

```bash
exasol connect -c "SELECT COUNT(*) FROM TPCH.CUSTOMER"
```

## 2. No script language container needed

AIRLOCK's in-database logic is deliberately SQL and Lua only. Lua is compiled
into Exasol, so nothing has to be downloaded and UDFs work on a bare local
deployment.

> Installing the Python SLC (`exasol slc install python3`) pulls a multi-GB
> image inside the VM. The launcher only allows VM init 4 minutes, so on a slow
> connection it times out, kills the VM mid-write, and corrupts the ext4
> filesystem — after which the database will not start. If you hit that:
> `e2fsck -f -y <deployment>/local/runtime/vm/data.img`, then
> `exasol slc remove python3 --no-restart`, then `exasol start`.

## 3. AIRLOCK

```bash
./scripts/bootstrap.sh
```

Creates the `AIRLOCK` schema, installs the views and Lua scripts, seeds the policy set, and syncs
the Python environment.

## 4. Run it

```bash
uv run python -m airlock.demo      # scripted walk-through
uv run airlock-api                 # governance console on http://127.0.0.1:8000
uv run airlock-mcp                 # governed MCP server for an agent
uv run pytest                      # policy engine tests (no database needed)
```

## 5. Connect an agent

`airlock-mcp` speaks MCP over stdio, so any MCP client can drive it. Point the
client at the repo with an absolute path:

```json
{
  "mcpServers": {
    "airlock": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/airlock", "airlock-mcp"]
    }
  }
}
```

Five tools come up: `list_schemas`, `describe_table`, `run_query`,
`explain_refusal`, `verify_ledger`. Every one of them goes through the gateway
and lands in the ledger, including the catalog browsing.

Worth asking the agent to try, in order -- each trips a different rule, and the
refusal tells it enough to correct itself:

| Ask for | What comes back |
|---|---|
| `SELECT C_PHONE FROM TPCH.CUSTOMER` | DENY -- the column is not readable at any aggregation |
| `SELECT C_NATIONKEY, AVG(C_ACCTBAL) FROM TPCH.CUSTOMER GROUP BY C_NATIONKEY` | ALLOW, with the measured smallest group |
| `SELECT S_NAME, S_COMMENT FROM TPCH.SUPPLIER` | DENY -- the rows carry injected instructions |
| `UPDATE TPCH.ORDERS SET O_ORDERPRIORITY = '1-URGENT' WHERE O_ORDERSTATUS = 'F'` | REQUIRE_APPROVAL -- 14,504 rows against a cap of 500 |
| `SELECT * FROM AIRLOCK.POLICY` | DENY -- the airlock is not reachable through itself |

Requires `mcp >= 2.1`. The 1.x `FastMCP` import path no longer exists.

## Connection details

The starter kit generates the `sys` password and stores it at
`~/.exasol-starter-kit/credentials/personal_sys_password`. `airlock.config`
reads it automatically, so no `.env` is needed for local work.
