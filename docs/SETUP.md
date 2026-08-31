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
uv run airlock-mcp                 # governed MCP server for an agent
uv run pytest                      # policy engine tests (no database needed)
```

## Connection details

The starter kit generates the `sys` password and stores it at
`~/.exasol-starter-kit/credentials/personal_sys_password`. `airlock.config`
reads it automatically, so no `.env` is needed for local work.
