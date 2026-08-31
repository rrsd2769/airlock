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

## 2. Python script language container

UDFs do not work on a local deployment until a container is installed. This is
the step most people miss — scripts fail with a missing-language error instead
of something obvious.

```bash
exasol slc install python3 --auto-approve
```

The database restarts and pulls a multi-GB image inside its VM; the first run
takes a while. Confirm with `exasol slc list` (`INSTALLED` should read `yes`).

> Run this in a terminal that stays open. If the launcher is killed mid-start
> the deployment is left in state `interrupted`; recover with
> `exasol stop && exasol start`.

## 3. AIRLOCK

```bash
./scripts/bootstrap.sh
```

Creates the `AIRLOCK` schema, installs the UDFs, seeds the policy set, and syncs
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
