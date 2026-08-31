#!/usr/bin/env bash
# Bring a fresh clone to a working AIRLOCK demo.
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

step() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }

step "Checking Exasol Personal is running"
exasol connect -c "SELECT 1" >/dev/null
echo "    database reachable"

step "Checking the Python script language container is installed"
if ! exasol slc list | grep -qE 'python-3.*yes'; then
    echo "    installing PYTHON3 SLC (restarts the database)"
    exasol slc install python3 --auto-approve
fi

step "Creating the AIRLOCK schema"
exasol connect -f sql/00_schema.sql

step "Installing in-database UDFs"
exasol connect -f sql/20_udfs.sql

step "Seeding policies"
exasol connect -f sql/10_policies.sql

step "Installing the Python package"
uv sync

step "Done"
echo "    Run the demo:      uv run python -m airlock.demo"
echo "    Start the MCP srv: uv run airlock-mcp"
