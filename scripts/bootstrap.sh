#!/usr/bin/env bash
# Bring a fresh clone to a working AIRLOCK demo.
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

step() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }

step "Syncing the Python environment"
uv sync --python 3.12

step "Checking the database is reachable"
uv run python - <<'PY'
import ssl, sys
from pathlib import Path
import pyexasol
pw = Path.home() / ".exasol-starter-kit/credentials/personal_sys_password"
try:
    c = pyexasol.connect(dsn="127.0.0.1:8563", user="sys",
                         password=pw.read_text().strip() if pw.is_file() else "exasol",
                         websocket_sslopt={"cert_reqs": ssl.CERT_NONE})
    print("    reachable:", c.execute("SELECT COUNT(*) FROM TPCH.CUSTOMER").fetchone()[0],
          "rows in TPCH.CUSTOMER")
except Exception as exc:
    sys.exit(f"    database not reachable: {exc}\n"
             "    Start it with: exasol start")
PY

step "Checking Lua scripting"
echo "    Lua is compiled into Exasol; no script language container is needed."

step "Creating schema, UDFs, and policies"
uv run python scripts/apply_sql.py sql/00_schema.sql sql/20_udfs.sql sql/10_policies.sql

step "Planting the demo's injected rows"
uv run python scripts/apply_sql.py sql/30_taint_seed.sql

step "Sweeping the warehouse's free text for injected instructions"
uv run python -m airlock.taint --schema TPCH --top 3

step "Running the tests"
uv run pytest -q

step "Done"
echo "    Demo:    uv run python -m airlock.demo"
echo "    MCP:     uv run airlock-mcp"
