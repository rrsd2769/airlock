"""Apply a .sql file to Exasol via pyexasol.

Why not `exasol connect -f`: that client splits input on ';', which corrupts
UDF bodies. Exasol script definitions are instead terminated by a line
containing a single '/'. A file uses one convention or the other, never both,
so detect which and split accordingly.

    python scripts/apply_sql.py sql/00_schema.sql [...]
"""
from __future__ import annotations

import ssl
import sys
from pathlib import Path

import pyexasol

PW_FILE = Path.home() / ".exasol-starter-kit/credentials/personal_sys_password"


def connect() -> pyexasol.ExaConnection:
    password = PW_FILE.read_text().strip() if PW_FILE.is_file() else "exasol"
    return pyexasol.connect(
        dsn="127.0.0.1:8563", user="sys", password=password,
        websocket_sslopt={"cert_reqs": ssl.CERT_NONE}, autocommit=True,
    )


def split_statements(text: str) -> list[str]:
    lines = text.splitlines()
    uses_script_terminator = any(line.strip() == "/" for line in lines)

    if uses_script_terminator:
        statements, buf = [], []
        for line in lines:
            if line.strip() == "/":
                statements.append("\n".join(buf))
                buf = []
            else:
                buf.append(line)
        if "\n".join(buf).strip():
            statements.append("\n".join(buf))
    else:
        statements = text.split(";")

    out = []
    for stmt in statements:
        # Drop statements that are only comments or blank.
        meaningful = [ln for ln in stmt.splitlines()
                      if ln.strip() and not ln.strip().startswith("--")]
        if meaningful:
            out.append(stmt.strip())
    return out


def main() -> int:
    conn = connect()
    failures = 0
    for path in sys.argv[1:]:
        statements = split_statements(Path(path).read_text())
        print(f"\n{path}: {len(statements)} statement(s)")
        for stmt in statements:
            label = " ".join(stmt.split())[:70]
            try:
                conn.execute(stmt)
                print(f"  ok    {label}")
            except Exception as exc:
                failures += 1
                print(f"  FAIL  {label}")
                print(f"        {str(exc).splitlines()[0][:160]}")
    conn.close()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
