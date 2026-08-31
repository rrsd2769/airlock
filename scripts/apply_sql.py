"""Apply a .sql file to Exasol via pyexasol.

Splitting Exasol SQL is not a one-liner:

  * `exasol connect -f` splits on ';', which corrupts script bodies.
  * ';' also appears inside string literals and comments, so a naive split
    tears statements in half.
  * A single file may mix ';'-terminated statements with script definitions,
    which are terminated by a line containing only '/'.

So: lift script blocks out first, then scan the remainder for ';' while
tracking string literals and both comment styles.

    python scripts/apply_sql.py sql/00_schema.sql [...]
"""
from __future__ import annotations

import re
import ssl
import sys
from pathlib import Path

import pyexasol

PW_FILE = Path.home() / ".exasol-starter-kit/credentials/personal_sys_password"

SCRIPT_START = re.compile(
    r"^\s*CREATE\s+(OR\s+REPLACE\s+)?"
    r"(LUA|PYTHON3?|PYTHON312|JAVA|JAVA17|R|R44)\b.*\bSCRIPT\b",
    re.IGNORECASE,
)


def connect() -> pyexasol.ExaConnection:
    password = PW_FILE.read_text().strip() if PW_FILE.is_file() else "exasol"
    return pyexasol.connect(
        dsn="127.0.0.1:8563", user="sys", password=password,
        websocket_sslopt={"cert_reqs": ssl.CERT_NONE}, autocommit=True,
    )


def _split_plain(sql: str) -> list[str]:
    """Split on ';' that are real statement terminators."""
    out, buf = [], []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""

        if ch == "'":                                  # string literal, '' escapes
            buf.append(ch)
            i += 1
            while i < n:
                buf.append(sql[i])
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        buf.append(sql[i + 1])
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue

        if ch == "-" and nxt == "-":                   # line comment
            while i < n and sql[i] != "\n":
                buf.append(sql[i])
                i += 1
            continue

        if ch == "/" and nxt == "*":                   # block comment
            while i < n and not (sql[i] == "*" and i + 1 < n and sql[i + 1] == "/"):
                buf.append(sql[i])
                i += 1
            buf.append(sql[i:i + 2])
            i += 2
            continue

        if ch == ";":
            out.append("".join(buf))
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    out.append("".join(buf))
    return out


def split_statements(text: str) -> list[str]:
    statements: list[str] = []
    pending: list[str] = []
    script: list[str] | None = None

    for line in text.splitlines():
        if script is not None:
            if line.strip() == "/":
                statements.append("\n".join(script))
                script = None
            else:
                script.append(line)
            continue

        if SCRIPT_START.match(line):
            statements.extend(_split_plain("\n".join(pending)))
            pending = []
            script = [line]
            continue

        pending.append(line)

    if script:
        statements.append("\n".join(script))
    statements.extend(_split_plain("\n".join(pending)))

    out = []
    for stmt in statements:
        meaningful = [ln for ln in stmt.splitlines()
                      if ln.strip() and not ln.strip().startswith("--")]
        if meaningful:
            out.append(stmt.strip())
    return out


def _error_text(exc: Exception) -> str:
    msg = " ".join(str(exc).split())
    return msg[:220] if msg else f"{type(exc).__name__} (no message)"


def main() -> int:
    conn = connect()
    failures = 0
    for path in sys.argv[1:]:
        statements = split_statements(Path(path).read_text())
        print(f"\n{path}: {len(statements)} statement(s)")
        for stmt in statements:
            label = " ".join(
                ln for ln in stmt.splitlines() if not ln.strip().startswith("--")
            )
            label = " ".join(label.split())[:66]
            try:
                conn.execute(stmt)
                print(f"  ok    {label}")
            except Exception as exc:
                failures += 1
                print(f"  FAIL  {label}")
                print(f"        {_error_text(exc)}")
    conn.close()
    if failures:
        print(f"\n{failures} statement(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
