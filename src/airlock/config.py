"""Connection and identity settings.

Defaults match what the Exasol Personal local starter kit produces, so a fresh
clone works with no .env at all.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# The starter kit writes the generated sys password here rather than using a
# hardcoded default. Read it if present so nobody has to paste a secret.
_KIT_PASSWORD = Path.home() / ".exasol-starter-kit/credentials/personal_sys_password"


def _default_password() -> str:
    if _KIT_PASSWORD.is_file():
        return _KIT_PASSWORD.read_text().strip()
    return "exasol"


@dataclass(frozen=True)
class Settings:
    dsn: str = os.getenv("AIRLOCK_DSN", "127.0.0.1:8563")
    user: str = os.getenv("AIRLOCK_USER", "sys")
    password: str = os.getenv("AIRLOCK_PASSWORD") or _default_password()
    schema: str = os.getenv("AIRLOCK_SCHEMA", "AIRLOCK")
    principal: str = os.getenv("AIRLOCK_PRINCIPAL", "demo-agent")
    # Local Exasol Personal uses a self-signed certificate.
    certificate_validation: bool = os.getenv("AIRLOCK_TLS_VERIFY", "0") == "1"


settings = Settings()
