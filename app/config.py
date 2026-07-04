from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / ".env")


def get_bool_env(name: str, default: bool = False) -> bool:
    """Convert an environment variable into a boolean."""

    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def get_database_path() -> str:
    """Return an absolute path for the SQLite database."""

    configured_path = os.getenv(
        "DATABASE_PATH",
        "instance/devsecops.sqlite",
    )

    database_path = Path(configured_path)

    if not database_path.is_absolute():
        database_path = BASE_DIR / database_path

    return str(database_path)


class Config:
    """Base application configuration."""

    SECRET_KEY = os.getenv("SECRET_KEY")
    DATABASE = get_database_path()

    # Secure mode is the default.
    VULNERABLE_MODE = get_bool_env(
        "VULNERABLE_MODE",
        False,
    )

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Keep False locally because localhost does not use HTTPS.
    SESSION_COOKIE_SECURE = False