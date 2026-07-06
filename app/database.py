from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import cast

from flask import Flask, current_app, g
from werkzeug.security import generate_password_hash


def get_db() -> sqlite3.Connection:
    """Return one database connection for the current request."""

    if "db" not in g:
        database_path = Path(current_app.config["DATABASE"])
        database_path.parent.mkdir(parents=True, exist_ok=True)

        connection = sqlite3.connect(str(database_path))
        connection.row_factory = sqlite3.Row
        g.db = connection

    return cast(sqlite3.Connection, g.db)


def close_db(_error: Exception | None = None) -> None:
    """Close the database connection after the request."""

    database = g.pop("db", None)

    if database is not None:
        database.close()


def init_db() -> None:
    """Create the local database and insert demonstration data."""

    database_path = Path(current_app.config["DATABASE"])
    database_path.parent.mkdir(parents=True, exist_ok=True)

    database = sqlite3.connect(str(database_path))

    try:
        database.executescript(
            """
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS products;

            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_plain TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
                    CHECK(role IN ('USER', 'ADMIN'))
            );

            CREATE TABLE products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                price REAL NOT NULL CHECK(price >= 0),
                quantity INTEGER NOT NULL CHECK(quantity >= 0)
            );
            """
        )

        database.executemany(
            """
            INSERT INTO users (
                username,
                password_plain,
                password_hash,
                role
            )
            VALUES (?, ?, ?, ?)
            """,
            [
                (
                    "admin",
                    "Admin123!",
                    generate_password_hash("Admin123!"),
                    "ADMIN",
                ),
                (
                    "user",
                    "User123!",
                    generate_password_hash("User123!"),
                    "USER",
                ),
            ],
        )

        database.executemany(
            """
            INSERT INTO products (
                name,
                description,
                price,
                quantity
            )
            VALUES (?, ?, ?, ?)
            """,
            [
                (
                    "Laptop",
                    "Ordinateur de démonstration",
                    8500.0,
                    4,
                ),
                (
                    "Clavier",
                    "Clavier USB",
                    250.0,
                    15,
                ),
            ],
        )

        database.commit()
    except sqlite3.Error:
        database.rollback()
        raise
    finally:
        database.close()


def init_app(app: Flask) -> None:
    """Register database functions with the Flask application."""

    app.teardown_appcontext(close_db)

    # Temporary compatibility for init_db.py and the current tests.
    app.init_db = init_db  # type: ignore[attr-defined]