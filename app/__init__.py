import os
import sqlite3
from pathlib import Path

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-secret-change-me"),
        DATABASE=os.environ.get(
            "DATABASE_PATH",
            str(Path(app.instance_path) / "devsecops.sqlite"),
        ),
        VULNERABLE_MODE=os.environ.get("VULNERABLE_MODE", "true").lower() == "true",
    )

    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_error: Exception | None = None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db() -> None:
        db = sqlite3.connect(app.config["DATABASE"])
        db.executescript(
            """
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS products;

            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_plain TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('USER', 'ADMIN'))
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
        db.executemany(
            "INSERT INTO users (username, password_plain, password_hash, role) VALUES (?, ?, ?, ?)",
            [
                ("admin", "Admin123!", generate_password_hash("Admin123!"), "ADMIN"),
                ("user", "User123!", generate_password_hash("User123!"), "USER"),
            ],
        )
        db.executemany(
            "INSERT INTO products (name, description, price, quantity) VALUES (?, ?, ?, ?)",
            [
                ("Laptop", "Ordinateur de démonstration", 8500.0, 4),
                ("Clavier", "Clavier USB", 250.0, 15),
            ],
        )
        db.commit()
        db.close()

    app.init_db = init_db  # type: ignore[attr-defined]

    @app.route("/")
    def index():
        if "user_id" in session:
            return redirect(url_for("products"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            db = get_db()

            if app.config["VULNERABLE_MODE"]:
                # Intentionally vulnerable for a LOCAL, AUTHORIZED training lab only.
                query = (
                    "SELECT id, username, role FROM users "
                    f"WHERE username = '{username}' AND password_plain = '{password}' LIMIT 1"
                )
                user = db.execute(query).fetchone()
            else:
                user = db.execute(
                    "SELECT id, username, password_hash, role FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
                if user is not None and not check_password_hash(user["password_hash"], password):
                    user = None

            if user is None:
                flash("Identifiants incorrects.", "error")
                return render_template("login.html"), 401

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("products"))

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    def require_login():
        if "user_id" not in session:
            return redirect(url_for("login"))
        return None

    @app.route("/products")
    def products():
        guard = require_login()
        if guard:
            return guard
        rows = get_db().execute("SELECT * FROM products ORDER BY id DESC").fetchall()
        return render_template("products.html", products=rows)

    @app.route("/products/add", methods=["GET", "POST"])
    def add_product():
        guard = require_login()
        if guard:
            return guard

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()
            try:
                price = float(request.form.get("price", ""))
                quantity = int(request.form.get("quantity", ""))
            except ValueError:
                flash("Le prix et la quantité doivent être numériques.", "error")
                return render_template("add_product.html"), 400

            if not name or not description or price < 0 or quantity < 0:
                flash("Les données du produit sont invalides.", "error")
                return render_template("add_product.html"), 400

            db = get_db()
            db.execute(
                "INSERT INTO products (name, description, price, quantity) VALUES (?, ?, ?, ?)",
                (name, description, price, quantity),
            )
            db.commit()
            flash("Produit ajouté.", "success")
            return redirect(url_for("products"))

        return render_template("add_product.html")

    @app.route("/admin")
    def admin():
        guard = require_login()
        if guard:
            return guard
        if session.get("role") != "ADMIN":
            return render_template("403.html"), 403
        users = get_db().execute(
            "SELECT id, username, role FROM users ORDER BY id"
        ).fetchall()
        return render_template("admin.html", users=users)

    @app.errorhandler(404)
    def not_found(_error):
        return "Page introuvable", 404

    return app
