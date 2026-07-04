import sqlite3
from pathlib import Path

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .config import Config


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure the Flask application."""

    app = Flask(__name__)
    app.config.from_object(Config)

    if test_config is not None:
        app.config.update(test_config)

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "SECRET_KEY is required. Create a .env file based on .env.example."
        )

    # Create the Flask instance directory.
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    # Create the database parent directory when necessary.
    database_path = Path(app.config["DATABASE"])
    database_path.parent.mkdir(parents=True, exist_ok=True)

    def get_db() -> sqlite3.Connection:
        """Return one database connection for the current request."""

        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row

        return g.db

    @app.teardown_appcontext
    def close_db(_error: Exception | None = None) -> None:
        """Close the database connection after each request."""

        database = g.pop("db", None)

        if database is not None:
            database.close()

    def init_db() -> None:
        """Create the local training database and seed test data."""

        database = sqlite3.connect(app.config["DATABASE"])

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

    # Temporary helper used by init_db.py and the tests.
    app.init_db = init_db  # type: ignore[attr-defined]

    def require_login():
        """Redirect anonymous visitors to the login page."""

        if "user_id" not in session:
            return redirect(url_for("login"))

        return None

    @app.route("/")
    def index():
        """Redirect users to the correct starting page."""

        if "user_id" in session:
            return redirect(url_for("products"))

        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """Authenticate a user."""

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if not username or not password:
                flash("Le nom d'utilisateur et le mot de passe sont obligatoires.", "error")
                return render_template("login.html"), 400

            database = get_db()

            if app.config["VULNERABLE_MODE"]:
                # Deliberately vulnerable code for an isolated local lab only.
                query = (
                    "SELECT id, username, role FROM users "
                    f"WHERE username = '{username}' "
                    f"AND password_plain = '{password}' "
                    "LIMIT 1"
                )
                user = database.execute(query).fetchone()
            else:
                user = database.execute(
                    """
                    SELECT id, username, password_hash, role
                    FROM users
                    WHERE username = ?
                    """,
                    (username,),
                ).fetchone()

                if user is not None and not check_password_hash(
                    user["password_hash"],
                    password,
                ):
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
        """Remove the authenticated user's session."""

        session.clear()
        return redirect(url_for("login"))

    @app.route("/products")
    def products():
        """Display the product list."""

        guard_response = require_login()

        if guard_response is not None:
            return guard_response

        product_rows = get_db().execute(
            """
            SELECT id, name, description, price, quantity
            FROM products
            ORDER BY id DESC
            """
        ).fetchall()

        return render_template(
            "products.html",
            products=product_rows,
        )

    @app.route("/products/add", methods=["GET", "POST"])
    def add_product():
        """Create a product after validating its data."""

        guard_response = require_login()

        if guard_response is not None:
            return guard_response

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()

            try:
                price = float(request.form.get("price", ""))
                quantity = int(request.form.get("quantity", ""))
            except ValueError:
                flash(
                    "Le prix et la quantité doivent être numériques.",
                    "error",
                )
                return render_template("add_product.html"), 400

            if not name or not description:
                flash(
                    "Le nom et la description sont obligatoires.",
                    "error",
                )
                return render_template("add_product.html"), 400

            if price < 0 or quantity < 0:
                flash(
                    "Le prix et la quantité ne peuvent pas être négatifs.",
                    "error",
                )
                return render_template("add_product.html"), 400

            database = get_db()

            try:
                database.execute(
                    """
                    INSERT INTO products (
                        name,
                        description,
                        price,
                        quantity
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        name,
                        description,
                        price,
                        quantity,
                    ),
                )
                database.commit()
            except sqlite3.Error:
                database.rollback()
                app.logger.exception("Unable to create the product.")

                flash(
                    "Une erreur est survenue pendant l'ajout du produit.",
                    "error",
                )
                return render_template("add_product.html"), 500

            flash("Produit ajouté.", "success")
            return redirect(url_for("products"))

        return render_template("add_product.html")

    @app.route("/admin")
    def admin():
        """Display the administration page to administrators only."""

        guard_response = require_login()

        if guard_response is not None:
            return guard_response

        if session.get("role") != "ADMIN":
            return render_template("403.html"), 403

        users = get_db().execute(
            """
            SELECT id, username, role
            FROM users
            ORDER BY id
            """
        ).fetchall()

        return render_template(
            "admin.html",
            users=users,
        )

    @app.errorhandler(404)
    def not_found(_error):
        """Return a controlled response for unknown pages."""

        return "Page introuvable", 404

    @app.errorhandler(500)
    def internal_server_error(_error):
        """Return a controlled response for unexpected server errors."""

        return "Erreur interne du serveur", 500

    return app