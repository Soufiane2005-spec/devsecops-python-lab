import sqlite3

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

from .config import Config
from .database import get_db
from .database import init_app as init_database


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

    # Register database lifecycle functions with Flask.
    init_database(app)

    def require_login():
        """Redirect anonymous visitors to the login page."""

        if "user_id" not in session:
            return redirect(url_for("login"))

        return None

    @app.route("/")
    def index():
        """Redirect users to the appropriate starting page."""

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
                flash(
                    "Le nom d'utilisateur et le mot de passe sont obligatoires.",
                    "error",
                )
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
        """Display the list of products."""

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