from app import create_app

app = create_app()
with app.app_context():
    app.init_db()
print("Base de données initialisée.")
