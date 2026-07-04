from app import create_app


def test_training_mode_demonstrates_sql_injection(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "DATABASE": str(tmp_path / "vulnerable.sqlite"),
            "VULNERABLE_MODE": True,
        }
    )
    with app.app_context():
        app.init_db()

    client = app.test_client()
    response = client.post(
        "/login",
        data={"username": "' OR 1=1 -- ", "password": "anything"},
        follow_redirects=False,
    )
    assert response.status_code == 302
