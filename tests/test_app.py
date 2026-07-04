def login(client, username="user", password="User123!"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


def test_login_success(client):
    response = login(client)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/products")


def test_login_failure(client):
    response = login(client, password="wrong")
    assert response.status_code == 401


def test_sql_injection_is_rejected_in_secure_mode(client):
    response = login(client, username="' OR 1=1 -- ", password="anything")
    assert response.status_code == 401


def test_user_cannot_access_admin(client):
    login(client)
    response = client.get("/admin")
    assert response.status_code == 403


def test_admin_can_access_admin(client):
    login(client, username="admin", password="Admin123!")
    response = client.get("/admin")
    assert response.status_code == 200
    assert b"Administration" in response.data


def test_add_product(client):
    login(client)
    response = client.post(
        "/products/add",
        data={
            "name": "Souris",
            "description": "Souris USB",
            "price": "120.50",
            "quantity": "8",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Souris" in response.data


def test_negative_price_is_rejected(client):
    login(client)
    response = client.post(
        "/products/add",
        data={
            "name": "Produit invalide",
            "description": "Test",
            "price": "-1",
            "quantity": "1",
        },
    )
    assert response.status_code == 400
