def register_user(client, username="alice", password="Passw0rd!23"):
    return client.post("/api/auth/register", json={
        "username": username, "email": f"{username}@example.com", "password": password,
    })


def test_register_success(client):
    resp = register_user(client)
    assert resp.status_code == 201
    body = resp.json()
    assert body["username"] == "alice"


def test_register_duplicate_username_rejected(client):
    register_user(client)
    resp = register_user(client)
    assert resp.status_code == 400


def test_login_wrong_password_fails(client):
    register_user(client)
    resp = client.post("/api/auth/login", json={"username": "alice", "password": "wrong-password"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["authentication_result"] == "failure"
    assert body["access_token"] is None


def test_login_first_time_success_is_low_risk(client):
    register_user(client)
    resp = client.post("/api/auth/login", json={
        "username": "alice", "password": "Passw0rd!23",
        "demo_context": {"location": "Hyderabad", "device": "Windows Laptop", "browser": "Chrome",
                          "simulate_hour": 20},
    })
    body = resp.json()
    assert body["authentication_result"] == "success"
    assert body["risk_level"] == "LOW"
    assert body["access_token"] is not None


def test_login_nonexistent_user_fails(client):
    resp = client.post("/api/auth/login", json={"username": "ghost", "password": "whatever"})
    body = resp.json()
    assert body["authentication_result"] == "failure"
