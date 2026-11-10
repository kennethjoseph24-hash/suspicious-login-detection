import re


def register_and_baseline(client, username="bob", password="Passw0rd!23"):
    client.post("/api/auth/register", json={
        "username": username, "email": f"{username}@example.com", "password": password,
    })
    # Establish a normal behavioral baseline with several familiar logins.
    for _ in range(5):
        client.post("/api/auth/login", json={
            "username": username, "password": password,
            "demo_context": {"location": "Hyderabad", "device": "Windows Laptop", "browser": "Chrome",
                              "simulate_hour": 20, "simulate_failed_attempts": 0},
        })


def test_suspicious_login_triggers_high_risk_and_block(client):
    register_and_baseline(client)
    resp = client.post("/api/auth/login", json={
        "username": "bob", "password": "Passw0rd!23",
        "demo_context": {
            "location": "New York", "device": "Unknown Windows PC", "browser": "Firefox",
            "operating_system": "Windows 10", "simulate_hour": 3, "simulate_failed_attempts": 5,
        },
    })
    body = resp.json()
    assert body["risk_level"] == "HIGH"
    assert body["otp_required"] is False
    assert body["security_action"] == "block"
    assert body["access_token"] is None
    assert "[DEMO OTP:" not in body["message"]


def test_new_device_same_location_is_medium_or_higher(client):
    register_and_baseline(client)
    resp = client.post("/api/auth/login", json={
        "username": "bob", "password": "Passw0rd!23",
        "demo_context": {"location": "Hyderabad", "device": "New iPhone", "browser": "Safari",
                          "simulate_hour": 20, "simulate_failed_attempts": 0},
    })
    body = resp.json()
    assert body["risk_level"] in ("MEDIUM", "HIGH")
    assert body["is_suspicious"] is True


def test_correct_otp_allows_login(client):
    register_and_baseline(client)
    login_resp = client.post("/api/auth/login", json={
        "username": "bob", "password": "Passw0rd!23",
        "demo_context": {
            "location": "Hyderabad", "device": "Windows Laptop", "browser": "Chrome",
            "simulate_hour": 20, "simulate_failed_attempts": 4,
        },
    })
    body = login_resp.json()
    match = re.search(r"\[DEMO OTP: (\d{6})\]", body["message"])
    assert match
    otp_code = match.group(1)

    verify_resp = client.post("/api/auth/verify-otp", json={
        "login_attempt_id": body["login_attempt_id"], "otp_code": otp_code,
    })
    verify_body = verify_resp.json()
    assert verify_body["success"] is True
    assert verify_body["access_token"] is not None


def test_incorrect_otp_denies_login(client):
    register_and_baseline(client)
    login_resp = client.post("/api/auth/login", json={
        "username": "bob", "password": "Passw0rd!23",
        "demo_context": {
            "location": "Hyderabad", "device": "Windows Laptop", "browser": "Chrome",
            "simulate_hour": 20, "simulate_failed_attempts": 4,
        },
    })
    body = login_resp.json()
    verify_resp = client.post("/api/auth/verify-otp", json={
        "login_attempt_id": body["login_attempt_id"], "otp_code": "000000",
    })
    verify_body = verify_resp.json()
    assert verify_body["success"] is False
    assert verify_body["access_token"] is None


def test_security_alert_created_for_high_risk_login(admin_client):
    client = admin_client
    register_and_baseline(client)
    client.post("/api/auth/login", json={
        "username": "bob", "password": "Passw0rd!23",
        "demo_context": {
            "location": "New York", "device": "Unknown Windows PC", "browser": "Firefox",
            "operating_system": "Windows 10", "simulate_hour": 3, "simulate_failed_attempts": 5,
        },
    })
    alerts_resp = client.get("/api/alerts")
    alerts = alerts_resp.json()
    assert any(a["severity"] == "HIGH" for a in alerts)
