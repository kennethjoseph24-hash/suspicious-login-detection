def test_dashboard_stats_start_empty(admin_client):
    resp = admin_client.get("/api/dashboard/stats")
    body = resp.json()
    assert body["total_logins"] == 0


def test_dashboard_stats_reflect_real_logins(admin_client):
    admin_client.post("/api/auth/register", json={
        "username": "carol", "email": "carol@example.com", "password": "Passw0rd!23",
    })
    admin_client.post("/api/auth/login", json={"username": "carol", "password": "Passw0rd!23"})
    admin_client.post("/api/auth/login", json={"username": "carol", "password": "wrong"})

    resp = admin_client.get("/api/dashboard/stats")
    body = resp.json()
    assert body["total_logins"] == 2
    assert body["successful_logins"] == 1
    assert body["failed_logins"] == 1


def test_risk_distribution_endpoint(admin_client):
    resp = admin_client.get("/api/dashboard/risk-distribution")
    body = resp.json()
    levels = [row["risk_level"] for row in body]
    assert levels == ["LOW", "MEDIUM", "HIGH"]


def test_login_attempts_list_and_detail(admin_client):
    admin_client.post("/api/auth/register", json={
        "username": "dave", "email": "dave@example.com", "password": "Passw0rd!23",
    })
    admin_client.post("/api/auth/login", json={"username": "dave", "password": "Passw0rd!23"})

    list_resp = admin_client.get("/api/login-attempts")
    attempts = list_resp.json()
    assert len(attempts) == 1

    detail_resp = admin_client.get(f"/api/login-attempts/{attempts[0]['id']}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["username_attempted"] == "dave"
    assert "detection_reasons" in detail


def test_admin_dataset_overview_uses_evaluation_files(admin_client):
    response = admin_client.get("/api/dashboard/dataset")
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["students"] == 50000
    assert body["summary"]["events"] == 5507347
    assert body["model"]["split"]["test_events"] == body["system"]["test_events"]
    assert body["model"]["confusion_matrix"] == {
        "true_positive": 3107, "false_negative": 885,
        "false_positive": 10860, "true_negative": 1083824,
    }
    assert body["system"]["policies"]["Rules + Isolation Forest"]["attacker_entry_attempts"] == 800
    assert len(body["sample_rows"]) <= 12
    assert len({row["student_id"] for row in body["sample_rows"]}) == len(body["sample_rows"])


