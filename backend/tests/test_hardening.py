"""Regressions for access control, lockout, alert noise and browser-update false alarms."""
import re
from datetime import datetime, timedelta, timezone

import pytest

from app.config import settings
from app.models.login_attempt import LoginAttempt
from app.models.security_alert import SecurityAlert
from app.security.auth import create_access_token
from app.services.context_capture import parse_device_context
from app.services.risk_engine import decide_action

PROTECTED = [("get", "/api/dashboard/stats"), ("get", "/api/dashboard/dataset"), ("get", "/api/dashboard/activity"),
             ("get", "/api/dashboard/risk-distribution"), ("get", "/api/alerts"),
             ("post", "/api/alerts/1/resolve"), ("get", "/api/login-attempts"),
             ("get", "/api/login-attempts/1"), ("get", "/api/users/1/behavior"),
             ("post", "/api/demo/reset")]
STUDENT = {"username": "student", "email": "student@example.com", "password": "Passw0rd!23"}


@pytest.mark.parametrize("method,path", PROTECTED)
def test_security_data_requires_a_token(client, method, path):
    assert getattr(client, method)(path).status_code == 401


@pytest.mark.parametrize("method,path", PROTECTED)
def test_students_cannot_reach_security_data(client, method, path):
    created = client.post("/api/auth/register", json=STUDENT).json()
    token = create_access_token(created["username"], created["id"])
    response = getattr(client, method)(path, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_forged_token_is_rejected(client):
    assert client.get("/api/alerts", headers={"Authorization": "Bearer not-a-token"}).status_code == 401


def test_admin_reaches_dashboard(admin_client):
    assert admin_client.get("/api/dashboard/stats").status_code == 200


def test_student_login_works_without_token(client):
    client.post("/api/auth/register", json=STUDENT)
    body = client.post("/api/auth/login", json={"username": "student", "password": "Passw0rd!23"}).json()
    assert body["access_token"]


def test_old_failures_stop_blocking_the_student(client, db_session):
    """Eight bad guesses used to lock an account forever, a free denial of service."""
    client.post("/api/auth/register", json=STUDENT)
    for _ in range(8):
        client.post("/api/auth/login", json={"username": "student", "password": "wrong-password"})
    good = {"username": "student", "password": "Passw0rd!23"}
    assert client.post("/api/auth/login", json=good).json()["security_action"] == "block"

    expired = datetime.now(timezone.utc) - timedelta(minutes=settings.failed_attempt_window_minutes + 1)
    db_session.query(LoginAttempt).update({LoginAttempt.login_timestamp: expired})
    db_session.commit()
    assert client.post("/api/auth/login", json=good).json()["security_action"] == "allow"


def test_typos_raise_no_alert_but_a_third_failure_does(client, db_session):
    client.post("/api/auth/register", json=STUDENT)
    wrong = {"username": "student", "password": "wrong-password"}
    client.post("/api/auth/login", json=wrong)
    client.post("/api/auth/login", json=wrong)
    assert db_session.query(SecurityAlert).count() == 0
    client.post("/api/auth/login", json=wrong)
    assert db_session.query(SecurityAlert).count() == 1


def test_guessing_burst_raises_one_alert(client, db_session):
    client.post("/api/auth/register", json=STUDENT)
    for _ in range(10):
        client.post("/api/auth/login", json={"username": "student", "password": "wrong-password"})
    assert db_session.query(SecurityAlert).count() == 1


def test_behaviour_alone_never_hard_blocks():
    assert decide_action("HIGH", 0) == "otp"
    assert decide_action("MEDIUM", 0) == "otp"
    assert decide_action("LOW", 0) == "allow"
    assert decide_action("HIGH", 3) == "block"
    assert decide_action("LOW", 0, password_ok=False) == "block"


def test_student_far_from_home_can_verify_instead_of_being_blocked(client, db_session):
    client.post("/api/auth/register", json=STUDENT)
    usual = {"location": "Hyderabad", "device": "Windows Laptop", "browser": "Chrome",
             "operating_system": "Windows 10", "ip_address": "198.51.100.5", "simulate_hour": 20,
             "simulate_failed_attempts": 0}
    login = {"username": "student", "password": "Passw0rd!23"}
    for _ in range(3):
        client.post("/api/auth/login", json={**login, "demo_context": usual})
    away = {"location": "New York", "device": "Unknown PC", "browser": "Firefox",
            "operating_system": "Linux", "ip_address": "198.51.100.9", "simulate_hour": 3,
            "simulate_failed_attempts": 0}
    body = client.post("/api/auth/login", json={**login, "demo_context": away}).json()
    assert body["risk_level"] == "HIGH"
    assert body["security_action"] == "otp"
    code = re.search(r"DEMO OTP: ([0-9]{6})", body["message"]).group(1)
    assert client.post("/api/auth/verify-otp", json={
        "login_attempt_id": body["login_attempt_id"], "otp_code": code}).json()["success"]
    alert = db_session.query(SecurityAlert).filter_by(login_attempt_id=body["login_attempt_id"]).one()
    assert alert.status == "RESOLVED"


def test_timestamps_are_sent_as_utc(admin_client):
    admin_client.post("/api/auth/login", json={"username": "admin", "password": "AdminPass!23"})
    stamp = admin_client.get("/api/login-attempts").json()[0]["login_timestamp"]
    assert stamp.endswith("Z") or stamp.endswith("+00:00")


def test_browser_auto_update_is_not_a_new_browser():
    older = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    newer = older.replace("Chrome/120", "Chrome/131")
    assert parse_device_context(older) == parse_device_context(newer)
    assert parse_device_context(newer)[1] == "Chrome"
