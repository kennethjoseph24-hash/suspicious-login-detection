import json
import re

from app.config import settings
from app.services.network_context import classify_context, CAMPUS, LAB, EXTERNAL
from app.services.risk_engine import compute_risk
from app.models.behavior_profile import UserBehaviorProfile
from app.ml.feature_engineering import _hour_deviation


def test_context_precedence_and_device_trust(monkeypatch):
    monkeypatch.setattr(settings, "campus_ip_ranges", "192.0.2.0/24,2001:db8::/32")
    monkeypatch.setattr(settings, "lab_device_tokens", json.dumps({"lab-1": "registered-secret"}))
    assert classify_context("192.0.2.15") == CAMPUS
    assert classify_context("192.0.2.15", "registered-secret") == LAB
    assert classify_context("192.0.2.15", "forged") == CAMPUS
    assert classify_context("198.51.100.3", "registered-secret") == EXTERNAL
    assert classify_context("2001:db8::1") == CAMPUS
    assert classify_context("invalid") == EXTERNAL


def test_demo_lab_disabled(monkeypatch):
    monkeypatch.setattr(settings, "demo_context_enabled", False)
    assert classify_context("192.0.2.15", demo_lab_id="lab-pc-01") == CAMPUS


def test_shared_context_does_not_suppress_password_failures():
    features = dict(location_novelty=0, device_novelty=1, browser_novelty=1,
                    os_novelty=1, ip_novelty=1, hour_deviation=0,
                    login_frequency_norm=0, geo_distance_norm=0)
    def score(context, failures=0, first=False):
        return compute_risk(features=features, failed_attempt_count=failures,
            ml_anomaly_score=None, ml_is_anomaly=False, is_first_ever_login=first,
            network_context=context)
    assert score(LAB)["level"] == "LOW"
    assert score(EXTERNAL)["score"] > score(CAMPUS)["score"] > score(LAB)["score"]
    assert score(LAB, 8, True)["level"] == "HIGH"
    assert features["device_novelty"] == 1


def test_overnight_hour_window():
    assert _hour_deviation(1, 22, 2) == 0
    assert _hour_deviation(23, 22, 2) == 0
    assert _hour_deviation(12, 22, 2) > .5


def create_challenge(client, failures=4):
    client.post("/api/auth/register", json={"username":"student", "email":"student@example.com", "password":"Passw0rd!23"})
    return client.post("/api/auth/login", json={"username":"student", "password":"Passw0rd!23", "demo_context":{"ip_address":"192.0.2.20", "simulate_hour":20, "simulate_failed_attempts":failures}}).json()


def test_otp_does_not_learn_until_verified(client, db_session):
    body = create_challenge(client)
    assert body["risk_level"] == "MEDIUM"
    assert body["authentication_result"] == "pending"
    assert body["access_token"] is None
    profile = db_session.query(UserBehaviorProfile).first()
    assert profile.total_logins == 0
    code = re.search(r"DEMO OTP: ([0-9]{6})", body["message"]).group(1)
    payload = {"login_attempt_id":body["login_attempt_id"], "otp_code":code}
    assert client.post("/api/auth/verify-otp", json=payload).json()["success"]
    db_session.refresh(profile)
    assert profile.total_logins == 1
    assert not client.post("/api/auth/verify-otp", json=payload).json()["success"]


def test_blocked_login_cannot_use_otp_or_learn(client, db_session):
    body = create_challenge(client, 8)
    assert body["security_action"] == "block"
    assert body["authentication_result"] == "blocked"
    assert body["access_token"] is None
    assert db_session.query(UserBehaviorProfile).first().total_logins == 0
    assert not client.post("/api/auth/verify-otp", json={"login_attempt_id":body["login_attempt_id"], "otp_code":"123456"}).json()["success"]


def test_otp_attempt_limit(client):
    body = create_challenge(client)
    code = re.search(r"DEMO OTP: ([0-9]{6})", body["message"]).group(1)
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(settings.otp_max_attempts):
        assert not client.post("/api/auth/verify-otp", json={"login_attempt_id":body["login_attempt_id"], "otp_code":wrong}).json()["success"]
    assert not client.post("/api/auth/verify-otp", json={"login_attempt_id":body["login_attempt_id"], "otp_code":code}).json()["success"]


def test_real_failures_survive_pending_challenges(client):
    client.post("/api/auth/register", json={"username":"student", "email":"student@example.com", "password":"Passw0rd!23"})
    for _ in range(4):
        client.post("/api/auth/login", json={"username":"student", "password":"wrong-password"})
    payload = {"username":"student", "password":"Passw0rd!23"}
    first = client.post("/api/auth/login", json=payload).json()
    assert first["security_action"] == "otp"
    second = client.post("/api/auth/login", json=payload).json()
    assert second["security_action"] == "otp"


def test_forwarded_header_cannot_claim_campus(client):
    client.post("/api/auth/register", json={"username":"student", "email":"student@example.com", "password":"Passw0rd!23"})
    body = client.post("/api/auth/login", headers={"X-Forwarded-For":"192.0.2.20"}, json={"username":"student", "password":"Passw0rd!23"}).json()
    assert body["network_context"] == EXTERNAL


def test_expired_otp_does_not_grant_access(client, db_session):
    from datetime import datetime, timedelta, timezone
    from app.models.login_attempt import LoginAttempt
    body = create_challenge(client)
    code = re.search(r"DEMO OTP: ([0-9]{6})", body["message"]).group(1)
    attempt = db_session.get(LoginAttempt, body["login_attempt_id"])
    attempt.otp_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()
    verified = client.post("/api/auth/verify-otp", json={"login_attempt_id":attempt.id, "otp_code":code}).json()
    assert not verified["success"]
    assert verified["access_token"] is None
