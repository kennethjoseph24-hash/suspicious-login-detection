from datetime import datetime, timedelta, timezone
import json
from zoneinfo import ZoneInfo
from app.services.network_context import classify_context, contextualize_features

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.login_attempt import LoginAttempt
from app.security.auth import verify_password, create_access_token
from app.security.otp import generate_otp, hash_otp, verify_otp as check_otp
from app.services import behavior_service, context_capture
from app.services.risk_engine import compute_risk, decide_action
from app.services.alert_service import create_alert_if_needed, resolve_alerts_for_attempt
from app.ml.feature_engineering import build_features, FEATURE_COLUMNS
from app.ml.model_service import model_service
from app.config import settings


def _recent_failed_count(db: Session, username: str) -> int:
    """Failed attempts since the last success, within the configured time window.
    The window stops an attacker permanently locking a student out with bad guesses."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.failed_attempt_window_minutes)
    recent = (
        db.query(LoginAttempt)
        .filter(LoginAttempt.username_attempted == username,
                LoginAttempt.login_timestamp >= cutoff)
        .order_by(desc(LoginAttempt.login_timestamp))
        .limit(20)
        .all()
    )
    count = 0
    for attempt in recent:
        if attempt.authentication_result == "failure":
            count += 1
        elif attempt.authentication_result == "success":
            break
    return count


def _seconds_since_last_attempt(db: Session, username: str):
    last = (
        db.query(LoginAttempt)
        .filter(LoginAttempt.username_attempted == username)
        .order_by(desc(LoginAttempt.login_timestamp))
        .first()
    )
    if not last or not last.login_timestamp:
        return None
    now = datetime.now(timezone.utc)
    ts = last.login_timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (now - ts).total_seconds()


def process_login(db: Session, request, username: str, password: str, demo_context) -> dict:
    if not settings.demo_context_enabled:
        demo_context = None
    user = db.query(User).filter(User.username == username).first()

    ip_address = (demo_context.ip_address if demo_context and demo_context.ip_address
                  else context_capture.get_client_ip(request))
    network_context = classify_context(
        ip_address, request.headers.get("x-lab-device-token"),
        demo_context.lab_device_id if demo_context else None,
    )
    ua_string = request.headers.get("user-agent", "")
    device, browser, os_name = context_capture.parse_device_context(ua_string)

    location = "Unknown"
    is_simulated = bool(demo_context and demo_context.location)
    if demo_context and demo_context.location:
        location = demo_context.location
    if demo_context and demo_context.device:
        device = demo_context.device
    if demo_context and demo_context.browser:
        browser = demo_context.browser
    if demo_context and demo_context.operating_system:
        os_name = demo_context.operating_system

    lat, lon = context_capture.resolve_demo_location(location)
    if demo_context and demo_context.latitude is not None and demo_context.longitude is not None:
        lat, lon = demo_context.latitude, demo_context.longitude

    password_ok = bool(user and verify_password(password, user.password_hash))

    prior_failed = _recent_failed_count(db, username)
    failed_attempt_count = (
        demo_context.simulate_failed_attempts
        if demo_context and demo_context.simulate_failed_attempts is not None
        else prior_failed
    )

    now = datetime.now(timezone.utc)
    login_hour = demo_context.simulate_hour if (demo_context and demo_context.simulate_hour is not None) else now.astimezone(ZoneInfo(settings.login_timezone)).hour

    seconds_since_last = _seconds_since_last_attempt(db, username)

    is_first_ever_login = False
    profile = None
    features = {
        "location_novelty": 1, "device_novelty": 1, "browser_novelty": 1,
        "ip_novelty": 1, "hour_deviation": 0, "failed_attempts_norm": 0,
        "login_frequency_norm": 0, "geo_distance_norm": 0,
    }

    if user:
        profile = behavior_service.get_or_create_profile(db, user.id)
        snap = behavior_service.profile_snapshot(profile)
        is_first_ever_login = snap["total_logins"] == 0
        avg_lat, avg_lon = behavior_service.average_known_coordinates(profile)
        features = build_features(
            location=location, device=device, browser=browser, ip_address=ip_address,
            latitude=lat, longitude=lon, login_hour=login_hour,
            failed_attempt_count=failed_attempt_count,
            seconds_since_last_attempt=seconds_since_last,
            known_locations=snap["known_locations"], known_devices=snap["known_devices"],
            known_browsers=snap["known_browsers"], known_ips=snap["known_ips"],
            usual_hour_start=snap["usual_hour_start"], usual_hour_end=snap["usual_hour_end"],
            avg_latitude=avg_lat, avg_longitude=avg_lon,
            operating_system=os_name, known_os=snap["known_os"],
        )

    features = contextualize_features(features, network_context)
    features["network_context"] = network_context
    ml_score, ml_is_anomaly = (None, None)
    if user and not is_first_ever_login:
        ml_score, ml_is_anomaly = model_service.predict(features)
    # store ML feature values for the detail page breakdown
    features_for_storage = {k: features[k] for k in FEATURE_COLUMNS if k in features}

    risk = compute_risk(
        features=features, failed_attempt_count=failed_attempt_count,
        ml_anomaly_score=ml_score, ml_is_anomaly=ml_is_anomaly,
        is_first_ever_login=is_first_ever_login or not user, network_context=network_context,
    )

    if not password_ok:
        risk["level"] = "HIGH" if risk["level"] != "HIGH" else risk["level"]
        risk["score"] = max(risk["score"], 65)
        risk["reasons"] = ["Incorrect password"] + risk["reasons"]

    action = decide_action(risk["level"], failed_attempt_count, password_ok)
    otp_required = action == "otp"
    auth_result = "failure" if not password_ok else "blocked" if action == "block" else "pending" if otp_required else "success"

    attempt = LoginAttempt(
        user_id=user.id if user else None,
        username_attempted=username,
        network_context=network_context,
        security_action=action,
        evaluated_login_hour=login_hour,
        ip_address=ip_address,
        location=location,
        latitude=lat,
        longitude=lon,
        is_simulated_location=is_simulated,
        device=device,
        browser=browser,
        operating_system=os_name,
        authentication_result=auth_result,
        failed_attempt_count=failed_attempt_count,
        risk_score=risk["score"],
        risk_level=risk["level"],
        is_suspicious=risk["level"] != "LOW",
        detection_reasons=json.dumps(risk["reasons"]),
        ml_anomaly_score=ml_score,
        ml_is_anomaly=ml_is_anomaly,
        ml_features_json=json.dumps(features_for_storage) if features_for_storage else None,
        otp_required=otp_required,
        otp_verified=False,
    )

    if otp_required:
        otp_code = generate_otp()
        attempt.otp_code_hash = hash_otp(otp_code)
        attempt.otp_expires_at = now + timedelta(minutes=settings.otp_expire_minutes)
    else:
        otp_code = None

    db.add(attempt)
    db.commit()
    db.refresh(attempt)

    # Raise one alert when a run of wrong passwords reaches three, not one per guess or typo.
    if password_ok or failed_attempt_count == 2:
        create_alert_if_needed(db, attempt)

    if user and auth_result == "success":
        behavior_service.update_profile_after_login(
            db, profile, location=location, device=device, browser=browser,
            ip_address=ip_address, operating_system=os_name, login_hour=login_hour,
            failed_attempt_count=failed_attempt_count, authentication_result=auth_result,
        )

    access_token = None
    message = "Invalid username or password."
    if password_ok:
        if action == "block":
            message = "High-risk login blocked. Contact the college IT administrator."
        elif otp_required:
            message = "Suspicious login detected. Additional verification required."
        else:
            message = "Login successful."
            access_token = create_access_token(user.username, user.id)

    return {
        "attempt": attempt,
        "message": message,
        "access_token": access_token,
        "demo_otp_code": otp_code,  # DEMO MODE ONLY — see docs; never do this in production
    }


def verify_otp_for_attempt(db: Session, attempt_id: int, otp_code: str) -> dict:
    attempt = db.query(LoginAttempt).filter(LoginAttempt.id == attempt_id).first()
    if not attempt or not attempt.otp_required:
        return {"success": False, "message": "No OTP verification pending for this login attempt."}

    if attempt.otp_verified:
        return {"success": False, "message": "OTP already verified."}

    now = datetime.now(timezone.utc)
    expires_at = attempt.otp_expires_at
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at and now > expires_at:
        return {"success": False, "message": "OTP has expired. Please log in again."}

    if (attempt.otp_attempts or 0) >= settings.otp_max_attempts:
        return {"success": False, "message": "OTP attempt limit reached. Please log in again."}

    attempt.otp_attempts = (attempt.otp_attempts or 0) + 1

    if not check_otp(otp_code, attempt.otp_code_hash or ""):
        db.add(attempt)
        db.commit()
        return {"success": False, "message": "Incorrect OTP. Login denied."}

    attempt.otp_verified = True
    attempt.authentication_result = "success"
    db.add(attempt)
    db.commit()
    db.refresh(attempt)
    resolve_alerts_for_attempt(db, attempt.id)  # the student proved it was them

    user = attempt.user
    token = create_access_token(user.username, user.id) if user else None

    if user:
        profile = behavior_service.get_or_create_profile(db, user.id)
        behavior_service.update_profile_after_login(
            db, profile, location=attempt.location, device=attempt.device,
            browser=attempt.browser, ip_address=attempt.ip_address,
            operating_system=attempt.operating_system,
            login_hour=attempt.evaluated_login_hour if attempt.evaluated_login_hour is not None else 0,
            failed_attempt_count=attempt.failed_attempt_count,
            authentication_result="success",
        )

    return {"success": True, "message": "OTP verified. Login successful.", "access_token": token}
