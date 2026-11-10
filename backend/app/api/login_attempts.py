import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.database.session import get_db
from app.models.login_attempt import LoginAttempt
from app.services import behavior_service
from app.schemas.dashboard import LoginAttemptOut, LoginAttemptDetail, BehaviorSnapshot

router = APIRouter(prefix="/api/login-attempts", tags=["login-attempts"], dependencies=[Depends(require_admin)])


def _to_out(attempt: LoginAttempt) -> dict:
    d = {
        "id": attempt.id, "user_id": attempt.user_id, "username_attempted": attempt.username_attempted,
        "network_context": attempt.network_context, "security_action": attempt.security_action,
        "ip_address": attempt.ip_address, "location": attempt.location,
        "is_simulated_location": attempt.is_simulated_location, "device": attempt.device,
        "browser": attempt.browser, "operating_system": attempt.operating_system,
        "login_timestamp": attempt.login_timestamp, "authentication_result": attempt.authentication_result,
        "failed_attempt_count": attempt.failed_attempt_count, "risk_score": attempt.risk_score,
        "risk_level": attempt.risk_level, "is_suspicious": attempt.is_suspicious,
        "detection_reasons": json.loads(attempt.detection_reasons or "[]"),
        "ml_anomaly_score": attempt.ml_anomaly_score, "ml_is_anomaly": attempt.ml_is_anomaly,
        "otp_required": attempt.otp_required, "otp_verified": attempt.otp_verified,
    }
    return d


@router.get("", response_model=list[LoginAttemptOut])
def list_login_attempts(
    db: Session = Depends(get_db),
    risk_level: Optional[str] = Query(None),
    is_suspicious: Optional[bool] = Query(None),
    authentication_result: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    network_context: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
):
    q = db.query(LoginAttempt)
    if risk_level:
        q = q.filter(LoginAttempt.risk_level == risk_level.upper())
    if is_suspicious is not None:
        q = q.filter(LoginAttempt.is_suspicious == is_suspicious)
    if authentication_result:
        q = q.filter(LoginAttempt.authentication_result == authentication_result)
    if username:
        q = q.filter(LoginAttempt.username_attempted == username)
    if network_context:
        q = q.filter(LoginAttempt.network_context == network_context)
    attempts = q.order_by(LoginAttempt.login_timestamp.desc()).limit(limit).all()
    return [_to_out(a) for a in attempts]


@router.get("/{attempt_id}", response_model=LoginAttemptDetail)
def get_login_attempt(attempt_id: int, db: Session = Depends(get_db)):
    attempt = db.query(LoginAttempt).filter(LoginAttempt.id == attempt_id).first()
    if not attempt:
        raise HTTPException(status_code=404, detail="Login attempt not found.")

    import json as _json
    out = _to_out(attempt)
    out["historical_behavior"] = None
    out["ml_features"] = _json.loads(attempt.ml_features_json) if attempt.ml_features_json else None
    if attempt.user_id:
        profile = behavior_service.get_or_create_profile(db, attempt.user_id)
        snap = behavior_service.profile_snapshot(profile)
        out["historical_behavior"] = BehaviorSnapshot(
            known_locations=snap["known_locations"], known_devices=snap["known_devices"],
            known_browsers=snap["known_browsers"], known_os=snap["known_os"],
            usual_login_hour_start=snap["usual_hour_start"], usual_login_hour_end=snap["usual_hour_end"],
            average_failed_attempts=snap["average_failed_attempts"], total_logins=snap["total_logins"],
            successful_logins=snap["successful_logins"],
        )
    return out
