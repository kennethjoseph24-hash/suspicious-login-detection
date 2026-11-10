from sqlalchemy.orm import Session

from app.models.security_alert import SecurityAlert
from app.models.login_attempt import LoginAttempt


def resolve_alerts_for_attempt(db: Session, attempt_id: int) -> None:
    db.query(SecurityAlert).filter(SecurityAlert.login_attempt_id == attempt_id).update({"status": "RESOLVED"})
    db.commit()


def create_alert_if_needed(db: Session, attempt: LoginAttempt) -> SecurityAlert | None:
    if attempt.risk_level == "LOW":
        return None

    alert_type = "HIGH_RISK_LOGIN" if attempt.risk_level == "HIGH" else "UNUSUAL_ACTIVITY"
    message = (
        f"{'High' if attempt.risk_level == 'HIGH' else 'Medium'} risk login attempt for "
        f"user '{attempt.username_attempted}' from {attempt.location or 'unknown location'} "
        f"(risk score {attempt.risk_score:.0f})."
    )
    alert = SecurityAlert(
        login_attempt_id=attempt.id,
        user_id=attempt.user_id,
        alert_type=alert_type,
        severity=attempt.risk_level,
        message=message,
        status="OPEN",
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert
