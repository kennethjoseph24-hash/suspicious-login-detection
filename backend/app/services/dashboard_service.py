from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.login_attempt import LoginAttempt
from app.models.security_alert import SecurityAlert


def get_stats(db: Session) -> dict:
    total = db.query(func.count(LoginAttempt.id)).scalar() or 0
    successful = db.query(func.count(LoginAttempt.id)).filter(
        LoginAttempt.authentication_result == "success").scalar() or 0
    failed = db.query(func.count(LoginAttempt.id)).filter(
        LoginAttempt.authentication_result == "failure").scalar() or 0
    blocked = db.query(func.count(LoginAttempt.id)).filter(
        LoginAttempt.authentication_result == "blocked").scalar() or 0
    pending = db.query(func.count(LoginAttempt.id)).filter(
        LoginAttempt.authentication_result == "pending").scalar() or 0
    suspicious = db.query(func.count(LoginAttempt.id)).filter(
        LoginAttempt.is_suspicious.is_(True)).scalar() or 0
    high = db.query(func.count(LoginAttempt.id)).filter(LoginAttempt.risk_level == "HIGH").scalar() or 0
    medium = db.query(func.count(LoginAttempt.id)).filter(LoginAttempt.risk_level == "MEDIUM").scalar() or 0
    low = db.query(func.count(LoginAttempt.id)).filter(LoginAttempt.risk_level == "LOW").scalar() or 0
    open_alerts = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "OPEN").scalar() or 0

    return {
        "total_logins": total,
        "successful_logins": successful,
        "failed_logins": failed,
        "blocked_logins": blocked,
        "pending_logins": pending,
        "suspicious_logins": suspicious,
        "high_risk_logins": high,
        "medium_risk_logins": medium,
        "low_risk_logins": low,
        "open_alerts": open_alerts,
    }


def get_risk_distribution(db: Session):
    rows = (
        db.query(LoginAttempt.risk_level, func.count(LoginAttempt.id))
        .group_by(LoginAttempt.risk_level)
        .all()
    )
    counts = {level: count for level, count in rows}
    return [
        {"risk_level": level, "count": counts.get(level, 0)}
        for level in ["LOW", "MEDIUM", "HIGH"]
    ]


def get_activity_over_time(db: Session, days: int = 14):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    attempts = db.query(LoginAttempt).filter(LoginAttempt.login_timestamp >= since).all()

    buckets = {}
    for a in attempts:
        ts = a.login_timestamp
        if ts is None:
            continue
        key = ts.strftime("%Y-%m-%d")
        b = buckets.setdefault(key, {"total": 0, "successful": 0, "failed": 0, "blocked": 0, "pending": 0, "suspicious": 0})
        b["total"] += 1
        if a.authentication_result == "success":
            b["successful"] += 1
        elif a.authentication_result == "failure":
            b["failed"] += 1
        elif a.authentication_result == "blocked":
            b["blocked"] += 1
        elif a.authentication_result == "pending":
            b["pending"] += 1
        if a.is_suspicious:
            b["suspicious"] += 1

    return [
        {"date": date, **counts}
        for date, counts in sorted(buckets.items())
    ]
