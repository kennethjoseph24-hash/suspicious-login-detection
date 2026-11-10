from datetime import datetime, timezone
from typing import Annotated, Optional, List
from pydantic import AfterValidator, BaseModel

# SQLite drops the time zone from stored UTC values. Mark them as UTC, so browsers
# convert them to local time instead of showing UTC as if it were local.
UtcDatetime = Annotated[datetime, AfterValidator(lambda v: v if v.tzinfo else v.replace(tzinfo=timezone.utc))]


class LoginAttemptOut(BaseModel):
    network_context: Optional[str] = None
    security_action: Optional[str] = None
    id: int
    user_id: Optional[int]
    username_attempted: str
    ip_address: str
    location: Optional[str]
    is_simulated_location: bool
    device: Optional[str]
    browser: Optional[str]
    operating_system: Optional[str]
    login_timestamp: UtcDatetime
    authentication_result: str
    failed_attempt_count: int
    risk_score: float
    risk_level: str
    is_suspicious: bool
    detection_reasons: List[str]
    ml_anomaly_score: Optional[float]
    ml_is_anomaly: Optional[bool]
    otp_required: bool
    otp_verified: bool

    class Config:
        from_attributes = True


class BehaviorSnapshot(BaseModel):
    known_locations: List[str]
    known_devices: List[str]
    known_browsers: List[str]
    known_os: List[str]
    usual_login_hour_start: int
    usual_login_hour_end: int
    average_failed_attempts: float
    total_logins: int
    successful_logins: int


class LoginAttemptDetail(LoginAttemptOut):
    historical_behavior: Optional[BehaviorSnapshot]
    ml_features: Optional[dict] = None


class SecurityAlertOut(BaseModel):
    id: int
    login_attempt_id: int
    user_id: Optional[int]
    alert_type: str
    severity: str
    message: str
    status: str
    created_at: UtcDatetime

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    blocked_logins: int = 0
    pending_logins: int = 0
    total_logins: int
    successful_logins: int
    failed_logins: int
    suspicious_logins: int
    high_risk_logins: int
    medium_risk_logins: int
    low_risk_logins: int
    open_alerts: int


class RiskDistributionPoint(BaseModel):
    risk_level: str
    count: int


class ActivityPoint(BaseModel):
    blocked: int = 0
    pending: int = 0
    date: str
    total: int
    successful: int
    failed: int
    suspicious: int
