from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text, func
from sqlalchemy.orm import relationship

from app.database.session import Base


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    username_attempted = Column(String(50), nullable=False, index=True)

    network_context = Column(String(30), nullable=True)
    security_action = Column(String(20), nullable=True)
    evaluated_login_hour = Column(Integer, nullable=True)

    ip_address = Column(String(45), nullable=False)
    location = Column(String(100), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    is_simulated_location = Column(Boolean, default=True)

    device = Column(String(100), nullable=True)
    browser = Column(String(100), nullable=True)
    operating_system = Column(String(100), nullable=True)

    login_timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    authentication_result = Column(String(20), nullable=False)  # success | failure
    failed_attempt_count = Column(Integer, default=0)

    risk_score = Column(Float, default=0)
    risk_level = Column(String(10), default="LOW", index=True)
    is_suspicious = Column(Boolean, default=False, index=True)
    detection_reasons = Column(Text, nullable=True)  # JSON-encoded list of strings
    ml_anomaly_score = Column(Float, nullable=True)
    ml_is_anomaly = Column(Boolean, nullable=True)

    otp_required = Column(Boolean, default=False)
    otp_verified = Column(Boolean, default=False)
    otp_code_hash = Column(String(255), nullable=True)
    otp_expires_at = Column(DateTime(timezone=True), nullable=True)
    otp_attempts = Column(Integer, default=0)

    ml_features_json = Column(Text, nullable=True)  # JSON dict of ML feature values

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="login_attempts")
    alerts = relationship("SecurityAlert", back_populates="login_attempt")
