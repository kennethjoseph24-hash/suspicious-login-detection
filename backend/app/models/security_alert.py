from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, func
from sqlalchemy.orm import relationship

from app.database.session import Base


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    login_attempt_id = Column(Integer, ForeignKey("login_attempts.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    alert_type = Column(String(50), nullable=False)
    severity = Column(String(10), nullable=False, index=True)  # LOW | MEDIUM | HIGH
    message = Column(Text, nullable=False)
    status = Column(String(20), default="OPEN", index=True)  # OPEN | RESOLVED
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    login_attempt = relationship("LoginAttempt", back_populates="alerts")
