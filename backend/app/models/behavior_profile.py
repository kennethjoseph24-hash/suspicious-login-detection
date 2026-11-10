from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float, func
from sqlalchemy.orm import relationship

from app.database.session import Base


class UserBehaviorProfile(Base):
    __tablename__ = "user_behavior_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False, index=True)

    known_locations = Column(Text, default="[]")   # JSON list
    known_devices = Column(Text, default="[]")      # JSON list
    known_browsers = Column(Text, default="[]")     # JSON list
    known_ips = Column(Text, default="[]")          # JSON list
    known_os = Column(Text, default="[]")           # JSON list

    usual_login_hour_start = Column(Integer, default=8)
    usual_login_hour_end = Column(Integer, default=22)

    average_failed_attempts = Column(Float, default=0)
    total_logins = Column(Integer, default=0)
    successful_logins = Column(Integer, default=0)

    last_login_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    user = relationship("User", back_populates="behavior_profile")
