from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)


class RegisterResponse(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class DemoContext(BaseModel):
    """Optional demo overrides used only because this is a local academic
    prototype without real IP geolocation / device fingerprinting."""
    location: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    device: Optional[str] = None
    browser: Optional[str] = None
    operating_system: Optional[str] = None
    ip_address: Optional[str] = None
    lab_device_id: Optional[str] = None
    simulate_failed_attempts: Optional[int] = Field(None, ge=0, le=100)
    simulate_hour: Optional[int] = Field(None, ge=0, le=23)  # override login hour for demo purposes


class LoginRequest(BaseModel):
    username: str
    password: str
    demo_context: Optional[DemoContext] = None


class LoginResponse(BaseModel):
    login_attempt_id: int
    network_context: str
    security_action: str
    authentication_result: str
    risk_score: float
    risk_level: str
    is_suspicious: bool
    detection_reasons: List[str]
    otp_required: bool
    message: str
    access_token: Optional[str] = None


class VerifyOtpRequest(BaseModel):
    login_attempt_id: int
    otp_code: str


class VerifyOtpResponse(BaseModel):
    success: bool
    message: str
    access_token: Optional[str] = None
