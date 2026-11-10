from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
import json

from app.database.session import get_db
from app.models.user import User
from app.schemas.auth import (
    RegisterRequest, RegisterResponse, LoginRequest, LoginResponse,
    VerifyOtpRequest, VerifyOtpResponse,
)
from app.security.auth import hash_password
from app.services.login_service import process_login, verify_otp_for_attempt
from app.config import settings

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=RegisterResponse, status_code=201)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already taken.")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered.")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    result = process_login(db, request, payload.username, payload.password, payload.demo_context)
    attempt = result["attempt"]
    response = {
        "login_attempt_id": attempt.id,
        "network_context": attempt.network_context,
        "security_action": attempt.security_action,
        "authentication_result": attempt.authentication_result,
        "risk_score": attempt.risk_score,
        "risk_level": attempt.risk_level,
        "is_suspicious": attempt.is_suspicious,
        "detection_reasons": json.loads(attempt.detection_reasons or "[]"),
        "otp_required": attempt.otp_required,
        "message": result["message"],
        "access_token": result["access_token"],
    }
    if settings.otp_demo_mode and result.get("demo_otp_code"):
        # DEMO MODE ONLY: surface the OTP directly in the API response and logs
        # because this academic prototype has no real SMS/email provider.
        response["message"] += f" [DEMO OTP: {result['demo_otp_code']}]"
    return response


@router.post("/verify-otp", response_model=VerifyOtpResponse)
def verify_otp(payload: VerifyOtpRequest, db: Session = Depends(get_db)):
    result = verify_otp_for_attempt(db, payload.login_attempt_id, payload.otp_code)
    return result
