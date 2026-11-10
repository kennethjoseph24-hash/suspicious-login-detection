import hashlib
import hmac
import secrets


def generate_otp() -> str:
    """Generate a 6-digit numeric OTP. DEMO MODE: not sent via real SMS/email."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(otp_code: str) -> str:
    return hashlib.sha256(otp_code.encode()).hexdigest()


def verify_otp(otp_code: str, otp_hash: str) -> bool:
    return hmac.compare_digest(hash_otp(otp_code), otp_hash or "")
