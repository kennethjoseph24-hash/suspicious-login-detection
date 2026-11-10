import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "sqlite:///./dev_fallback.db"
    jwt_secret_key: str = "dev-secret-key-change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    otp_expire_minutes: int = 5
    otp_demo_mode: bool = True
    demo_context_enabled: bool = True
    campus_ip_ranges: str = "192.0.2.0/24"
    lab_device_tokens: str = "{}"
    login_timezone: str = "Asia/Kolkata"
    otp_max_attempts: int = 5
    # Failures older than this stop counting, so guessing cannot lock a student out forever.
    failed_attempt_window_minutes: int = 15

    risk_low_max: int = 30
    risk_medium_max: int = 60

    model_path: str = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "ml", "models", "isolation_forest.joblib",
    )

    class Config:
        env_file = ".env"
        extra = "ignore"
        protected_namespaces = ("settings_",)


settings = Settings()
