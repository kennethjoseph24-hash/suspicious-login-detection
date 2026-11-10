"""
Seeds demo users and login history so the README's demo scenarios and
admin dashboard have real, consistent data to run against.

Run from the backend venv per README section 14:

    cd backend
    venv\\Scripts\\python ../database/seed.py

Creates:
- kenneth / Passw0rd!23 — 18 days of successful Hyderabad / Windows Laptop /
  Chrome logins around hour 20, so his behavior profile treats that as
  "known" (the LOW-risk baseline demo scenario).
- priya / Passw0rd!23 — same idea, but Bangalore / MacBook / Chrome.
- admin / AdminPass!23 — is_admin=1, no login history; the only account that can
  open the dashboard.
- ravi / Passw0rd!23 — Mumbai / Android Phone / Firefox history.
- sajida / Passw0rd!23 — no history, for showing a first login.

Login history is created by calling the real
app.services.behavior_service.update_profile_after_login (not hand-crafted
rows), so the resulting behavior profile matches exactly what real logins
would have produced.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

BACKEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))

from app.database.session import Base, engine, SessionLocal  # noqa: E402
from app import models  # noqa: E402,F401
from app.models.user import User  # noqa: E402
from app.models.login_attempt import LoginAttempt  # noqa: E402
from app.security.auth import hash_password  # noqa: E402
from app.services.behavior_service import get_or_create_profile, update_profile_after_login  # noqa: E402
from app.services.context_capture import DEMO_LOCATIONS  # noqa: E402

DAYS_OF_HISTORY = 18


def seed_user(db, *, username, email, password, is_admin=False):
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        print(f"  {username}: already exists, skipping user creation")
        return existing
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        is_admin=1 if is_admin else 0,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    print(f"  {username}: created (id={user.id})")
    return user


def seed_login_history(db, user, *, location, device, browser, operating_system, hour):
    lat, lon = DEMO_LOCATIONS[location]
    profile = get_or_create_profile(db, user.id)

    if profile.total_logins > 0:
        print(f"  {user.username}: behavior profile already has history, skipping")
        return

    now = datetime.now(timezone.utc)
    for day_offset in range(DAYS_OF_HISTORY, 0, -1):
        login_time = now - timedelta(days=day_offset, minutes=day_offset)  # slight jitter

        attempt = LoginAttempt(
            user_id=user.id,
            username_attempted=user.username,
            network_context="External Connection",
            security_action="allow",
            evaluated_login_hour=hour,
            ip_address="203.0.113.10",
            location=location,
            latitude=lat,
            longitude=lon,
            is_simulated_location=True,
            device=device,
            browser=browser,
            operating_system=operating_system,
            login_timestamp=login_time,
            authentication_result="success",
            failed_attempt_count=0,
            risk_score=5.0,
            risk_level="LOW",
            is_suspicious=False,
            detection_reasons="[]",
            ml_anomaly_score=None,
            ml_is_anomaly=None,
            otp_required=False,
            otp_verified=False,
        )
        db.add(attempt)
        db.commit()

        profile = update_profile_after_login(
            db,
            profile,
            location=location,
            device=device,
            browser=browser,
            ip_address="203.0.113.10",
            operating_system=operating_system,
            login_hour=hour,
            failed_attempt_count=0,
            authentication_result="success",
        )

    print(f"  {user.username}: seeded {DAYS_OF_HISTORY} days of {location}/{device}/{browser} history "
          f"(total_logins={profile.total_logins})")


def main():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        print("Seeding users...")
        kenneth = seed_user(db, username="kenneth", email="kenneth@example.com", password="Passw0rd!23")
        priya = seed_user(db, username="priya", email="priya@example.com", password="Passw0rd!23")
        seed_user(db, username="admin", email="admin@example.com", password="AdminPass!23", is_admin=True)

        ravi = seed_user(db, username="ravi", email="ravi@example.com", password="Passw0rd!23")
        sajida = seed_user(db, username="sajida", email="sajida@example.com", password="Passw0rd!23")
        

        # --- ADD YOUR OWN USERS BELOW ---
        # yourname = seed_user(db, username="yourname", email="yourname@example.com", password="YourPass!23")

        print("Seeding login history...")
        seed_login_history(
            db, kenneth,
            location="Hyderabad", device="Windows Laptop", browser="Chrome",
            operating_system="Windows 10", hour=20,
        )
        seed_login_history(
            db, priya,
            location="Bangalore", device="MacBook", browser="Chrome",
            operating_system="macOS", hour=20,
        )
        seed_login_history(
            db, ravi,
            location="Mumbai", device="Android Phone", browser="Firefox",
            operating_system="Android", hour=9,
        )
        print("Done.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
