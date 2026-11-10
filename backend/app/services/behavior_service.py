import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.behavior_profile import UserBehaviorProfile
from app.services.context_capture import DEMO_LOCATIONS


def get_or_create_profile(db: Session, user_id: int) -> UserBehaviorProfile:
    profile = db.query(UserBehaviorProfile).filter(UserBehaviorProfile.user_id == user_id).first()
    if not profile:
        profile = UserBehaviorProfile(user_id=user_id)
        db.add(profile)
        db.commit()
        db.refresh(profile)
    return profile


def _load(json_text: str) -> list:
    try:
        return json.loads(json_text) if json_text else []
    except (TypeError, ValueError):
        return []


def profile_snapshot(profile: UserBehaviorProfile) -> dict:
    return {
        "known_locations": _load(profile.known_locations),
        "known_devices": _load(profile.known_devices),
        "known_browsers": _load(profile.known_browsers),
        "known_ips": _load(profile.known_ips),
        "known_os": _load(profile.known_os),
        "usual_hour_start": profile.usual_login_hour_start,
        "usual_hour_end": profile.usual_login_hour_end,
        "average_failed_attempts": profile.average_failed_attempts,
        "total_logins": profile.total_logins,
        "successful_logins": profile.successful_logins,
    }


def average_known_coordinates(profile: UserBehaviorProfile):
    locations = _load(profile.known_locations)
    if not locations:
        return None, None
    coords = [DEMO_LOCATIONS[loc] for loc in locations if loc in DEMO_LOCATIONS]
    if not coords:
        return None, None
    lat = sum(c[0] for c in coords) / len(coords)
    lon = sum(c[1] for c in coords) / len(coords)
    return lat, lon


def update_profile_after_login(
    db: Session,
    profile: UserBehaviorProfile,
    *,
    location: str,
    device: str,
    browser: str,
    ip_address: str,
    operating_system: str,
    login_hour: int,
    failed_attempt_count: int,
    authentication_result: str,
):
    locations = set(_load(profile.known_locations))
    devices = set(_load(profile.known_devices))
    browsers = set(_load(profile.known_browsers))
    ips = set(_load(profile.known_ips))
    os_set = set(_load(profile.known_os))

    if authentication_result == "success":
        # Only reinforce the "known" baseline on successful, low-effort logins
        # so a single suspicious success doesn't instantly get treated as normal.
        locations.add(location)
        devices.add(device)
        browsers.add(browser)
        ips.add(ip_address)
        os_set.add(operating_system)

        if profile.total_logins > 0:
            start, end = profile.usual_login_hour_start, profile.usual_login_hour_end
            if login_hour < start:
                profile.usual_login_hour_start = max(0, start - 1) if profile.successful_logins > 3 else start
            if login_hour > end:
                profile.usual_login_hour_end = min(23, end + 1) if profile.successful_logins > 3 else end
        profile.successful_logins += 1
        profile.last_login_at = datetime.now(timezone.utc)

    profile.known_locations = json.dumps(sorted(locations))
    profile.known_devices = json.dumps(sorted(devices))
    profile.known_browsers = json.dumps(sorted(browsers))
    profile.known_ips = json.dumps(sorted(ips))
    profile.known_os = json.dumps(sorted(os_set))

    total = profile.total_logins
    profile.average_failed_attempts = (
        (profile.average_failed_attempts * total + failed_attempt_count) / (total + 1)
    )
    profile.total_logins = total + 1

    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile
