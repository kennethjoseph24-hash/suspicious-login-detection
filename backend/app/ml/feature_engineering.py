"""
Builds the numeric feature vector for a single login attempt, comparing it
against the user's stored behavioral profile. FEATURE_COLUMNS are the 8 features
the Isolation Forest model was trained on. os_novelty is an extra rule-only
feature (not used by the ML model to preserve backward compatibility).
"""
import math
from datetime import datetime
from typing import Optional

FEATURE_COLUMNS = [
    "location_novelty",
    "device_novelty",
    "browser_novelty",
    "ip_novelty",
    "hour_deviation",
    "failed_attempts_norm",
    "login_frequency_norm",
    "geo_distance_norm",
]


def _haversine_km(lat1, lon1, lat2, lon2) -> float:
    if None in (lat1, lon1, lat2, lon2):
        return 0.0
    r = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(min(1, math.sqrt(a)))


def _hour_deviation(hour: int, start: int, end: int) -> float:
    in_window = start <= hour <= end if start <= end else hour >= start or hour <= end
    if in_window:
        return 0.0
    dist = min((hour - start) % 24, (start - hour) % 24,
               (hour - end) % 24, (end - hour) % 24)
    return min(1.0, dist / 12.0)


def build_features(
    *,
    location: Optional[str],
    device: Optional[str],
    browser: Optional[str],
    ip_address: str,
    latitude: Optional[float],
    longitude: Optional[float],
    login_hour: int,
    failed_attempt_count: int,
    seconds_since_last_attempt: Optional[float],
    known_locations: list,
    known_devices: list,
    known_browsers: list,
    known_ips: list,
    usual_hour_start: int,
    usual_hour_end: int,
    avg_latitude: Optional[float],
    avg_longitude: Optional[float],
    # rule-only extras (not in FEATURE_COLUMNS / not fed to ML model)
    operating_system: Optional[str] = None,
    known_os: Optional[list] = None,
) -> dict:
    location_novelty = 0 if not location or location == "Unknown" or location in known_locations else 1
    device_novelty = 0 if device in known_devices else 1
    browser_novelty = 0 if browser in known_browsers else 1
    ip_novelty = 0 if ip_address in known_ips else 1

    # OS novelty — rule engine only; not in FEATURE_COLUMNS
    os_novelty = 0
    if operating_system and known_os is not None:
        os_novelty = 0 if operating_system in known_os else 1

    hour_deviation = _hour_deviation(login_hour, usual_hour_start, usual_hour_end)
    failed_attempts_norm = min(1.0, failed_attempt_count / 5.0)

    if seconds_since_last_attempt is None:
        login_frequency_norm = 0.0
    else:
        login_frequency_norm = max(0.0, min(1.0, 1 - (seconds_since_last_attempt / 30.0)))

    distance_km = _haversine_km(avg_latitude, avg_longitude, latitude, longitude)
    geo_distance_norm = min(1.0, distance_km / 3000.0)

    return {
        # ML model features (FEATURE_COLUMNS)
        "location_novelty": location_novelty,
        "device_novelty": device_novelty,
        "browser_novelty": browser_novelty,
        "ip_novelty": ip_novelty,
        "hour_deviation": hour_deviation,
        "failed_attempts_norm": failed_attempts_norm,
        "login_frequency_norm": login_frequency_norm,
        "geo_distance_norm": geo_distance_norm,
        # rule-only extras
        "os_novelty": os_novelty,
    }
