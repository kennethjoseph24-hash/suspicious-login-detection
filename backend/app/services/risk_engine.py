"""Explainable, context-aware rules combined with Isolation Forest."""
from app.config import settings
from app.services.network_context import EXTERNAL, CAMPUS, LAB, contextualize_features


BLOCK_MIN_FAILURES = 3


def decide_action(level, failed_attempt_count, password_ok=True):
    """Unfamiliar behaviour earns an OTP; a hard block needs evidence of password guessing.
    Evaluation showed blocking on behaviour alone locked out 28% of genuine students in a
    semester (often just logging in from home) while stopping no attacker an OTP would not."""
    if not password_ok:
        return "block"
    if level == "LOW":
        return "allow"
    if level == "HIGH" and failed_attempt_count >= BLOCK_MIN_FAILURES:
        return "block"
    return "otp"


def compute_risk(*, features, failed_attempt_count, ml_anomaly_score,
                 ml_is_anomaly, is_first_ever_login, network_context=EXTERNAL):
    features = contextualize_features(features, network_context)
    score = 5 if is_first_ever_login else 0
    reasons = [f"Login context: {network_context}"]
    if network_context in (CAMPUS, LAB):
        reasons.append("Shared campus IP is expected; IP novelty carries no risk points")
    if network_context == LAB:
        reasons.append("Registered laboratory device; shared device and browser novelty carry no risk points")
    if is_first_ever_login:
        reasons.append("Limited history: establishing a baseline; failed-attempt checks remain active")
    novelty = 0
    if not is_first_ever_login:
        for key, points, reason in [
            ("location_novelty", 20, "Unfamiliar location"),
            ("device_novelty", 25, "Unfamiliar device"),
            ("browser_novelty", 10, "Unfamiliar browser"),
            ("os_novelty", 5, "Unfamiliar operating system"),
            ("ip_novelty", 10, "Unfamiliar external IP address"),
        ]:
            if features.get(key):
                score += points
                novelty += 1
                reasons.append(reason)
        if features.get("hour_deviation", 0) > .15:
            score += 15
            novelty += 1
            reasons.append("Login outside usual hours")
        if novelty >= 3:
            score += 10
            reasons.append("Multiple independent unfamiliar signals")
        if features.get("geo_distance_norm", 0) > .2:
            score += 10
            reasons.append("Location far from historical baseline")
        if ml_is_anomaly:
            score += 20
            reasons.append("Isolation Forest detected an unusual context-adjusted pattern")
    if failed_attempt_count:
        score += min(40, failed_attempt_count * 8)
        reasons.append(f"{failed_attempt_count} recent failed password attempts")
    # A rapid successful revisit alone should not cause a challenge.
    if failed_attempt_count and features.get("login_frequency_norm", 0) > .7:
        score += 15
        reasons.append("Rapid burst combined with failed passwords")
    if failed_attempt_count >= 8:
        score = max(score, 75)
        reasons.append("Repeated password failures exceed the blocking threshold")
    elif failed_attempt_count >= 3:
        score = max(score, settings.risk_low_max + 1)
        reasons.append("Repeated password failures require at least OTP verification")
    score = min(100, score)
    level = "LOW" if score <= settings.risk_low_max else "MEDIUM" if score <= settings.risk_medium_max else "HIGH"
    return {"score": score, "level": level, "reasons": reasons}
