"""
LEGACY baseline, kept only for comparison in ml/training/evaluate_system.py.
The deployed model is trained by generate_student_dataset.py + train_model.py.

Samples 50,000 feature rows directly from hand-written distributions: 46,000
normal rows (five archetypes) and 4,000 attack rows (seven patterns). Attack rows
are separable by construction, which is why detectors score near-perfectly on it;
that score says little about real performance. The distributions are modelling
assumptions, not values calibrated against measurements.

Feature columns (must match backend/app/ml/feature_engineering.py::FEATURE_COLUMNS):
    location_novelty       — 0 = known location, 1 = first seen
    device_novelty         — 0 = known device,   1 = first seen
    browser_novelty        — 0 = known browser,  1 = first seen
    ip_novelty             — 0 = known IP,       1 = first seen
    hour_deviation         — 0.0 (within usual window) → 1.0 (12 h away)
    failed_attempts_norm   — failed_count / 5, capped at 1.0
    login_frequency_norm   — 1 − (seconds_since_last / 30), capped [0,1]
    geo_distance_norm      — haversine_km / 3000, capped at 1.0
"""
import os
import numpy as np
import pandas as pd

RANDOM_SEED      = 42
N_ROWS           = 50_000
ANOMALY_FRACTION = 0.08          # 8 % — matches CONTAMINATION in train_model.py
FEATURE_COLUMNS  = [
    "location_novelty",
    "device_novelty",
    "browser_novelty",
    "ip_novelty",
    "hour_deviation",
    "failed_attempts_norm",
    "login_frequency_norm",
    "geo_distance_norm",
]

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "dataset",
    "synthetic_login_data.csv",
)


def _c(x: np.ndarray) -> np.ndarray:
    """Clip to [0, 1]."""
    return np.clip(x, 0.0, 1.0)


# ── NORMAL ARCHETYPES ────────────────────────────────────────────────────────

def archetype_home_student(n: int, rng) -> pd.DataFrame:
    """
    Undergraduate who logs in from dorm / home on a personal laptop.
    Sessions between 08:00–23:00. Rarely sees a new device or location.
    Occasional new IP when roaming on mobile hotspot.
    """
    return pd.DataFrame({
        "location_novelty":     rng.binomial(1, 0.02, n),
        "device_novelty":       rng.binomial(1, 0.015, n),
        "browser_novelty":      rng.binomial(1, 0.03, n),
        "ip_novelty":           rng.binomial(1, 0.12, n),   # hotspot/VPN
        "hour_deviation":       _c(np.abs(rng.normal(0.01, 0.04, n))),
        "failed_attempts_norm": _c(np.abs(rng.normal(0.00, 0.04, n))),
        "login_frequency_norm": _c(np.abs(rng.normal(0.00, 0.03, n))),
        "geo_distance_norm":    _c(np.abs(rng.normal(0.01, 0.03, n))),
    })


def archetype_lab_student(n: int, rng) -> pd.DataFrame:
    """
    Student who logs in primarily from campus computer labs.
    Different machines each session -> moderate device/IP novelty.
    Typical hours: 10:00–20:00.  Very few failed attempts.
    """
    return pd.DataFrame({
        "location_novelty":     rng.binomial(1, 0.04, n),   # rotates lab rooms
        "device_novelty":       rng.binomial(1, 0.25, n),   # different lab PC each time
        "browser_novelty":      rng.binomial(1, 0.06, n),
        "ip_novelty":           rng.binomial(1, 0.20, n),   # lab subnets vary
        "hour_deviation":       _c(np.abs(rng.normal(0.00, 0.05, n))),
        "failed_attempts_norm": _c(np.abs(rng.normal(0.00, 0.03, n))),
        "login_frequency_norm": _c(np.abs(rng.normal(0.00, 0.02, n))),
        "geo_distance_norm":    _c(np.abs(rng.normal(0.00, 0.01, n))),
    })


def archetype_mobile_student(n: int, rng) -> pd.DataFrame:
    """
    Student who mostly uses a smartphone / tablet.
    Higher IP novelty (cellular networks rotate IPs). Scattered session hours.
    Occasionally switches to another app browser.
    """
    return pd.DataFrame({
        "location_novelty":     rng.binomial(1, 0.05, n),
        "device_novelty":       rng.binomial(1, 0.02, n),
        "browser_novelty":      rng.binomial(1, 0.08, n),   # in-app webview vs Safari
        "ip_novelty":           rng.binomial(1, 0.30, n),   # cellular IPs rotate
        "hour_deviation":       _c(np.abs(rng.normal(0.03, 0.07, n))),
        "failed_attempts_norm": _c(np.abs(rng.normal(0.00, 0.05, n))),
        "login_frequency_norm": _c(np.abs(rng.normal(0.00, 0.02, n))),
        "geo_distance_norm":    _c(np.abs(rng.normal(0.02, 0.04, n))),
    })


def archetype_graduate_student(n: int, rng) -> pd.DataFrame:
    """
    Postgraduate researcher. Long late-night sessions (20:00–02:00 normal for them).
    Very consistent device (own laptop). Occasionally accesses via university VPN.
    """
    return pd.DataFrame({
        "location_novelty":     rng.binomial(1, 0.02, n),
        "device_novelty":       rng.binomial(1, 0.01, n),
        "browser_novelty":      rng.binomial(1, 0.02, n),
        "ip_novelty":           rng.binomial(1, 0.15, n),   # VPN
        "hour_deviation":       _c(np.abs(rng.normal(0.00, 0.03, n))),  # night = their normal
        "failed_attempts_norm": _c(np.abs(rng.normal(0.00, 0.03, n))),
        "login_frequency_norm": _c(np.abs(rng.normal(0.00, 0.02, n))),
        "geo_distance_norm":    _c(np.abs(rng.normal(0.01, 0.02, n))),
    })


def archetype_faculty(n: int, rng) -> pd.DataFrame:
    """
    Faculty member. Extremely consistent: office desktop, campus Wi-Fi,
    09:00–17:00. Almost never a new device or location. Negligible failures.
    """
    return pd.DataFrame({
        "location_novelty":     rng.binomial(1, 0.005, n),
        "device_novelty":       rng.binomial(1, 0.005, n),
        "browser_novelty":      rng.binomial(1, 0.01, n),
        "ip_novelty":           rng.binomial(1, 0.04, n),
        "hour_deviation":       _c(np.abs(rng.normal(0.00, 0.02, n))),
        "failed_attempts_norm": _c(np.abs(rng.normal(0.00, 0.02, n))),
        "login_frequency_norm": _c(np.abs(rng.normal(0.00, 0.01, n))),
        "geo_distance_norm":    _c(np.abs(rng.normal(0.00, 0.01, n))),
    })


def generate_normal_rows(n: int, rng) -> pd.DataFrame:
    """
    Combine all five archetypes proportionally:
      35 % home student  |  25 % lab student  |  20 % mobile student
      12 % grad student  |   8 % faculty
    """
    splits = [int(n * f) for f in [0.35, 0.25, 0.20, 0.12]]
    splits.append(n - sum(splits))                    # remainder to faculty
    frames = [
        archetype_home_student(splits[0], rng),
        archetype_lab_student(splits[1], rng),
        archetype_mobile_student(splits[2], rng),
        archetype_graduate_student(splits[3], rng),
        archetype_faculty(splits[4], rng),
    ]
    return pd.concat(frames, ignore_index=True)


# ── ATTACK / ANOMALY PATTERNS ────────────────────────────────────────────────

def _attack_account_takeover(n: int, rng) -> pd.DataFrame:
    """
    Attacker uses stolen credentials from a different country.
    New location, device, IP; large geo distance; some failed attempts first.
    """
    return pd.DataFrame({
        "location_novelty":     np.ones(n),
        "device_novelty":       np.ones(n),
        "browser_novelty":      rng.binomial(1, 0.70, n),
        "ip_novelty":           np.ones(n),
        "hour_deviation":       _c(rng.uniform(0.0, 0.5, n)),
        "failed_attempts_norm": _c(rng.uniform(0.0, 0.4, n)),
        "login_frequency_norm": _c(rng.uniform(0.0, 0.3, n)),
        "geo_distance_norm":    _c(rng.uniform(0.5, 1.0, n)),
    })


def _attack_brute_force(n: int, rng) -> pd.DataFrame:
    """
    High volume of failed attempts from a single new IP, typically off-hours.
    """
    return pd.DataFrame({
        "location_novelty":     rng.binomial(1, 0.6, n),
        "device_novelty":       rng.binomial(1, 0.6, n),
        "browser_novelty":      rng.binomial(1, 0.4, n),
        "ip_novelty":           np.ones(n),
        "hour_deviation":       _c(rng.uniform(0.5, 1.0, n)),
        "failed_attempts_norm": _c(rng.uniform(0.6, 1.0, n)),
        "login_frequency_norm": _c(rng.uniform(0.3, 0.8, n)),
        "geo_distance_norm":    _c(rng.uniform(0.0, 0.5, n)),
    })


def _attack_credential_stuffing(n: int, rng) -> pd.DataFrame:
    """
    Automated tool tries many username/password pairs very rapidly.
    Very high login_frequency_norm; many failures; new IP every batch.
    """
    return pd.DataFrame({
        "location_novelty":     rng.binomial(1, 0.5, n),
        "device_novelty":       rng.binomial(1, 0.5, n),
        "browser_novelty":      rng.binomial(1, 0.5, n),
        "ip_novelty":           np.ones(n),
        "hour_deviation":       _c(rng.uniform(0.0, 0.7, n)),
        "failed_attempts_norm": _c(rng.uniform(0.4, 1.0, n)),
        "login_frequency_norm": _c(rng.uniform(0.8, 1.0, n)),   # very rapid
        "geo_distance_norm":    _c(rng.uniform(0.0, 0.7, n)),
    })


def _attack_impossible_travel(n: int, rng) -> pd.DataFrame:
    """
    Login from a location physically impossible given prior login time
    (e.g. India → USA within 20 minutes). Maximum geo distance.
    """
    return pd.DataFrame({
        "location_novelty":     np.ones(n),
        "device_novelty":       rng.binomial(1, 0.4, n),
        "browser_novelty":      rng.binomial(1, 0.3, n),
        "ip_novelty":           np.ones(n),
        "hour_deviation":       _c(rng.uniform(0.0, 0.4, n)),
        "failed_attempts_norm": _c(rng.uniform(0.0, 0.2, n)),
        "login_frequency_norm": _c(rng.uniform(0.0, 0.2, n)),
        "geo_distance_norm":    _c(rng.uniform(0.85, 1.0, n)),  # intercontinental
    })


def _attack_device_compromise(n: int, rng) -> pd.DataFrame:
    """
    Malware on a personal device exfiltrates session; attacker connects
    from a different sub-network. New device fingerprint + slightly off-hours.
    """
    return pd.DataFrame({
        "location_novelty":     rng.binomial(1, 0.3, n),
        "device_novelty":       np.ones(n),
        "browser_novelty":      rng.binomial(1, 0.6, n),
        "ip_novelty":           rng.binomial(1, 0.8, n),
        "hour_deviation":       _c(rng.uniform(0.3, 0.8, n)),
        "failed_attempts_norm": _c(rng.uniform(0.0, 0.3, n)),
        "login_frequency_norm": _c(rng.uniform(0.0, 0.4, n)),
        "geo_distance_norm":    _c(rng.uniform(0.1, 0.5, n)),
    })


def _attack_insider_threat(n: int, rng) -> pd.DataFrame:
    """
    Legitimate user (known location/device) accessing at an extreme hour
    with elevated failure count — e.g. trying to access another account.
    """
    return pd.DataFrame({
        "location_novelty":     rng.binomial(1, 0.05, n),   # their own location
        "device_novelty":       rng.binomial(1, 0.05, n),   # their own device
        "browser_novelty":      rng.binomial(1, 0.10, n),
        "ip_novelty":           rng.binomial(1, 0.15, n),
        "hour_deviation":       _c(rng.uniform(0.65, 1.0, n)),  # very late/early
        "failed_attempts_norm": _c(rng.uniform(0.4, 0.9, n)),
        "login_frequency_norm": _c(rng.uniform(0.3, 0.7, n)),
        "geo_distance_norm":    _c(rng.uniform(0.0, 0.1, n)),
    })


def _attack_worst_case(n: int, rng) -> pd.DataFrame:
    """All signals elevated simultaneously — maximum anomaly fingerprint."""
    return pd.DataFrame({
        "location_novelty":     np.ones(n),
        "device_novelty":       np.ones(n),
        "browser_novelty":      np.ones(n),
        "ip_novelty":           np.ones(n),
        "hour_deviation":       _c(rng.uniform(0.5, 1.0, n)),
        "failed_attempts_norm": _c(rng.uniform(0.5, 1.0, n)),
        "login_frequency_norm": _c(rng.uniform(0.4, 1.0, n)),
        "geo_distance_norm":    _c(rng.uniform(0.6, 1.0, n)),
    })


def generate_anomalous_rows(n: int, rng) -> pd.DataFrame:
    """
    Seven attack patterns, roughly equal weight:
      15 % account takeover   | 15 % brute force
      15 % credential stuffing | 15 % impossible travel
      15 % device compromise  | 12 % insider threat
      13 % worst case
    """
    fractions = [0.15, 0.15, 0.15, 0.15, 0.15, 0.12, 0.13]
    counts = [int(n * f) for f in fractions]
    counts[-1] += n - sum(counts)                      # absorb rounding
    generators = [
        _attack_account_takeover,
        _attack_brute_force,
        _attack_credential_stuffing,
        _attack_impossible_travel,
        _attack_device_compromise,
        _attack_insider_threat,
        _attack_worst_case,
    ]
    frames = [gen(k, rng) for gen, k in zip(generators, counts)]
    return pd.concat(frames, ignore_index=True)


# ── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    rng = np.random.default_rng(RANDOM_SEED)
    n_anomalous = int(N_ROWS * ANOMALY_FRACTION)
    n_normal    = N_ROWS - n_anomalous

    print(f"Generating {n_normal:,} normal rows across 5 archetypes …")
    normal_df = generate_normal_rows(n_normal, rng)

    print(f"Generating {n_anomalous:,} anomalous rows across 7 attack patterns …")
    anomalous_df = generate_anomalous_rows(n_anomalous, rng)

    # Preserve scenario ground truth instead of deriving labels from risk rules.
    normal_df["label"] = 0
    anomalous_df["label"] = 1
    for frame in (normal_df, anomalous_df):
        frame["network_context"] = rng.choice(
            ["Campus Network", "Laboratory Device", "External Connection"],
            size=len(frame), p=[.35, .30, .35],
        )
        campus = frame["network_context"] != "External Connection"
        lab = frame["network_context"] == "Laboratory Device"
        frame.loc[campus, "ip_novelty"] = 0
        frame.loc[lab, ["device_novelty", "browser_novelty"]] = 0
    df = pd.concat([normal_df, anomalous_df], ignore_index=True)
    df = df.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df.to_csv(OUTPUT_PATH, index=False)

    print(f"\nDataset saved to {OUTPUT_PATH}")
    print(f"  Total rows  : {len(df):,}")
    print(f"  Normal      : {n_normal:,} ({n_normal/len(df):.1%})")
    print(f"  Anomalous   : {n_anomalous:,} ({n_anomalous/len(df):.1%})")
    print(f"\nFeature statistics:\n{df.describe().round(4).to_string()}")


if __name__ == "__main__":
    main()
