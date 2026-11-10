"""
Simulates one semester of college-ERP logins for a large student population.

THIS DATA IS SIMULATED. No real student, login or attack record is used. Every
behaviour rate below is a documented modelling assumption, not a measurement,
so results describe the system under these scenarios, not real-world accuracy.

Why simulate an event log instead of sampling feature values directly?
    The earlier generate_dataset.py draws feature values straight from
    hand-written distributions, so attack rows are separable by construction
    and any detector scores near-perfectly. Here, only behaviour is simulated:
    each student's chronological logins are replayed through the production
    build_features(), contextualize_features() and compute_risk() code, with a
    behaviour profile that learns as it would in production. Features therefore
    arise the same way they do at runtime, and realistic overlaps appear
    (holiday travel looks like an attack; a roommate on campus looks normal).

Usage (default: 50,000 students, 120 days, about 4-5 million events):
    python ml/training/generate_student_dataset.py
    python ml/training/generate_student_dataset.py --students 10000 --seed 7 --out DIR
"""
import argparse
import csv
import gzip
import json
import math
import multiprocessing as mp
import random
import shutil
import sys
import time
from collections import Counter, deque
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.ml.feature_engineering import FEATURE_COLUMNS, build_features  # noqa: E402
from app.config import settings  # noqa: E402
from app.services.network_context import CAMPUS, EXTERNAL, LAB, contextualize_features  # noqa: E402
from app.services.risk_engine import compute_risk, decide_action  # noqa: E402

SEMESTER_START = datetime(2025, 7, 14)
SEMESTER_DAYS = 120
SHARDS = 16
SAMPLE_STUDENTS = 400              # whole students kept for the small sample file
ATTACKED_STUDENT_FRACTION = 0.10   # stress-test level, not a prevalence claim
BASELINE_DAYS = 21                 # attacks begin only after baselines form
OTP_PASS_RATE_LEGIT = 0.97         # a real student occasionally abandons an OTP
FAILED_WINDOW = timedelta(minutes=settings.failed_attempt_window_minutes)

CAMPUS_CITY = "Hyderabad"
DOMESTIC = {
    "Hyderabad": (17.3850, 78.4867), "Bangalore": (12.9716, 77.5946),
    "Mumbai": (19.0760, 72.8777), "Delhi": (28.7041, 77.1025),
    "Chennai": (13.0827, 80.2707), "Pune": (18.5204, 73.8567),
    "Kolkata": (22.5726, 88.3639), "Vijayawada": (16.5062, 80.6480),
    "Visakhapatnam": (17.6868, 83.2185), "Warangal": (17.9689, 79.5941),
    "Nagpur": (21.1458, 79.0882), "Jaipur": (26.9124, 75.7873),
    "Patna": (25.5941, 85.1376), "Kochi": (9.9312, 76.2673),
}
FOREIGN = {
    "New York": (40.7128, -74.0060), "London": (51.5074, -0.1278),
    "Frankfurt": (50.1109, 8.6821), "Singapore": (1.3521, 103.8198),
    "Sao Paulo": (-23.5505, -46.6333), "Sydney": (-33.8688, 151.2093),
    "Amsterdam": (52.3676, 4.9041), "Tokyo": (35.6762, 139.6503),
}
CITY = {**DOMESTIC, **FOREIGN}
HOME_NAMES = ["Hyderabad", "Vijayawada", "Visakhapatnam", "Warangal", "Bangalore", "Chennai",
              "Mumbai", "Pune", "Delhi", "Kolkata", "Nagpur", "Jaipur", "Patna", "Kochi"]
HOME_WEIGHTS = [28, 12, 10, 9, 7, 6, 5, 4, 4, 3, 3, 3, 3, 3]

DEPARTMENTS = ["CSE", "ECE", "EEE", "MECH", "CIVIL", "IT", "AIML", "CHEM", "BIOTECH", "MBA"]
DEPARTMENT_WEIGHTS = [24, 16, 8, 10, 7, 12, 10, 4, 3, 6]

# archetype: (population share, logins/day, mean hour, hour sd, phone share, lab share)
ARCHETYPES = {
    "regular":      (0.40, 0.85, 18.0, 3.5, 0.30, 0.20),
    "lab_heavy":    (0.18, 0.95, 13.0, 3.0, 0.15, 0.55),
    "mobile_first": (0.20, 1.10, 16.0, 5.0, 0.80, 0.08),
    "night_owl":    (0.12, 0.95, 23.0, 2.5, 0.40, 0.10),
    "low_activity": (0.10, 0.25, 14.0, 4.0, 0.40, 0.20),
}
LAPTOPS = [("Windows Laptop", "Chrome", "Windows 11", 40), ("Windows Laptop", "Edge", "Windows 11", 12),
           ("Windows Laptop", "Chrome", "Windows 10", 22), ("Windows Laptop", "Firefox", "Windows 11", 6),
           ("MacBook", "Safari", "macOS", 7), ("MacBook", "Chrome", "macOS", 5),
           ("Linux Laptop", "Firefox", "Linux", 4), ("Linux Laptop", "Chrome", "Linux", 4)]
PHONES = [("Android Phone", "Chrome Mobile", "Android", 78), ("iPhone", "Mobile Safari", "iOS", 22)]
TABLET = ("Android Tablet", "Chrome Mobile", "Android")

# scenario: share of attack campaigns
SCENARIOS = {
    "credential_stuffing": 0.20,  # leaked password replay by a bot from a data centre
    "brute_force": 0.10,          # sustained online password guessing
    "foreign_takeover": 0.15,     # phished password used from abroad
    "domestic_phishing": 0.20,    # phished password used from another Indian city
    "impossible_travel": 0.05,    # abroad, minutes after a real login, spoofed device
    "insider_peer": 0.15,         # classmate on campus who saw the password
    "stolen_device": 0.07,        # the student's own device and browser
    "lab_shoulder_surf": 0.08,    # password observed, used on a registered lab PC
}

COLUMNS = ["student_id", "timestamp", "network_context", "ip_address", "location", "latitude",
           "longitude", "device", "browser", "operating_system", "login_hour", "password_correct",
           "failed_attempt_count", "seconds_since_last", "is_first_login", "os_novelty",
           *FEATURE_COLUMNS, "rule_score", "rule_level", "rule_action", "result",
           "label", "scenario", "stage", "campaign_id"]
STUDENT_COLUMNS = ["student_id", "department", "year", "residence", "home_city", "archetype"]


class Profile:
    """Same learning rules as behavior_service.update_profile_after_login,
    without a database. tests/test_simulator_parity.py keeps the two in step."""
    __slots__ = ("locations", "devices", "browsers", "ips", "os_names",
                 "start", "end", "total", "successful", "_coords")

    def __init__(self):
        self.locations, self.devices, self.browsers = set(), set(), set()
        self.ips, self.os_names = set(), set()
        self.start, self.end, self.total, self.successful = 8, 22, 0, 0
        self._coords = (None, None)

    def learn(self, location, device, browser, ip, os_name, hour):
        if location not in self.locations:
            self.locations.add(location)
            points = [CITY[name] for name in self.locations]
            self._coords = (sum(p[0] for p in points) / len(points),
                            sum(p[1] for p in points) / len(points))
        self.devices.add(device)
        self.browsers.add(browser)
        self.ips.add(ip)
        self.os_names.add(os_name)
        if self.total > 0:
            if hour < self.start and self.successful > 3:
                self.start = max(0, self.start - 1)
            if hour > self.end and self.successful > 3:
                self.end = min(23, self.end + 1)
        self.successful += 1
        self.total += 1


def poisson(rng, rate):
    limit, count, product = math.exp(-rate), 0, rng.random()
    while product > limit:
        count += 1
        product *= rng.random()
    return count


def is_holiday(date):
    return (datetime(2025, 9, 29) <= date <= datetime(2025, 10, 4)
            or datetime(2025, 10, 18) <= date <= datetime(2025, 10, 23))


def day_factor(date):
    factor = 0.6 if date.weekday() >= 5 else 1.0
    if datetime(2025, 9, 8) <= date <= datetime(2025, 9, 13):  # mid-semester exams
        factor *= 1.5
    if datetime(2025, 11, 3) <= date <= datetime(2025, 11, 10):  # end-semester exams
        factor *= 1.6
    if date == datetime(2025, 10, 10):  # results published
        factor *= 2.5
    if is_holiday(date):
        factor *= 0.4
    return factor


def external_ip(rng):
    return f"100.{rng.randint(64, 127)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"  # RFC 6598


def attacker_ip(rng):
    return f"198.{rng.randint(18, 19)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"   # RFC 2544


def lab_ip(rng):
    return f"192.0.2.{rng.randint(128, 254)}"


def campus_ip(rng):
    return f"192.0.2.{rng.randint(1, 127)}"


def make_student(rng, index):
    names = list(ARCHETYPES)
    archetype = rng.choices(names, [ARCHETYPES[n][0] for n in names])[0]
    department = rng.choices(DEPARTMENTS, DEPARTMENT_WEIGHTS)[0]
    home = rng.choices(HOME_NAMES, HOME_WEIGHTS)[0]
    residence = "day_scholar" if home == CAMPUS_CITY and rng.random() < 0.85 else (
        "hostel" if home != CAMPUS_CITY or rng.random() < 0.5 else "day_scholar")
    laptop = rng.choices(LAPTOPS, [row[3] for row in LAPTOPS])[0][:3]
    phone = rng.choices(PHONES, [row[3] for row in PHONES])[0][:3]
    return {
        "id": f"S{index:06d}", "department": department,
        "year": rng.randint(1, 2) if department == "MBA" else rng.randint(1, 4),
        "residence": residence, "home": home, "archetype": archetype,
        "laptop": laptop, "phone": phone, "has_laptop": rng.random() < 0.93,
        "home_ip": external_ip(rng),
    }


def make_attempt(when, context, ip, location, device, password_ok, *,
                 label=0, scenario="normal", stage="normal", campaign="", requires_access=False):
    return {"when": when, "context": context, "ip": ip, "location": location,
            "device": device[0], "browser": device[1], "os": device[2],
            "password_ok": password_ok, "label": label, "scenario": scenario,
            "stage": stage, "campaign": campaign, "requires_access": requires_access}


def plan_legitimate(rng, student):
    """A student's normal semester, including legitimate surprises."""
    params = ARCHETYPES[student["archetype"]]
    rate, mean_hour, hour_sd, phone_share, lab_share = params[1:]
    laptop, phone = student["laptop"], student["phone"]
    if rng.random() < 0.08:                    # moved to a different phone platform
        switch_day = rng.randint(10, SEMESTER_DAYS - 1)
        other_phone = next(p[:3] for p in PHONES if p[0] != phone[0])
    else:
        switch_day, other_phone = None, phone
    tablet_day = rng.randint(10, SEMESTER_DAYS - 1) if rng.random() < 0.05 else None
    trips = []
    for _ in range(poisson(rng, 0.35)):        # internship visit, fest, family event
        start = rng.randint(5, SEMESTER_DAYS - 6)
        city = rng.choice([c for c in DOMESTIC if c != CAMPUS_CITY])
        trips.append((start, start + rng.randint(2, 5), city))
    if rng.random() < 0.004:                   # exchange programme or conference abroad
        start = rng.randint(10, SEMESTER_DAYS - 12)
        trips.append((start, start + rng.randint(5, 10), rng.choice(list(FOREIGN))))
    wifi_ip = student["home_ip"]
    plan = []

    for day in range(SEMESTER_DAYS):
        date = SEMESTER_START + timedelta(days=day)
        if day % 7 == 0 and rng.random() < 0.5:
            wifi_ip = external_ip(rng)         # home broadband address rotates
        trip = next((t for t in trips if t[0] <= day <= t[1]), None)
        for _ in range(poisson(rng, rate * day_factor(date))):
            hour = int(rng.gauss(mean_hour, hour_sd)) % 24
            when = date + timedelta(hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
            on_phone = rng.random() < phone_share or not student["has_laptop"]
            current_phone = other_phone if switch_day is not None and day >= switch_day else phone
            device = current_phone if on_phone else laptop
            if tablet_day is not None and day >= tablet_day and rng.random() < 0.2:
                device = TABLET

            if trip:
                context, location = EXTERNAL, trip[2]
            elif is_holiday(date) and student["residence"] == "hostel" and rng.random() < 0.85:
                context, location = EXTERNAL, student["home"]
            else:
                roll = rng.random()
                on_site = date.weekday() < 5 and 8 <= hour <= 19
                away = 0.15 if student["residence"] == "hostel" else 0.45
                if on_site and roll < lab_share:
                    context = LAB
                elif roll < 1 - away:
                    context = CAMPUS
                else:
                    context = EXTERNAL
                location = student["home"] if (context == EXTERNAL and student["residence"] == "day_scholar") \
                    else CAMPUS_CITY

            if context == LAB:
                device = ("Lab Workstation", rng.choice(["Edge", "Chrome"]), "Windows 11")
                ip = lab_ip(rng)
            elif context == CAMPUS:
                ip = campus_ip(rng)
            elif on_phone or trip:
                ip = external_ip(rng)          # carrier NAT or a travel network
            else:
                ip = wifi_ip

            if context != LAB and rng.random() < 0.005:   # a friend's device or a cyber cafe
                device = rng.choices(LAPTOPS, [r[3] for r in LAPTOPS])[0][:3]
                ip = external_ip(rng) if context == EXTERNAL else ip
                if rng.random() < 0.3:
                    location = rng.choice([c for c in DOMESTIC if c != CAMPUS_CITY]) \
                        if context == EXTERNAL else location

            typo_rate = 0.10 if is_holiday(date) else 0.05
            failures = 0
            if rng.random() < 0.002:           # genuinely forgotten password
                failures = rng.randint(4, 10)
            elif rng.random() < typo_rate:
                failures = 1
                while failures < 6 and rng.random() < 0.25:
                    failures += 1
            for k in range(failures, 0, -1):
                plan.append(make_attempt(when - timedelta(seconds=k * rng.randint(8, 40)),
                                         context, ip, location, device, False))
            plan.append(make_attempt(when, context, ip, location, device, True))
            if rng.random() < 0.08:            # session timed out, signs back in
                plan.append(make_attempt(when + timedelta(seconds=rng.randint(40, 900)),
                                         context, ip, location, device, True))
    return plan


def plan_attack(rng, student, legit_plan):
    """One attack campaign. Follow-up logins happen only if the attacker got in."""
    names = list(SCENARIOS)
    scenario = rng.choices(names, [SCENARIOS[n] for n in names])[0]
    day = rng.randint(BASELINE_DAYS, SEMESTER_DAYS - 3)
    midnight = SEMESTER_START + timedelta(days=day)
    campaign = f"C{student['id'][1:]}"
    tag = dict(label=1, scenario=scenario, campaign=campaign)
    at_hour = lambda hour: midnight + timedelta(hours=hour % 24, minutes=rng.randint(0, 59),
                                                seconds=rng.randint(0, 59))
    laptop_like = rng.choices(LAPTOPS, [r[3] for r in LAPTOPS])[0][:3]
    victim_device = student["laptop"] if student["has_laptop"] else student["phone"]
    plan, followup = [], None

    def burst(start, count, context, ip, location, device, low=2, high=15):
        when = start
        for _ in range(count):
            plan.append(make_attempt(when, context, ip, location, device, False, stage="probe", **tag))
            when += timedelta(seconds=rng.randint(low, high))
        return when

    if scenario == "credential_stuffing":
        bot = ("Linux Server", "Headless Chrome", "Linux")
        ip, city = attacker_ip(rng), rng.choice(list(FOREIGN))
        when = at_hour(rng.randint(0, 23))
        if rng.random() < 0.4:                 # the leaked password still works
            when = burst(when, rng.randint(0, 1), EXTERNAL, ip, city, bot)
            plan.append(make_attempt(when, EXTERNAL, ip, city, bot, True, stage="entry", **tag))
            followup = (EXTERNAL, ip, city, bot)
        else:
            burst(when, rng.randint(1, 3), EXTERNAL, ip, city, bot)
    elif scenario == "brute_force":
        bot = ("Linux Server", rng.choice(["Headless Chrome", "Firefox"]), "Linux")
        ip, city = attacker_ip(rng), rng.choice(list(CITY))
        when = burst(at_hour(rng.randint(0, 23)), rng.randint(8, 40), EXTERNAL, ip, city, bot)
        if rng.random() < 0.05:
            plan.append(make_attempt(when, EXTERNAL, ip, city, bot, True, stage="entry", **tag))
            followup = (EXTERNAL, ip, city, bot)
    elif scenario == "foreign_takeover":
        ip, city = attacker_ip(rng), rng.choice(list(FOREIGN))
        plan.append(make_attempt(at_hour(rng.randint(0, 23)), EXTERNAL, ip, city, laptop_like, True,
                                 stage="entry", **tag))
        followup = (EXTERNAL, ip, city, laptop_like)
    elif scenario == "domestic_phishing":
        ip = attacker_ip(rng)
        city = rng.choice([c for c in DOMESTIC if c not in (CAMPUS_CITY, student["home"])])
        plan.append(make_attempt(at_hour(int(rng.gauss(19, 3))), EXTERNAL, ip, city, laptop_like, True,
                                 stage="entry", **tag))
        followup = (EXTERNAL, ip, city, laptop_like)
    elif scenario == "impossible_travel":
        ip, city = attacker_ip(rng), rng.choice(list(FOREIGN))
        anchors = [p["when"] for p in legit_plan if p["password_ok"] and p["when"] >= midnight]
        when = (anchors[0] if anchors else at_hour(12)) + timedelta(minutes=rng.randint(10, 60))
        plan.append(make_attempt(when, EXTERNAL, ip, city, victim_device, True, stage="entry", **tag))
        followup = (EXTERNAL, ip, city, victim_device)
    elif scenario == "insider_peer":
        ip = campus_ip(rng)
        plan.append(make_attempt(at_hour(int(rng.gauss(16, 3))), CAMPUS, ip, CAMPUS_CITY, laptop_like, True,
                                 stage="entry", **tag))
        followup = (CAMPUS, ip, CAMPUS_CITY, laptop_like)
    elif scenario == "stolen_device":
        context = rng.choice([CAMPUS, EXTERNAL])
        ip = campus_ip(rng) if context == CAMPUS else external_ip(rng)
        city = CAMPUS_CITY
        hour = rng.randint(1, 5) if rng.random() < 0.6 else rng.randint(9, 22)
        plan.append(make_attempt(at_hour(hour), context, ip, city, victim_device, True, stage="entry", **tag))
        followup = (context, ip, city, victim_device)
    else:  # lab_shoulder_surf
        device = ("Lab Workstation", rng.choice(["Edge", "Chrome"]), "Windows 11")
        ip = lab_ip(rng)
        plan.append(make_attempt(at_hour(rng.randint(9, 18)), LAB, ip, CAMPUS_CITY, device, True,
                                 stage="entry", **tag))
        followup = (LAB, ip, CAMPUS_CITY, device)

    if followup:                               # the attacker returns if access succeeded
        context, ip, city, device = followup
        for offset in sorted(rng.sample(range(1, 3), k=rng.randint(1, 2))):
            when = midnight + timedelta(days=offset, hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
            plan.append(make_attempt(when, context, ip, city, device, True, stage="persist",
                                     requires_access=True, **tag))
    return plan, scenario


def replay(rng, student, plan, writer, counters):
    """Run the attempts through the production feature and rule code in time order."""
    profile = Profile()
    recent_failures = deque(maxlen=20)
    last_attempt = None
    accessed = set()

    for item in sorted(plan, key=lambda p: p["when"]):
        if item["requires_access"] and item["campaign"] not in accessed:
            continue
        when, context = item["when"], item["context"]
        while recent_failures and when - recent_failures[0] > FAILED_WINDOW:
            recent_failures.popleft()
        failed_count = len(recent_failures)
        seconds_since = None if last_attempt is None else (when - last_attempt).total_seconds()
        latitude, longitude = CITY[item["location"]]
        hour = when.hour
        first_login = profile.total == 0
        features = build_features(
            location=item["location"], device=item["device"], browser=item["browser"],
            ip_address=item["ip"], latitude=latitude, longitude=longitude, login_hour=hour,
            failed_attempt_count=failed_count, seconds_since_last_attempt=seconds_since,
            known_locations=profile.locations, known_devices=profile.devices,
            known_browsers=profile.browsers, known_ips=profile.ips,
            usual_hour_start=profile.start, usual_hour_end=profile.end,
            avg_latitude=profile._coords[0], avg_longitude=profile._coords[1],
            operating_system=item["os"], known_os=profile.os_names,
        )
        features = contextualize_features(features, context)
        risk = compute_risk(features=features, failed_attempt_count=failed_count,
                            ml_anomaly_score=None, ml_is_anomaly=False,
                            is_first_ever_login=first_login, network_context=context)
        score, level = risk["score"], risk["level"]

        if not item["password_ok"]:
            score, level, action, result = max(score, 65), "HIGH", "block", "failure"
            recent_failures.append(when)
        else:
            action = decide_action(level, failed_count)
            if action == "allow":
                result = "success"
            elif action == "block":
                result = "blocked"
            elif item["label"] == 0 and rng.random() < OTP_PASS_RATE_LEGIT:
                result = "success"
            else:
                result = "otp_not_completed"   # attackers do not hold the student's OTP channel
            if result == "success":
                recent_failures.clear()
                profile.learn(item["location"], item["device"], item["browser"], item["ip"], item["os"], hour)
                if item["campaign"]:
                    accessed.add(item["campaign"])
        last_attempt = when

        writer.writerow([
            student["id"], when.isoformat(timespec="seconds"), context, item["ip"], item["location"],
            latitude, longitude, item["device"], item["browser"], item["os"], hour,
            int(item["password_ok"]), failed_count,
            "" if seconds_since is None else round(seconds_since, 1), int(first_login),
            features["os_novelty"], *[round(float(features[c]), 4) for c in FEATURE_COLUMNS],
            score, level, action, result, item["label"], item["scenario"], item["stage"], item["campaign"],
        ])
        counters["events"] += 1
        counters[f"label_{item['label']}"] += 1
        counters[f"context::{context}"] += 1
        counters[f"action::{item['label']}::{action}"] += 1
        counters[f"scenario_events::{item['scenario']}"] += 1


def run_shard(job):
    shard, first, last, seed, out_dir = job
    counters = Counter()
    events_path = Path(out_dir) / f"_events_{shard:02d}.csv.gz"
    students_path = Path(out_dir) / f"_students_{shard:02d}.csv.gz"
    sample_file = sample_writer = None
    if shard == 0:
        sample_file = open(Path(out_dir) / "student_logins_sample.csv", "w", newline="", encoding="utf-8")
        sample_writer = csv.writer(sample_file)
        sample_writer.writerow(COLUMNS)

    class Tee:
        def __init__(self, primary, secondary=None):
            self.primary, self.secondary = primary, secondary

        def writerow(self, row):
            self.primary.writerow(row)
            if self.secondary:
                self.secondary.writerow(row)

    with gzip.open(events_path, "wt", newline="", encoding="utf-8", compresslevel=6) as events_gz, \
            gzip.open(students_path, "wt", newline="", encoding="utf-8", compresslevel=6) as students_gz:
        events = csv.writer(events_gz)
        students = csv.writer(students_gz)
        if shard == 0:
            events.writerow(COLUMNS)
            students.writerow(STUDENT_COLUMNS)
        for index in range(first, last):
            rng = random.Random(seed * 10_000_019 + index)  # independent of the worker count
            student = make_student(rng, index)
            plan = plan_legitimate(rng, student)
            if rng.random() < ATTACKED_STUDENT_FRACTION:
                attack_plan, scenario = plan_attack(rng, student, plan)
                plan += attack_plan
                counters["campaigns"] += 1
                counters[f"campaigns::{scenario}"] += 1
            keep_sample = sample_writer is not None and index - first < SAMPLE_STUDENTS
            replay(rng, student, plan, Tee(events, sample_writer if keep_sample else None), counters)
            students.writerow([student["id"], student["department"], student["year"],
                               student["residence"], student["home"], student["archetype"]])
            counters["students"] += 1
            counters[f"residence::{student['residence']}"] += 1
            counters[f"archetype::{student['archetype']}"] += 1
            counters[f"department::{student['department']}"] += 1
    if sample_file:
        sample_file.close()
    return dict(counters)


def concatenate(parts, target):
    """Concatenated gzip members form a single valid gzip file."""
    with open(target, "wb") as output:
        for part in parts:
            with open(part, "rb") as source:
                shutil.copyfileobj(source, output)
            Path(part).unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--students", type=int, default=50_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--out", default=str(ROOT / "ml" / "dataset"))
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    step = args.students / SHARDS
    jobs = [(i, round(i * step), round((i + 1) * step), args.seed, str(out_dir)) for i in range(SHARDS)]
    started = time.perf_counter()
    with mp.Pool(args.workers) as pool:
        results = pool.map(run_shard, jobs, chunksize=1)
    totals = Counter()
    for result in results:
        totals.update(result)

    concatenate([out_dir / f"_events_{i:02d}.csv.gz" for i in range(SHARDS)], out_dir / "student_login_events.csv.gz")
    concatenate([out_dir / f"_students_{i:02d}.csv.gz" for i in range(SHARDS)], out_dir / "students.csv.gz")

    summary = {
        "data_source": "Simulated. Contains no real student, login or attack records.",
        "seed": args.seed, "students": totals["students"], "semester_days": SEMESTER_DAYS,
        "events": totals["events"], "normal_events": totals["label_0"], "attack_events": totals["label_1"],
        "attack_campaigns": totals["campaigns"],
        "attacked_student_fraction_assumed": ATTACKED_STUDENT_FRACTION,
        "campaigns_by_scenario": {k.split("::")[1]: v for k, v in totals.items() if k.startswith("campaigns::")},
        "events_by_scenario": {k.split("::")[1]: v for k, v in totals.items() if k.startswith("scenario_events::")},
        "events_by_context": {k.split("::")[1]: v for k, v in totals.items() if k.startswith("context::")},
        "students_by_residence": {k.split("::")[1]: v for k, v in totals.items() if k.startswith("residence::")},
        "students_by_archetype": {k.split("::")[1]: v for k, v in totals.items() if k.startswith("archetype::")},
        "students_by_department": {k.split("::")[1]: v for k, v in totals.items() if k.startswith("department::")},
        "generation_seconds": round(time.perf_counter() - started, 1),
    }
    (out_dir / "student_dataset_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
