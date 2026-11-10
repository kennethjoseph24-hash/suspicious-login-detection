"""
Demo simulation script — sends varied login attempts to populate the dashboard
with realistic patterns: normal logins, credential stuffing, geo-anomalies,
brute-force bursts, and device/browser switching.
"""
import time
import random
import requests

BASE = "http://localhost:8000"

USERS = [
    {"username": "kenneth", "password": "Passw0rd!23"},
    {"username": "priya",   "password": "Passw0rd!23"},
    {"username": "ravi",    "password": "Passw0rd!23"},
]

WRONG_PASSWORDS = ["wrong123", "letmein", "abc123", "qwerty", "123456", "hunter2"]

LOCATIONS = [
    "Hyderabad", "Mumbai", "Chennai", "Bangalore",
    "New York", "London", "Moscow", "Beijing",
    "Tokyo", "Sydney", "Frankfurt", "São Paulo",
]

DEVICES = [
    "Windows Laptop", "MacBook Pro", "Linux Desktop",
    "Android Phone", "iPhone", "iPad", "Unknown Device",
    "Kali Linux VM", "Windows Server",
]

BROWSERS = ["Chrome", "Firefox", "Safari", "Edge", "Opera", "curl/7.88", "python-requests"]

HOURS = list(range(0, 24))

def login(username, password, location, device, browser, hour, failed_attempts=0, os_name="Windows 10"):
    payload = {
        "username": username,
        "password": password,
        "demo_context": {
            "location": location,
            "device": device,
            "browser": browser,
            "operating_system": os_name,
            "simulate_hour": hour,
            "simulate_failed_attempts": failed_attempts,
        }
    }
    try:
        r = requests.post(f"{BASE}/api/auth/login", json=payload, timeout=8)
        data = r.json()
        risk = data.get("risk_level", "?")
        score = data.get("risk_score", "?")
        result = data.get("authentication_result", "?")
        print(f"  [{result.upper():7}] {username:10} | {location:14} | {device:22} | hr={hour:02d} | risk={risk:6} score={score}")
        return data
    except Exception as e:
        print(f"  [ERROR] {e}")
        return {}

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

# ── 1. Normal baseline logins ──────────────────────────────────
section("1. Normal baseline — establishing behaviour profiles")
for _ in range(6):
    for u in USERS:
        login(u["username"], u["password"],
              location="Hyderabad", device="Windows Laptop",
              browser="Chrome", hour=random.randint(9, 18),
              os_name="Windows 10")
        time.sleep(0.3)

# ── 2. Successful logins from slightly varied but plausible context ──
section("2. Legitimate variation — same city, new browser")
for u in USERS:
    login(u["username"], u["password"],
          location="Hyderabad", device="Windows Laptop",
          browser="Firefox", hour=random.randint(10, 17),
          os_name="Windows 10")
    time.sleep(0.3)

# ── 3. New device logins (medium risk expected) ──────────────────
section("3. New device logins — should trigger MEDIUM risk")
for u in USERS:
    login(u["username"], u["password"],
          location="Hyderabad", device="New iPhone",
          browser="Safari", hour=20, os_name="iOS")
    time.sleep(0.3)

# ── 4. Geo-anomaly logins (HIGH risk expected) ───────────────────
section("4. Geographic anomaly — far foreign locations")
foreign = ["New York", "London", "Moscow", "Beijing", "Tokyo"]
for loc in foreign:
    u = random.choice(USERS)
    login(u["username"], u["password"],
          location=loc, device="Unknown Device",
          browser=random.choice(["Firefox", "Chrome", "curl/7.88"]),
          hour=random.randint(0, 5), os_name="Linux",
          failed_attempts=0)
    time.sleep(0.4)

# ── 5. Off-hours logins ──────────────────────────────────────────
section("5. Unusual hours — 2 AM to 4 AM logins")
for _ in range(5):
    u = random.choice(USERS)
    login(u["username"], u["password"],
          location="Hyderabad", device="Windows Laptop",
          browser="Chrome", hour=random.randint(2, 4),
          os_name="Windows 10")
    time.sleep(0.3)

# ── 6. Brute-force simulation (wrong password bursts) ───────────
section("6. Brute-force — repeated wrong passwords (HIGH risk)")
for u in USERS:
    for i, wrong_pw in enumerate(WRONG_PASSWORDS):
        login(u["username"], wrong_pw,
              location="New York", device="Kali Linux VM",
              browser="curl/7.88", hour=3,
              failed_attempts=i + 1, os_name="Kali Linux")
        time.sleep(0.15)

# ── 7. Credential stuffing — unknown usernames ───────────────────
section("7. Credential stuffing — unknown usernames")
fake_users = ["admin", "root", "test", "user1", "info", "support", "guest"]
for fake in fake_users:
    login(fake, random.choice(WRONG_PASSWORDS),
          location=random.choice(["Moscow", "Beijing", "São Paulo"]),
          device="Unknown Device", browser="python-requests",
          hour=random.randint(1, 6), failed_attempts=3,
          os_name="Linux")
    time.sleep(0.2)

# ── 8. Full combo attack — ALL novelty signals at once ───────────
section("8. Maximum suspicion — all signals combined (combo boost)")
for u in USERS:
    login(u["username"], u["password"],
          location="Moscow", device="Kali Linux VM",
          browser="curl/7.88", hour=3,
          failed_attempts=5, os_name="Kali Linux")
    time.sleep(0.3)

# ── 9. OTP bypass attempt (correct password, HIGH context) ───────
section("9. Correct password + HIGH risk context (OTP required)")
for u in USERS:
    data = login(u["username"], u["password"],
                 location="Frankfurt", device="Unknown Windows PC",
                 browser="Firefox", hour=2,
                 failed_attempts=4, os_name="Windows Server")
    if data.get("otp_required"):
        print(f"     >> OTP required for {u['username']} (not verified - simulating abandoned session)")
    time.sleep(0.4)

# ── 10. Recovery — normal logins at the end ──────────────────────
section("10. Recovery — normal logins after attack")
for _ in range(4):
    for u in USERS:
        login(u["username"], u["password"],
              location="Hyderabad", device="Windows Laptop",
              browser="Chrome", hour=random.randint(9, 17),
              os_name="Windows 10")
        time.sleep(0.3)

section("Simulation complete — refresh the dashboard at http://localhost:3000/dashboard")
