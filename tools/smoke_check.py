"""One-command local demo check. Run from the project root:

    python tools/smoke_check.py

Start the backend and frontend first. This creates one admin login attempt in the
demo database, but does not reset or delete any data.
"""

import argparse
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class SmokeFailure(Exception):
    pass


def fetch(url, *, method="GET", body=None, token=None):
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, data=json.dumps(body).encode() if body is not None else None,
                      headers=headers, method=method)
    try:
        with urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except HTTPError as error:
        return error.code, error.read()
    except URLError as error:
        raise SmokeFailure(f"Cannot reach {url}: {error.reason}") from error


def expect_json(url, expected_status=200, **kwargs):
    status, raw = fetch(url, **kwargs)
    if status != expected_status:
        try:
            detail = json.loads(raw).get("detail", raw.decode(errors="replace"))
        except ValueError:
            detail = raw.decode(errors="replace")
        raise SmokeFailure(f"{url} returned HTTP {status}; expected {expected_status}. {detail}")
    try:
        return json.loads(raw)
    except ValueError as error:
        raise SmokeFailure(f"{url} did not return JSON") from error


def run(backend, frontend, username, password):
    health = expect_json(f"{backend}/api/health")
    if not health.get("ml_model_loaded"):
        raise SmokeFailure("Backend is running, but the trained ML model is not loaded.")
    print("PASS  Backend is healthy and the ML model is loaded")

    expect_json(f"{backend}/api/dashboard/dataset", expected_status=401)
    print("PASS  Dataset endpoint rejects unauthenticated requests")

    login = expect_json(f"{backend}/api/auth/login", method="POST",
                        body={"username": username, "password": password})
    token = login.get("access_token")
    if login.get("otp_required"):
        match = re.search(r"\[DEMO OTP: (\d{6})\]", login.get("message", ""))
        if not match:
            raise SmokeFailure("OTP required, but no demo code was returned. Complete admin sign-in manually.")
        verified = expect_json(f"{backend}/api/auth/verify-otp", method="POST",
                               body={"login_attempt_id": login["login_attempt_id"], "otp_code": match.group(1)})
        token = verified.get("access_token") if verified.get("success") else None
    if not token:
        raise SmokeFailure(f"Admin sign-in failed: {login.get('message', 'no access token returned')}")
    print("PASS  Demo administrator can sign in")

    dataset = expect_json(f"{backend}/api/dashboard/dataset", token=token)
    summary, model, system = dataset["summary"], dataset["model"], dataset["system"]
    split = model["split"]
    matrix = model["confusion_matrix"]
    if summary["students"] != 50_000 or summary["events"] != 5_507_347:
        raise SmokeFailure("Dataset summary does not match the expected simulated dataset.")
    if split["train_events"] + split["calibration_events"] + split["test_events"] != summary["events"]:
        raise SmokeFailure("Train/calibration/test counts do not add up to the dataset total.")
    if sum(matrix.values()) != split["test_events"] or system["test_events"] != split["test_events"]:
        raise SmokeFailure("Evaluation counts do not add up to the held-out test total.")
    print(f"PASS  Dataset view returns {summary['students']:,} students and {summary['events']:,} events")
    print(f"PASS  Held-out evaluation has {split['test_events']:,} events and consistent counts")

    stats = expect_json(f"{backend}/api/dashboard/stats", token=token)
    print(f"PASS  Administrator can read live dashboard stats ({stats['total_logins']} recorded attempts)")

    status, raw = fetch(f"{frontend}/dashboard")
    if status != 200 or b"CampusGuard" not in raw:
        raise SmokeFailure(f"Frontend dashboard did not load correctly (HTTP {status}).")
    print("PASS  Frontend dashboard loads")
    print("\nAll demo checks passed. Open the Admin Dashboard and select 'Dataset & model'.")


def main():
    parser = argparse.ArgumentParser(description="Check the running CampusGuard demo end to end.")
    parser.add_argument("--backend", default="http://localhost:8000")
    parser.add_argument("--frontend", default="http://localhost:3000")
    parser.add_argument("--username", default="admin")
    args = parser.parse_args()
    # This default is for the seeded local prototype account only.
    password = os.getenv("CAMPUSGUARD_SMOKE_ADMIN_PASSWORD", "AdminPass!23")
    try:
        run(args.backend.rstrip("/"), args.frontend.rstrip("/"), args.username, password)
    except SmokeFailure as error:
        print(f"FAIL  {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
