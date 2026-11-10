# API Reference

Base URL: `http://localhost:8000`. Interactive docs (Swagger UI) are also
available at `/docs` while the backend is running. CORS is open (`*`) since
this is a local academic prototype.

**Access:** login-attempt, dashboard, alert, user-behaviour and demo-reset routes require
`Authorization: Bearer <token>` from an administrator's login. They return `401` without
a valid token and `403` for a non-administrator.

## Auth

### `POST /api/auth/register`
Body: `{username, email, password}` (username 3-50 chars, password 6-128).
→ `201` `{id, username, email, created_at}`. `400` if username/email taken.

### `POST /api/auth/login`
Body:
```json
{
  "username": "kenneth",
  "password": "Passw0rd!23",
  "demo_context": {
    "location": "Hyderabad", "device": "Windows Laptop", "browser": "Chrome",
    "operating_system": "Windows 10", "ip_address": "203.0.113.10",
    "simulate_hour": 20, "simulate_failed_attempts": 0
  }
}
```
`demo_context` is optional — every field in it is optional too; omitted
fields fall back to the real request's User-Agent/IP. Always returns `200`,
even for a wrong password or unknown user (the failure is communicated via
`authentication_result`, not an HTTP error, since a login attempt is itself
a valid API event to record).

→
```json
{
  "login_attempt_id": 39, "network_context": "External Connection",
  "security_action": "otp", "authentication_result": "pending",
  "risk_score": 80.0, "risk_level": "HIGH", "is_suspicious": true,
  "detection_reasons": ["Login context: External Connection", "Unfamiliar location", "..."],
  "otp_required": true,
  "message": "Suspicious login detected. Additional verification required. [DEMO OTP: 968252]",
  "access_token": null
}
```
The `[DEMO OTP: ...]` suffix only appears when `OTP_DEMO_MODE=true`
(default) — in a real deployment the OTP would be sent via SMS/email
instead of echoed back.

### `POST /api/auth/verify-otp`
Body: `{login_attempt_id, otp_code}` → `{success, message, access_token}`.

## Login attempts

### `GET /api/login-attempts`
Query: `risk_level`, `is_suspicious`, `authentication_result`, `username`,
`limit` (default 100, max 500). → list of attempts, newest first.

### `GET /api/login-attempts/{id}`
→ full attempt detail plus `historical_behavior` (the behavior profile
snapshot used to score this specific attempt). `404` if not found.

## Dashboard

- `GET /api/dashboard/stats` → totals (logins, success/fail, risk tiers, open alerts).
- `GET /api/dashboard/risk-distribution` → `[{risk_level, count}]`, always 3 rows (LOW/MEDIUM/HIGH).
- `GET /api/dashboard/activity?days=14` → `[{date, total, successful, failed, suspicious}]`.

- `GET /api/dashboard/dataset` returns the simulated dataset summary, model
  evaluation, held-out policy comparison, scenario outcomes, and up to 12 sample
  student rows. It reads saved files under `ml/` without importing the full log
  into SQLite.

## Alerts

- `GET /api/alerts` — query `status`, `severity`, `limit` → list, newest first.
- `POST /api/alerts/{id}/resolve` → marks `status="RESOLVED"`.

## Users

- `GET /api/users/{user_id}/behavior` → that user's current behavior profile
  snapshot (auto-creates an empty one if missing).

## Demo utilities

- `GET /api/demo/locations` → `{"locations": ["Hyderabad", "Bangalore", "Mumbai", "Delhi", "New York"]}`
  — the picker values for the frontend's demo controls.
- `POST /api/demo/reset` → deletes all login attempts, alerts, and behavior
  profiles (user accounts are kept) so the demo scenarios can be re-run
  from a clean slate.

## Health

- `GET /` → `{"status": "ok", ...}`.
- `GET /api/health` → `{"status": "healthy", "ml_model_loaded": true|false}`
  — `false` means the risk engine is running on rules only (no trained
  model file found at `ml/models/isolation_forest.joblib`).
