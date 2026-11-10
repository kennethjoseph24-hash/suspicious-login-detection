# Architecture

## Components

```
┌──────────────────────┐       REST / JSON       ┌───────────────────────────┐
│   Next.js frontend   │ ──────────────────────▶ │      FastAPI backend      │
│  portal + dashboard  │ ◀────────────────────── │  api / services / security│
└──────────────────────┘    bearer token (admin) └─────────────┬─────────────┘
                                                               │ SQLAlchemy
                                  ┌────────────────────────────┼─────────────┐
                                  ▼                                          ▼
                     ┌──────────────────────────┐            ┌──────────────────────────┐
                     │  ml/models/              │            │  SQLite or PostgreSQL    │
                     │  isolation_forest.joblib │            │  users, login_attempts,  │
                     │  (loaded at startup)     │            │  security_alerts,        │
                     └──────────────────────────┘            │  user_behavior_profiles  │
                                                             └──────────────────────────┘
```

## Request flow: one login

1. The frontend posts `{username, password, demo_context}` to `POST /api/auth/login`.
2. `services/network_context.py` classifies the login as Campus Network, Laboratory Device
   or External Connection, from configured IP ranges and a server-side device token.
3. `services/context_capture.py` reads device, browser and OS from the User-Agent, or from
   clearly labelled demo inputs. The password is checked with bcrypt.
4. `services/login_service.py` counts failures in the last 15 minutes and loads the
   student's profile from `services/behavior_service.py`.
5. `ml/feature_engineering.py` builds the eight features, and context rules suppress
   novelty that is expected on shared networks and lab PCs.
6. `ml/model_service.py` scores the features with the Isolation Forest. If the model file is
   missing, the system falls back to rules.
7. `services/risk_engine.py` turns signals into a 0-100 score, a level and readable reasons.
   `decide_action` chooses allow, OTP or block.
8. `services/alert_service.py` raises an alert for risky logins and for a guessing run
   reaching three failures. A verified OTP closes its alert.
9. Allowed logins and verified OTPs update the baseline. Blocked and failed logins do not.
10. The admin dashboard reads events, alerts and statistics through routes protected by
    `api/deps.py::require_admin`.

## Access control

Students and the public can use only registration, login, OTP verification and health checks.
Dashboard, alerts, login attempts, behaviour profiles and demo reset need a valid token
belonging to a user with `is_admin` set.
