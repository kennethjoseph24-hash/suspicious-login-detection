# Setup

`ReadMe.txt` covers the standard path, which uses SQLite and needs no configuration.

## Using PostgreSQL instead

```bash
docker compose up -d
psql -h localhost -U slduser -d suspicious_login_db -f database/schema.sql
```

Then create `backend/.env` containing:

```
DATABASE_URL=postgresql+psycopg2://slduser:sldpassword@localhost:5432/suspicious_login_db
```

Settings load from `.env` in the directory the backend starts from, so start it from `backend`.
Application behaviour is the same on either database.

## Before any real deployment

- Set `DEMO_CONTEXT_ENABLED=false` and `OTP_DEMO_MODE=false`, and connect real OTP delivery.
- Set a long random `JWT_SECRET_KEY`.
- Replace the demo `CAMPUS_IP_RANGES` with the institution's ranges, and issue real
  `LAB_DEVICE_TOKENS` through a trusted device agent, never through frontend code.
- Restrict CORS in `backend/app/main.py`.
- Upgrade Next.js: `npm audit` reports advisories for `next@14.2.32`. This matters for public
  deployment, not for local use.
