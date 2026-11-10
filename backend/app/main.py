import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database.session import Base, engine
from app.config import settings
from app import models  # noqa: F401 ensures models are registered before create_all
from app.api import auth, login_attempts, dashboard, alerts, users, demo

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="Suspicious Login Detection API",
    description="Academic prototype: behavioral + ML-based suspicious login detection.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # auth uses Authorization headers, not cookies
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

# Additive migration preserves existing login records.
from sqlalchemy import inspect, text
with engine.begin() as connection:
    existing = {c["name"] for c in inspect(connection).get_columns("login_attempts")}
    for name, kind in {"ml_features_json": "TEXT", "network_context": "VARCHAR(30)",
                       "security_action": "VARCHAR(20)", "evaluated_login_hour": "INTEGER"}.items():
        if name not in existing:
            connection.execute(text(f"ALTER TABLE login_attempts ADD COLUMN {name} {kind}"))

app.include_router(auth.router)
app.include_router(login_attempts.router)
app.include_router(dashboard.router)
app.include_router(alerts.router)
app.include_router(users.router)
app.include_router(demo.router)


@app.get("/")
def root():
    return {"status": "ok", "service": "suspicious-login-detection-api"}


@app.get("/api/health")
def health():
    from app.ml.model_service import model_service
    return {"status": "healthy", "ml_model_loaded": model_service.loaded}
