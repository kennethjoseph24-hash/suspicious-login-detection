import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ["DATABASE_URL"] = "sqlite:///./test_suspicious_login.db"

import pytest
from fastapi.testclient import TestClient

from app.database.session import Base, engine, SessionLocal
from app.main import app
from app.models.user import User
from app.security.auth import create_access_token, hash_password


@pytest.fixture(scope="function", autouse=True)
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_client(client, db_session):
    """Same app, with a real administrator's bearer token attached."""
    admin = User(username="admin", email="admin@example.com",
                 password_hash=hash_password("AdminPass!23"), is_admin=1)
    db_session.add(admin)
    db_session.commit()
    client.headers["Authorization"] = f"Bearer {create_access_token(admin.username, admin.id)}"
    return client


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.close()
