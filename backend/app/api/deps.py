from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from app.security.auth import decode_access_token

__all__ = ["get_db", "require_admin"]

_bearer = HTTPBearer(auto_error=False)


def require_admin(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Security data is visible only to a signed-in administrator."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Sign in as an administrator to view this page.")
    try:
        user_id = decode_access_token(credentials.credentials).get("user_id")
    except JWTError:
        raise HTTPException(status_code=401, detail="Your session has expired. Please sign in again.")
    user = db.get(User, user_id) if user_id is not None else None
    if user is None:
        raise HTTPException(status_code=401, detail="Your session has expired. Please sign in again.")
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    return user
