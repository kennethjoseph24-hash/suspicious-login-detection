from fastapi import APIRouter, Depends, HTTPException
from app.api.deps import require_admin
from app.config import settings
from sqlalchemy.orm import Session

from app.database.session import get_db, engine
from app.database.session import Base
from app.services.context_capture import DEMO_LOCATIONS
from app.models import User, LoginAttempt, SecurityAlert, UserBehaviorProfile  # noqa: F401

router = APIRouter(prefix="/api/demo", tags=["demo"])


@router.get("/locations")
def demo_locations():
    return {"locations": list(DEMO_LOCATIONS.keys())}


@router.post("/reset", dependencies=[Depends(require_admin)])
def reset_demo_data(db: Session = Depends(get_db)):
    """DEMO/DEV ONLY: wipes all login attempts, alerts and behavior profiles
    (but keeps user accounts) so the demo scenarios can be re-run from a clean
    slate. Never expose this endpoint in a production deployment."""
    if not settings.demo_context_enabled:
        raise HTTPException(status_code=403, detail="Demo mode is disabled.")
    db.query(SecurityAlert).delete()
    db.query(LoginAttempt).delete()
    db.query(UserBehaviorProfile).delete()
    db.commit()
    return {"message": "Demo login/security data has been reset. User accounts were preserved."}
