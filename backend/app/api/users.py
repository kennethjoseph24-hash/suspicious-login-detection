from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.database.session import get_db
from app.models.user import User
from app.services import behavior_service
from app.schemas.dashboard import BehaviorSnapshot

router = APIRouter(prefix="/api/users", tags=["users"], dependencies=[Depends(require_admin)])


@router.get("/{user_id}/behavior", response_model=BehaviorSnapshot)
def get_user_behavior(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    profile = behavior_service.get_or_create_profile(db, user_id)
    snap = behavior_service.profile_snapshot(profile)
    return BehaviorSnapshot(
        known_locations=snap["known_locations"], known_devices=snap["known_devices"],
        known_browsers=snap["known_browsers"], known_os=snap["known_os"],
        usual_login_hour_start=snap["usual_hour_start"], usual_login_hour_end=snap["usual_hour_end"],
        average_failed_attempts=snap["average_failed_attempts"], total_logins=snap["total_logins"],
        successful_logins=snap["successful_logins"],
    )
