from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.database.session import get_db
from app.models.security_alert import SecurityAlert
from app.schemas.dashboard import SecurityAlertOut

router = APIRouter(prefix="/api/alerts", tags=["alerts"], dependencies=[Depends(require_admin)])


@router.get("", response_model=list[SecurityAlertOut])
def list_alerts(
    db: Session = Depends(get_db),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
):
    q = db.query(SecurityAlert)
    if status:
        q = q.filter(SecurityAlert.status == status.upper())
    if severity:
        q = q.filter(SecurityAlert.severity == severity.upper())
    return q.order_by(SecurityAlert.created_at.desc()).limit(limit).all()


@router.post("/{alert_id}/resolve", response_model=SecurityAlertOut)
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    alert.status = "RESOLVED"
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert
