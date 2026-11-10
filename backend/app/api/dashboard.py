import csv
import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.database.session import get_db
from app.schemas.dashboard import DashboardStats, RiskDistributionPoint, ActivityPoint
from app.services import dashboard_service

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"], dependencies=[Depends(require_admin)])
ML_ROOT = Path(__file__).resolve().parents[3] / "ml"


@router.get("/stats", response_model=DashboardStats)
def stats(db: Session = Depends(get_db)):
    return dashboard_service.get_stats(db)


@router.get("/risk-distribution", response_model=list[RiskDistributionPoint])
def risk_distribution(db: Session = Depends(get_db)):
    return dashboard_service.get_risk_distribution(db)


@router.get("/activity", response_model=list[ActivityPoint])
def activity(db: Session = Depends(get_db), days: int = 14):
    return dashboard_service.get_activity_over_time(db, days)


@router.get("/dataset")
def dataset_overview():
    """Small, read-only summary of the simulated training data and held-out results."""
    paths = {
        "summary": ML_ROOT / "dataset" / "student_dataset_summary.json",
        "model": ML_ROOT / "models" / "evaluation.json",
        "system": ML_ROOT / "results" / "system_evaluation.json",
    }
    if any(not path.is_file() for path in paths.values()):
        raise HTTPException(status_code=503, detail="Dataset or evaluation files are missing.")

    data = {name: json.loads(path.read_text(encoding="utf-8")) for name, path in paths.items()}
    sample_rows = []
    sample_path = ML_ROOT / "dataset" / "student_logins_sample.csv"
    if sample_path.is_file():
        seen_students = set()
        with sample_path.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                student_id = row["student_id"]
                if student_id in seen_students:
                    continue
                seen_students.add(student_id)
                sample_rows.append({key: row[key] for key in (
                    "student_id", "timestamp", "network_context", "location",
                    "device", "result", "label", "scenario",
                )})
                if len(sample_rows) == 12:
                    break

    system = data["system"]
    model = data["model"]
    attack_rows = model["attack_rows"]
    normal_rows = model["rows"] - attack_rows
    true_positive = round(model["recall"] * attack_rows)
    false_positive = round(model["false_positive_rate"] * normal_rows)
    return {
        "summary": data["summary"],
        "model": {
            **model,
            "confusion_matrix": {
                "true_positive": true_positive,
                "false_negative": attack_rows - true_positive,
                "false_positive": false_positive,
                "true_negative": normal_rows - false_positive,
            },
        },
        "system": {
            "test_students": system["test_students"],
            "test_events": system["test_events"],
            "policies": system["policies"],
            "scenarios": system["scenarios"]["Rules + Isolation Forest"],
            "ranking_correct_password_decisions": system["ranking_correct_password_decisions"],
        },
        "sample_rows": sample_rows,
    }
