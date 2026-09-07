"""
Case management routes.

Lists and retrieves saved investigation cases from the database.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.models import Case

router = APIRouter(prefix="/api/cases", tags=["cases"])


@router.get("/")
def list_cases(db: Session = Depends(get_db)):
    """Returns all cases, most recent first."""
    cases = db.query(Case).order_by(Case.created_at.desc()).all()
    return [
        {
            "id": c.id,
            "case_id": c.case_id,
            "status": c.status,
            "threat_level": c.threat_level,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "subject": c.emails[0].subject if c.emails else None,
            "sender": c.emails[0].sender if c.emails else None,
        }
        for c in cases
    ]


@router.get("/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db)):
    """Returns full detail for a single case by its human-readable case_id."""
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    email = case.emails[0] if case.emails else None

    return {
        "case_id": case.case_id,
        "status": case.status,
        "threat_level": case.threat_level,
        "notes": case.notes,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "email": {
            "subject": email.subject if email else None,
            "sender": email.sender if email else None,
            "recipient": email.recipient if email else None,
            "date": email.date if email else None,
        } if email else None,
    }


@router.patch("/{case_id}/status")
def update_case_status(case_id: str, status: str, db: Session = Depends(get_db)):
    """Updates a case's status (OPEN, INVESTIGATING, CONFIRMED, FALSE POSITIVE, CLOSED)."""
    valid_statuses = {"OPEN", "INVESTIGATING", "CONFIRMED", "FALSE POSITIVE", "CLOSED"}
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Status must be one of {valid_statuses}")

    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    case.status = status
    db.commit()
    return {"case_id": case_id, "status": status}