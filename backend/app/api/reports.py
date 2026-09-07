"""
Report generation routes.
"""

import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.models import Case
from app.reports.report_generator import generate_report_pdf

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/{case_id}/generate")
def generate_report(case_id: str, db: Session = Depends(get_db)):
    """Generates and streams a PDF forensic report for the given case."""
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    if not case.emails or not case.emails[0].analysis_json:
        raise HTTPException(
            status_code=400,
            detail="No analysis data stored for this case yet.",
        )

    analysis = json.loads(case.emails[0].analysis_json)
    pdf_buffer = generate_report_pdf(case, analysis)

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={case_id}_report.pdf"},
    )