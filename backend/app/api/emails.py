"""
API routes related to emails.

Phase 3: upload + parse
Phase 4: + header forensics / authentication analysis
Phase 5: + URL analysis / IP classification
Phase 6: + NLP phishing language analysis
Phase 7: + attachment analysis
Phase 8: + ML classification
Phase 9: + threat intelligence
Phase 10: + geolocation
Phase 11: + correlation engine (final risk score)
Case Management: + save each analysis as a Case + Email record
PDF Reports: + store full analysis JSON for report generation
"""
from app.core.deps import get_current_user
from app.models.models import User
import uuid
import json
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session

from app.parsers.email_parser import EmailParser
from app.analyzers.header_analyzer import HeaderAnalyzer
from app.analyzers.url_analyzer import analyze_urls
from app.analyzers.ip_analyzer import analyze_ips
from app.analyzers.nlp_analyzer import NLPAnalyzer
from app.analyzers.attachment_analyzer import analyze_attachments
from app.ml.predict import predict
from app.services.threat_intel_service import get_threat_intel_service
from app.services.geoip_service import get_geoip_service
from app.correlation.risk_engine import calculate_final_risk
from app.database.session import get_db
from app.models.models import Case, Email

router = APIRouter(prefix="/api/emails", tags=["emails"])


@router.post("/upload")
async def upload_email(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported right now.")

    raw_bytes = await file.read()

    try:
        parser = EmailParser(raw_bytes)
        parsed_result = parser.parse()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse email: {str(e)}")

    try:
        header_analyzer = HeaderAnalyzer(parsed_result)
        header_analysis = header_analyzer.analyze()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Header analysis failed: {str(e)}")

    try:
        url_analysis = analyze_urls(parsed_result.get("urls", []))
        ip_analysis = analyze_ips(parsed_result.get("ips", []))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL/IP analysis failed: {str(e)}")

    try:
        nlp_analyzer = NLPAnalyzer(parsed_result.get("body_text", ""))
        nlp_analysis = nlp_analyzer.analyze()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"NLP analysis failed: {str(e)}")

    try:
        attachment_analysis = analyze_attachments(parsed_result.get("attachments", []))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attachment analysis failed: {str(e)}")

    try:
        ml_prediction = predict(parsed_result.get("body_text", ""))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ML prediction failed: {str(e)}")

    try:
        threat_intel = get_threat_intel_service()
        sender_domain = header_analysis.get("domain_analysis", {}).get("sender_domain", "")

        public_ips = [ip_info["ip"] for ip_info in ip_analysis if ip_info.get("is_public")]

        ip_intel = [threat_intel.check_ip(ip) for ip in public_ips]
        domain_intel = threat_intel.check_domain(sender_domain) if sender_domain else None
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat intelligence lookup failed: {str(e)}")

    try:
        geoip = get_geoip_service()
        geo_results = [geoip.locate(ip) for ip in public_ips]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Geolocation lookup failed: {str(e)}")

    threat_intelligence_data = {
        "ip_reputation": ip_intel,
        "domain_check": domain_intel,
    }

    try:
        final_verdict = calculate_final_risk(
            header_analysis=header_analysis,
            nlp_analysis=nlp_analysis,
            url_analysis=url_analysis,
            attachment_analysis=attachment_analysis,
            ml_prediction=ml_prediction,
            threat_intelligence=threat_intelligence_data,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Correlation engine failed: {str(e)}")

    case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"

    full_result = {
        "case_id": case_id,
        "filename": file.filename,
        "parsed": parsed_result,
        "final_verdict": final_verdict,
        "header_analysis": header_analysis,
        "url_analysis": url_analysis,
        "ip_analysis": ip_analysis,
        "nlp_analysis": nlp_analysis,
        "attachment_analysis": attachment_analysis,
        "ml_prediction": ml_prediction,
        "threat_intelligence": threat_intelligence_data,
        "geo_intelligence": geo_results,
    }

    try:
        new_case = Case(
            case_id=case_id,
            status="OPEN",
            threat_level=final_verdict["risk_level"],
        )
        db.add(new_case)
        db.commit()
        db.refresh(new_case)

        new_email = Email(
            case_id=new_case.id,
            subject=parsed_result["basic_fields"].get("subject", ""),
            sender=parsed_result["basic_fields"].get("from", ""),
            recipient=parsed_result["basic_fields"].get("to", ""),
            reply_to=parsed_result["basic_fields"].get("reply_to", ""),
            date=parsed_result["basic_fields"].get("date", ""),
            message_id=parsed_result["basic_fields"].get("message_id", ""),
            analysis_json=json.dumps(full_result),
        )
        db.add(new_email)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to save case: {str(e)}")

    return full_result