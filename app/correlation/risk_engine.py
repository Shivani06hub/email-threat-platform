"""
Correlation Engine.

Combines the output of every independent analyzer (ML model, header
forensics, NLP, URL analysis, attachment analysis, threat intelligence)
into a single, transparent Final Risk Score with a clear breakdown of
how it was calculated. This is the last step before a human analyst
sees the verdict -- it does NOT re-run detection logic itself, only
combines scores that were already computed elsewhere.

Weights (documented here so the methodology is transparent for the
project report):
    ML Classification        30%
    Header & Authentication  20%
    NLP Phishing Language    15%
    URL Risk (highest)       15%
    Attachment Risk (highest) 10%
    Domain/Threat Intel Risk 10%
"""

WEIGHTS = {
    "ml": 0.30,
    "header": 0.20,
    "nlp": 0.15,
    "url": 0.15,
    "attachment": 0.10,
    "domain_intel": 0.10,
}


def _highest_url_risk(url_analysis: list) -> int:
    if not url_analysis:
        return 0
    return max(u.get("risk_score", 0) for u in url_analysis)


def _highest_attachment_risk(attachment_analysis: list) -> int:
    if not attachment_analysis:
        return 0
    return max(a.get("risk_score", 0) for a in attachment_analysis)


def calculate_final_risk(
    header_analysis: dict,
    nlp_analysis: dict,
    url_analysis: list,
    attachment_analysis: list,
    ml_prediction: dict,
    threat_intelligence: dict,
) -> dict:
    """Combines all analyzer scores into one Final Risk Score with breakdown."""

    ml_score = ml_prediction.get("phishing_probability", 0)
    header_score = header_analysis.get("header_risk_score", 0)
    nlp_score = nlp_analysis.get("nlp_risk_score", 0)
    url_score = _highest_url_risk(url_analysis)
    attachment_score = _highest_attachment_risk(attachment_analysis)

    domain_check = threat_intelligence.get("domain_check") or {}
    domain_intel_score = domain_check.get("risk_score", 0)

    breakdown = {
        "ml_score": round(ml_score, 1),
        "header_risk": header_score,
        "nlp_risk": nlp_score,
        "url_risk": url_score,
        "attachment_risk": attachment_score,
        "domain_intel_risk": domain_intel_score,
    }

    final_score = (
        ml_score * WEIGHTS["ml"]
        + header_score * WEIGHTS["header"]
        + nlp_score * WEIGHTS["nlp"]
        + url_score * WEIGHTS["url"]
        + attachment_score * WEIGHTS["attachment"]
        + domain_intel_score * WEIGHTS["domain_intel"]
    )
    final_score = round(min(final_score, 100), 1)

    if final_score >= 80:
        classification = "MALICIOUS"
        risk_level = "CRITICAL"
    elif final_score >= 60:
        classification = "PHISHING"
        risk_level = "HIGH"
    elif final_score >= 30:
        classification = "SUSPICIOUS"
        risk_level = "MEDIUM"
    else:
        classification = "SAFE"
        risk_level = "LOW"

    return {
        "final_risk_score": final_score,
        "classification": classification,
        "risk_level": risk_level,
        "breakdown": breakdown,
        "weights_used": WEIGHTS,
        "methodology_note": (
            "Final score is a weighted average of the ML model (30%), "
            "header/authentication analysis (20%), NLP language analysis (15%), "
            "highest URL risk (15%), highest attachment risk (10%), and "
            "domain threat-intel heuristics (10%)."
        ),
    }