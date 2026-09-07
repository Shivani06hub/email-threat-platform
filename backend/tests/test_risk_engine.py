"""
Tests for the Correlation Engine -- confirms the final weighted
risk score and classification are calculated correctly.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.correlation.risk_engine import calculate_final_risk


def test_all_clean_inputs_result_in_safe():
    result = calculate_final_risk(
        header_analysis={"header_risk_score": 0},
        nlp_analysis={"nlp_risk_score": 0},
        url_analysis=[],
        attachment_analysis=[],
        ml_prediction={"phishing_probability": 0},
        threat_intelligence={"domain_check": {"risk_score": 0}},
    )
    assert result["classification"] == "SAFE"
    assert result["final_risk_score"] == 0.0


def test_high_risk_inputs_result_in_malicious():
    result = calculate_final_risk(
        header_analysis={"header_risk_score": 100},
        nlp_analysis={"nlp_risk_score": 100},
        url_analysis=[{"risk_score": 100}],
        attachment_analysis=[{"risk_score": 100}],
        ml_prediction={"phishing_probability": 100},
        threat_intelligence={"domain_check": {"risk_score": 100}},
    )
    assert result["classification"] == "MALICIOUS"
    assert result["final_risk_score"] == 100.0


def test_breakdown_contains_all_components():
    result = calculate_final_risk(
        header_analysis={"header_risk_score": 50},
        nlp_analysis={"nlp_risk_score": 50},
        url_analysis=[],
        attachment_analysis=[],
        ml_prediction={"phishing_probability": 50},
        threat_intelligence={"domain_check": None},
    )
    breakdown = result["breakdown"]
    assert "ml_score" in breakdown
    assert "header_risk" in breakdown
    assert "nlp_risk" in breakdown