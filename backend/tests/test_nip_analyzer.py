"""
Tests for NLPAnalyzer -- confirms phishing language patterns are detected.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analyzers.nlp_analyzer import NLPAnalyzer


def test_clean_text_has_zero_score():
    result = NLPAnalyzer("This is a normal reminder about tomorrow's meeting.").analyze()
    assert result["nlp_risk_score"] == 0
    assert result["risk_level"] == "CLEAN"


def test_urgency_language_detected():
    text = "Act immediately, your account will be suspended within 24 hours."
    result = NLPAnalyzer(text).analyze()
    assert result["nlp_risk_score"] > 0
    assert "urgency" in result["matched_phrases"]


def test_credential_harvesting_detected():
    text = "Please verify your identity by clicking the link below."
    result = NLPAnalyzer(text).analyze()
    assert "credential_harvesting" in result["matched_phrases"]


def test_empty_text_handled_gracefully():
    result = NLPAnalyzer("").analyze()
    assert result["nlp_risk_score"] == 0