"""
Tests for HeaderAnalyzer -- confirms SPF/DKIM/DMARC parsing and
domain mismatch detection work correctly.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analyzers.header_analyzer import HeaderAnalyzer


def test_clean_email_has_low_risk():
    parsed = {
        "basic_fields": {
            "from": "Placements <placements@ipec.ac.in>",
            "reply_to": "",
            "return_path": "<placements@ipec.ac.in>",
        },
        "authentication": {
            "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
        },
        "received_chain": [],
    }
    result = HeaderAnalyzer(parsed).analyze()
    assert result["header_risk_score"] == 0
    assert result["risk_level"] == "CLEAN"


def test_failed_auth_increases_risk():
    parsed = {
        "basic_fields": {
            "from": "Security <security@fake-bank.com>",
            "reply_to": "",
            "return_path": "",
        },
        "authentication": {
            "authentication_results": "spf=fail; dkim=fail; dmarc=fail",
        },
        "received_chain": [],
    }
    result = HeaderAnalyzer(parsed).analyze()
    assert result["header_risk_score"] > 0
    assert result["risk_level"] in ("MEDIUM", "HIGH")
    assert "SPF authentication failed" in result["reasons"]


def test_reply_to_mismatch_detected():
    parsed = {
        "basic_fields": {
            "from": "Security <security@bank.com>",
            "reply_to": "attacker@evil.com",
            "return_path": "",
        },
        "authentication": {
            "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
        },
        "received_chain": [],
    }
    result = HeaderAnalyzer(parsed).analyze()
    assert result["domain_analysis"]["reply_to_mismatch"] is True