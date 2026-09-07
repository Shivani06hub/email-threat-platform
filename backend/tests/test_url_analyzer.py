"""
Tests for URLAnalyzer -- confirms phishing-style URL red flags are detected.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analyzers.url_analyzer import URLAnalyzer, analyze_urls


def test_https_url_has_lower_risk():
    result = URLAnalyzer("https://www.google.com").analyze()
    assert result["is_https"] is True
    assert result["risk_score"] < 30


def test_non_https_with_keywords_flagged():
    result = URLAnalyzer("http://verify-secure-login.com/account").analyze()
    assert result["is_https"] is False
    assert result["risk_score"] > 0


def test_ip_based_url_flagged():
    result = URLAnalyzer("http://192.168.1.1/login").analyze()
    assert result["is_ip_based"] is True
    assert result["risk_score"] >= 30


def test_analyze_urls_handles_empty_list():
    assert analyze_urls([]) == []


def test_analyze_urls_handles_multiple():
    urls = ["https://example.com", "http://bit.ly/abc123"]
    results = analyze_urls(urls)
    assert len(results) == 2
    assert results[1]["is_shortened"] is True