"""
URL Analyzer.

Analyzes each URL found in an email body for phishing-style red flags:
missing HTTPS, known link-shortener usage, IP-based URLs, the classic
'@' redirect trick, punycode (fake lookalike domains), and generally
suspicious keywords combined with a non-official-looking domain.

This is local, rule-based analysis -- no external API calls. A live
reputation check (VirusTotal/URLScan) can be added later behind the
same interface without changing how this is used.
"""

import re
from urllib.parse import urlparse


KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
}

SUSPICIOUS_KEYWORDS = [
    "verify", "secure", "account", "login", "update",
    "confirm", "suspend", "unlock", "billing",
]


class URLAnalyzer:
    """Analyzes a single URL and produces a risk score with reasons."""

    def __init__(self, url: str):
        self.url = url
        self.parsed = urlparse(url)
        self.reasons = []
        self.score = 0

    def _is_ip_based(self) -> bool:
        host = self.parsed.hostname or ""
        return bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', host))

    def _is_shortened(self) -> bool:
        host = (self.parsed.hostname or "").lower()
        return host in KNOWN_SHORTENERS

    def _has_at_symbol_trick(self) -> bool:
        # e.g. http://real-looking-site.com@attacker.com/ -- browsers
        # actually navigate to attacker.com, the part before '@' is decoration
        return "@" in self.url

    def _is_punycode(self) -> bool:
        host = self.parsed.hostname or ""
        return host.startswith("xn--") or ".xn--" in host

    def _has_suspicious_keyword(self) -> bool:
        full_url_lower = self.url.lower()
        return any(keyword in full_url_lower for keyword in SUSPICIOUS_KEYWORDS)

    def analyze(self) -> dict:
        is_https = self.parsed.scheme == "https"
        is_ip_based = self._is_ip_based()
        is_shortened = self._is_shortened()
        has_at_trick = self._has_at_symbol_trick()
        is_punycode = self._is_punycode()
        has_suspicious_keyword = self._has_suspicious_keyword()
        url_length = len(self.url)

        if not is_https:
            self.score += 20
            self.reasons.append("URL does not use HTTPS")

        if is_ip_based:
            self.score += 30
            self.reasons.append("URL uses a raw IP address instead of a domain name")

        if is_shortened:
            self.score += 15
            self.reasons.append("URL uses a known link-shortening service (destination is hidden)")

        if has_at_trick:
            self.score += 30
            self.reasons.append("URL contains '@' which can be used to disguise the real destination")

        if is_punycode:
            self.score += 25
            self.reasons.append("URL domain uses punycode encoding (possible lookalike domain)")

        if has_suspicious_keyword and not is_https:
            self.score += 10
            self.reasons.append("URL combines suspicious keywords (e.g. 'verify', 'secure') with non-HTTPS")

        if url_length > 100:
            self.score += 10
            self.reasons.append("URL is unusually long, which can be used to hide the real destination")

        final_score = min(self.score, 100)

        if final_score >= 70:
            risk_level = "HIGH"
        elif final_score >= 40:
            risk_level = "MEDIUM"
        elif final_score > 0:
            risk_level = "LOW"
        else:
            risk_level = "CLEAN"

        return {
            "url": self.url,
            "domain": self.parsed.hostname,
            "is_https": is_https,
            "is_ip_based": is_ip_based,
            "is_shortened": is_shortened,
            "risk_score": final_score,
            "risk_level": risk_level,
            "reasons": self.reasons,
        }


def analyze_urls(urls: list) -> list:
    """Convenience function: analyzes a list of URLs and returns a list of results."""
    return [URLAnalyzer(url).analyze() for url in urls]