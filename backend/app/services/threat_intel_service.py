"""
Threat Intelligence Service.

Provides IP reputation and domain characteristic checks through a
provider-abstraction layer. If no API key is configured, the service
falls back to LOCAL, CLEARLY-LABELED offline analysis rather than
faking external results -- this is a hard project requirement.

IP reputation: AbuseIPDB (free tier, requires an API key)
Domain check: local heuristics only (no live WHOIS in this phase)
"""

import requests
from app.core.config import settings


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "xyz", "top", "click", "loan", "work"}


class ThreatIntelService:
    """Provider-abstracted threat intelligence lookups."""

    def __init__(self):
        self.abuseipdb_key = settings.ABUSEIPDB_API_KEY

    # ---------- IP reputation ----------

    def check_ip(self, ip: str) -> dict:
        """
        Checks an IP's reputation via AbuseIPDB if a key is configured.
        Falls back to a clearly-labeled offline response otherwise.
        """
        if not self.abuseipdb_key:
            return {
                "ip": ip,
                "source": "OFFLINE",
                "note": (
                    "No AbuseIPDB API key configured. This is a local "
                    "placeholder, not real threat intelligence. Add "
                    "ABUSEIPDB_API_KEY in .env to enable live lookups."
                ),
                "abuse_confidence_score": None,
                "total_reports": None,
                "country": None,
                "isp": None,
            }

        try:
            response = requests.get(
                ABUSEIPDB_URL,
                headers={
                    "Key": self.abuseipdb_key,
                    "Accept": "application/json",
                },
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5,
            )
            response.raise_for_status()
            data = response.json().get("data", {})

            return {
                "ip": ip,
                "source": "AbuseIPDB (live)",
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "is_whitelisted": data.get("isWhitelisted"),
            }
        except requests.RequestException as e:
            return {
                "ip": ip,
                "source": "OFFLINE (API error)",
                "note": f"AbuseIPDB lookup failed: {str(e)}",
                "abuse_confidence_score": None,
                "total_reports": None,
                "country": None,
                "isp": None,
            }

    # ---------- Domain characteristics (local heuristics only) ----------

    def check_domain(self, domain: str) -> dict:
        """
        Local heuristic-only domain check. This is NOT live WHOIS or
        DNS intelligence -- it only looks at surface characteristics
        of the domain string itself, and is labeled as such.
        """
        if not domain:
            return {
                "domain": domain,
                "source": "OFFLINE (local heuristics)",
                "reasons": [],
                "risk_score": 0,
            }

        reasons = []
        score = 0

        tld = domain.split(".")[-1].lower()
        if tld in SUSPICIOUS_TLDS:
            score += 30
            reasons.append(f"Domain uses a TLD commonly associated with abuse (.{tld})")

        hyphen_count = domain.count("-")
        if hyphen_count >= 2:
            score += 15
            reasons.append(f"Domain contains {hyphen_count} hyphens, unusual for legitimate brands")

        digit_count = sum(c.isdigit() for c in domain)
        if digit_count >= 3:
            score += 15
            reasons.append("Domain contains an unusual number of digits")

        if len(domain) > 30:
            score += 10
            reasons.append("Domain name is unusually long")

        final_score = min(score, 100)

        return {
            "domain": domain,
            "source": "OFFLINE (local heuristics only -- not live WHOIS/DNS)",
            "reasons": reasons,
            "risk_score": final_score,
        }


def get_threat_intel_service() -> ThreatIntelService:
    """Factory function -- keeps instantiation in one place for future dependency injection."""
    return ThreatIntelService()