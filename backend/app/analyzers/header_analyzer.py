"""
Header Analyzer.

Takes the structured data produced by EmailParser (Phase 3) and
interprets it: SPF/DKIM/DMARC pass/fail, sender/reply-to/return-path
domain mismatches, and a hop-by-hop route timeline from the
Received chain.

Produces a Header Risk Score (0-100) with human-readable reasons.
This module does NOT decide the final verdict on its own -- that
combination happens later in the Correlation Engine.
"""

import re


EMAIL_ADDRESS_PATTERN = re.compile(r'[\w\.\-\+]+@([\w\.\-]+)')
IP_PATTERN = re.compile(r'\(?((?:[0-9]{1,3}\.){3}[0-9]{1,3})\)?')
HOSTNAME_PATTERN = re.compile(r'from\s+([\w\.\-]+)')
TIMESTAMP_PATTERN = re.compile(r';\s*(.+)$')


class HeaderAnalyzer:
    """Analyzes parsed email header data and produces a risk assessment."""

    def __init__(self, parsed_email: dict):
        self.basic_fields = parsed_email.get("basic_fields", {})
        self.authentication = parsed_email.get("authentication", {})
        self.received_chain = parsed_email.get("received_chain", [])

        self.reasons = []
        self.score = 0

    # ---------- Domain extraction helpers ----------

    def _extract_domain(self, header_value: str) -> str:
        """Pulls the domain out of a header like '"Name" <user@domain.com>'."""
        if not header_value:
            return ""
        match = EMAIL_ADDRESS_PATTERN.search(header_value)
        return match.group(1).lower() if match else ""

    # ---------- SPF / DKIM / DMARC ----------

    def analyze_authentication(self) -> dict:
        """
        Extracts spf=/dkim=/dmarc= verdicts from the raw
        Authentication-Results header string.
        """
        auth_string = self.authentication.get("authentication_results", "") or ""
        auth_string_lower = auth_string.lower()

        def find_verdict(mechanism: str) -> str:
            match = re.search(rf'{mechanism}=(\w+)', auth_string_lower)
            return match.group(1) if match else "not_found"

        spf = find_verdict("spf")
        dkim = find_verdict("dkim")
        dmarc = find_verdict("dmarc")

        if spf == "fail":
            self.score += 25
            self.reasons.append("SPF authentication failed")
        elif spf == "not_found":
            self.reasons.append("No SPF result found in headers")

        if dkim == "fail":
            self.score += 20
            self.reasons.append("DKIM authentication failed")
        elif dkim == "not_found":
            self.reasons.append("No DKIM result found in headers")

        if dmarc == "fail":
            self.score += 20
            self.reasons.append("DMARC authentication failed")
        elif dmarc == "not_found":
            self.reasons.append("No DMARC result found in headers")

        return {"spf": spf, "dkim": dkim, "dmarc": dmarc}

    # ---------- Domain mismatch checks ----------

    def analyze_domain_mismatch(self) -> dict:
        sender_domain = self._extract_domain(self.basic_fields.get("from", ""))
        reply_to_domain = self._extract_domain(self.basic_fields.get("reply_to", ""))
        return_path_domain = self._extract_domain(self.basic_fields.get("return_path", ""))

        reply_to_mismatch = bool(reply_to_domain and reply_to_domain != sender_domain)
        return_path_mismatch = bool(return_path_domain and return_path_domain != sender_domain)

        if reply_to_mismatch:
            self.score += 20
            self.reasons.append(
                f"Reply-To domain ({reply_to_domain}) does not match sender domain ({sender_domain})"
            )

        if return_path_mismatch:
            self.score += 15
            self.reasons.append(
                f"Return-Path domain ({return_path_domain}) does not match sender domain ({sender_domain})"
            )

        return {
            "sender_domain": sender_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
            "reply_to_mismatch": reply_to_mismatch,
            "return_path_mismatch": return_path_mismatch,
        }

    # ---------- Route timeline ----------

    def build_route_timeline(self) -> list:
        """
        Converts raw 'Received' header strings into a structured,
        hop-by-hop timeline. Received headers are listed most-recent-first
        by convention, so we reverse them to show sender -> recipient order.
        """
        hops = []
        for header in reversed(self.received_chain):
            ip_match = IP_PATTERN.search(header)
            hostname_match = HOSTNAME_PATTERN.search(header)
            timestamp_match = TIMESTAMP_PATTERN.search(header)

            hops.append({
                "hostname": hostname_match.group(1) if hostname_match else None,
                "ip": ip_match.group(1) if ip_match else None,
                "timestamp": timestamp_match.group(1).strip() if timestamp_match else None,
                "raw": header,
            })
        return hops

    # ---------- Combined result ----------

    def analyze(self) -> dict:
        auth_result = self.analyze_authentication()
        domain_result = self.analyze_domain_mismatch()
        timeline = self.build_route_timeline()

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
            "header_risk_score": final_score,
            "risk_level": risk_level,
            "reasons": self.reasons,
            "authentication": auth_result,
            "domain_analysis": domain_result,
            "route_timeline": timeline,
        }