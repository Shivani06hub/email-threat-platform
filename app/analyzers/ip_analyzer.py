"""
IP Analyzer.

Classifies extracted IP addresses as public, private, loopback, or
reserved using Python's built-in ipaddress module. Private/internal
IPs are normal in a Received chain (e.g. internal mail relays) and
should NOT be flagged as suspicious on their own.

Live reputation/geolocation lookups (AbuseIPDB, ip-api, etc.) are
added in a later phase behind this same interface.
"""

import ipaddress


class IPAnalyzer:
    """Classifies a single IP address."""

    def __init__(self, ip: str):
        self.ip = ip

    def analyze(self) -> dict:
        try:
            ip_obj = ipaddress.ip_address(self.ip)
        except ValueError:
            return {
                "ip": self.ip,
                "valid": False,
                "reason": "Not a valid IP address",
            }

        if ip_obj.is_loopback:
            ip_type = "loopback"
        elif ip_obj.is_private:
            ip_type = "private"
        elif ip_obj.is_reserved:
            ip_type = "reserved"
        elif ip_obj.is_multicast:
            ip_type = "multicast"
        else:
            ip_type = "public"

        return {
            "ip": self.ip,
            "valid": True,
            "ip_type": ip_type,
            "is_public": ip_type == "public",
            "note": (
                "Public IP -- eligible for geolocation and threat intelligence lookups (added in a later phase)."
                if ip_type == "public"
                else "Internal/private IP -- not something we can or should look up externally."
            ),
        }


def analyze_ips(ips: list) -> list:
    """Convenience function: analyzes a list of IPs and returns a list of results."""
    return [IPAnalyzer(ip).analyze() for ip in ips]