"""
GeoIP Service.

Provider-abstracted IP geolocation. Uses ip-api.com's free tier
(no API key required, rate-limited to 45 requests/minute) as the
default provider. Swappable later for ipinfo or MaxMind without
changing how callers use this service.

IMPORTANT: IP geolocation is approximate. It typically identifies the
ISP's registered location (often a city, sometimes just a country/region),
NOT the physical street address of the sender. This is stated clearly
in every response so it is never mistaken for precise location data.
"""

import requests

IP_API_URL = "http://ip-api.com/json/{ip}"


class GeoIPService:
    """Looks up approximate geolocation for a public IP address."""

    def locate(self, ip: str) -> dict:
        try:
            response = requests.get(
                IP_API_URL.format(ip=ip),
                params={
                    "fields": "status,message,country,regionName,city,lat,lon,isp,org,as,timezone,query"
                },
                timeout=5,
            )
            response.raise_for_status()
            data = response.json()

            if data.get("status") != "success":
                return {
                    "ip": ip,
                    "source": "OFFLINE (lookup failed)",
                    "note": data.get("message", "Geolocation lookup failed."),
                }

            return {
                "ip": ip,
                "source": "ip-api.com (live)",
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as"),
                "timezone": data.get("timezone"),
                "accuracy_note": (
                    "Approximate location based on ISP registration data. "
                    "This identifies the general area the IP is registered "
                    "to, not the sender's exact physical address."
                ),
            }
        except requests.RequestException as e:
            return {
                "ip": ip,
                "source": "OFFLINE (API error)",
                "note": f"GeoIP lookup failed: {str(e)}",
            }


def get_geoip_service() -> GeoIPService:
    """Factory function -- keeps instantiation in one place for future dependency injection."""
    return GeoIPService()