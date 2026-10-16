"""AbuseIPDB client: GET /api/v2/check for an IP's abuse confidence."""

from __future__ import annotations

import httpx

from sentinelx.intel.base import IntelError

_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


def check(ip: str, api_key: str, *, transport: httpx.BaseTransport | None = None) -> dict:
    """Return ``{"abuse_score", "total_reports", "country"}`` for *ip*.

    Raises :class:`IntelError` on non-200 responses or malformed payloads.
    """
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    with httpx.Client(timeout=10, transport=transport) as client:
        response = client.get(_CHECK_URL, headers=headers, params=params)
    if response.status_code != 200:
        raise IntelError(f"AbuseIPDB returned HTTP {response.status_code} for {ip}")
    try:
        data = response.json()["data"]
        return {
            "abuse_score": int(data.get("abuseConfidenceScore", 0)),
            "total_reports": int(data.get("totalReports", 0)),
            "country": str(data.get("countryCode", "")),
        }
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise IntelError(f"AbuseIPDB returned an unparseable payload for {ip}") from exc
