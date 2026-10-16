"""VirusTotal client: GET /api/v3/ip_addresses/{ip} for analysis stats."""

from __future__ import annotations

import httpx

from sentinelx.intel.base import IntelError

_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"


def check(ip: str, api_key: str, *, transport: httpx.BaseTransport | None = None) -> dict:
    """Return ``{"vt_malicious", "vt_reputation"}`` for *ip*.

    Raises :class:`IntelError` on non-200 responses or malformed payloads.
    """
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    with httpx.Client(timeout=10, transport=transport) as client:
        response = client.get(f"{_BASE_URL}/{ip}", headers=headers)
    if response.status_code != 200:
        raise IntelError(f"VirusTotal returned HTTP {response.status_code} for {ip}")
    try:
        attrs = response.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return {
            "vt_malicious": int(stats.get("malicious", 0)),
            "vt_reputation": int(attrs.get("reputation", 0)),
        }
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise IntelError(f"VirusTotal returned an unparseable payload for {ip}") from exc
