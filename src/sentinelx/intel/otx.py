"""AlienVault OTX client: GET /api/v1/indicators/IPv4/{ip}/general."""

from __future__ import annotations

import httpx

from sentinelx.intel.base import IntelError

_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4"


def check(ip: str, api_key: str, *, transport: httpx.BaseTransport | None = None) -> dict:
    """Return ``{"otx_pulses", "otx_reputation"}`` for *ip*.

    Raises :class:`IntelError` on non-200 responses or malformed payloads.
    """
    headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}
    with httpx.Client(timeout=10, transport=transport) as client:
        response = client.get(f"{_BASE_URL}/{ip}/general", headers=headers)
    if response.status_code != 200:
        raise IntelError(f"OTX returned HTTP {response.status_code} for {ip}")
    try:
        data = response.json()
        pulse_info = data.get("pulse_info") or {}
        return {
            "otx_pulses": int(pulse_info.get("count", 0)),
            "otx_reputation": int(data.get("reputation", 0)),
        }
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise IntelError(f"OTX returned an unparseable payload for {ip}") from exc
