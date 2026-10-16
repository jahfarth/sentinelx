"""IP enrichment: combine AbuseIPDB, VirusTotal and OTX into one verdict.

``enrich_ip`` is the pipeline entry point. The returned dict always carries
an integer ``boost`` (added to the alert score by the worker, which caps it
via ``compute_score``) plus ``malicious`` and per-source details.

Lookup order per source: Redis cache (24h) -> provider API, each guarded so
a failing or unconfigured provider is skipped without breaking the others.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Any

from sentinelx.intel import abuseipdb, otx, virustotal
from sentinelx.intel.base import CachedIntelClient

log = logging.getLogger(__name__)

_INTEL_TTL_S = 24 * 3600
_MALICIOUS_ABUSE_SCORE = 75
_MALICIOUS_VT_POSITIVES = 5
_MALICIOUS_OTX_PULSES = 3
_SUSPICIOUS_ABUSE_SCORE = 25
_BOOST_MALICIOUS = 25
_BOOST_SUSPICIOUS = 10


def _get_redis() -> Any | None:
    """Best-effort Redis client from ``REDIS_URL``; ``None`` when unavailable."""
    url = os.environ.get("REDIS_URL")
    if not url:
        return None
    try:
        import redis

        client = redis.Redis.from_url(url, socket_connect_timeout=3, decode_responses=True)
        client.ping()
        return client
    except Exception as exc:
        log.warning("intel redis unavailable: %s", exc)
        return None


def _mock_fixture(ip: str) -> dict:
    """Deterministic offline fixture returned when ``SENTINELX_INTEL_MOCK=1``."""
    return {
        "mock": True,
        "ip": ip,
        "private": False,
        "malicious": False,
        "boost": 0,
        "abuse_score": 0,
        "vt_positives": 0,
        "otx_pulses": 0,
        "sources": ["mock"],
    }


def enrich_ip(ip: str) -> dict:
    """Enrich a public *ip* with threat-intel and return the verdict dict.

    Private/non-global IPs short-circuit to
    ``{"private": True, "boost": 0, ...}`` with no network calls. In mock
    mode (``SENTINELX_INTEL_MOCK=1``) a deterministic fixture is returned.

    Verdict: ``malicious`` when ``abuse_score >= 75``, ``vt_positives >= 5``
    or ``otx_pulses >= 3``; ``boost`` is 25 when malicious, 10 when merely
    suspicious (``abuse_score >= 25`` or ``vt_positives >= 1``), else 0.
    """
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return {"private": False, "malicious": False, "boost": 0, "ip": ip, "sources": []}
    if not parsed.is_global:
        return {
            "private": True,
            "malicious": False,
            "boost": 0,
            "ip": ip,
            "sources": [],
        }
    if os.environ.get("SENTINELX_INTEL_MOCK", "") == "1":
        return _mock_fixture(ip)

    client = CachedIntelClient(redis_client=_get_redis())
    result: dict[str, Any] = {
        "private": False,
        "malicious": False,
        "boost": 0,
        "ip": ip,
        "sources": [],
    }

    providers = [
        ("abuseipdb", "ABUSEIPDB_API_KEY", abuseipdb.check),
        ("virustotal", "VIRUSTOTAL_API_KEY", virustotal.check),
        ("otx", "OTX_API_KEY", otx.check),
    ]
    for name, env_key, check_fn in providers:
        api_key = os.environ.get(env_key, "")
        if not api_key:
            log.debug("skipping %s: %s not set", name, env_key)
            continue
        try:
            detail = client._cached_get(
                f"sentinelx:intel:{name}:{ip}",
                _INTEL_TTL_S,
                lambda _fn=check_fn, _key=api_key: _fn(ip, _key),
            )
        except Exception:
            log.warning("%s lookup failed for %s", name, ip, exc_info=True)
            continue
        result[f"{name}_detail"] = detail
        result["sources"].append(name)

    abuse_score = int((result.get("abuseipdb_detail") or {}).get("abuse_score", 0))
    vt_positives = int((result.get("virustotal_detail") or {}).get("vt_malicious", 0))
    otx_pulses = int((result.get("otx_detail") or {}).get("otx_pulses", 0))
    result["abuse_score"] = abuse_score
    result["vt_positives"] = vt_positives
    result["otx_pulses"] = otx_pulses

    malicious = (
        abuse_score >= _MALICIOUS_ABUSE_SCORE
        or vt_positives >= _MALICIOUS_VT_POSITIVES
        or otx_pulses >= _MALICIOUS_OTX_PULSES
    )
    result["malicious"] = malicious
    if malicious:
        result["boost"] = _BOOST_MALICIOUS
    elif abuse_score >= _SUSPICIOUS_ABUSE_SCORE or vt_positives >= 1:
        result["boost"] = _BOOST_SUSPICIOUS
    return result
