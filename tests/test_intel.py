"""Tests for threat-intel enrichment: providers, caching, mock, boost logic."""

import json

import httpx
import pytest

from sentinelx.intel import abuseipdb, enrich, otx, virustotal
from sentinelx.intel.base import CachedIntelClient, IntelError


def _transport(handler):
    return httpx.MockTransport(handler)


def test_abuseipdb_parses_response():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["key"] = request.headers.get("Key")
        return httpx.Response(
            200,
            json={"data": {"abuseConfidenceScore": 90, "totalReports": 42, "countryCode": "RU"}},
        )

    result = abuseipdb.check("1.2.3.4", "secret", transport=_transport(handler))
    assert result == {"abuse_score": 90, "total_reports": 42, "country": "RU"}
    assert "api.abuseipdb.com/api/v2/check" in seen["url"]
    assert "ipAddress=1.2.3.4" in seen["url"]
    assert seen["key"] == "secret"


def test_abuseipdb_non_200_raises():
    transport = _transport(lambda request: httpx.Response(429, json={"error": "slow down"}))
    with pytest.raises(IntelError):
        abuseipdb.check("1.2.3.4", "secret", transport=transport)


def test_abuseipdb_bad_payload_raises():
    transport = _transport(lambda request: httpx.Response(200, json={"nope": True}))
    with pytest.raises(IntelError):
        abuseipdb.check("1.2.3.4", "secret", transport=transport)


def test_virustotal_parses_response():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("x-apikey") == "vt-key"
        assert request.url.path == "/api/v3/ip_addresses/1.2.3.4"
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 12, "harmless": 70},
                        "reputation": -50,
                    }
                }
            },
        )

    result = virustotal.check("1.2.3.4", "vt-key", transport=_transport(handler))
    assert result == {"vt_malicious": 12, "vt_reputation": -50}


def test_virustotal_non_200_raises():
    transport = _transport(lambda request: httpx.Response(404, json={"error": "not found"}))
    with pytest.raises(IntelError):
        virustotal.check("1.2.3.4", "vt-key", transport=transport)


def test_otx_parses_response():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("X-OTX-API-KEY") == "otx-key"
        assert request.url.path == "/api/v1/indicators/IPv4/1.2.3.4/general"
        return httpx.Response(
            200, json={"pulse_info": {"count": 5, "pulses": []}, "reputation": 0}
        )

    result = otx.check("1.2.3.4", "otx-key", transport=_transport(handler))
    assert result == {"otx_pulses": 5, "otx_reputation": 0}


def test_otx_non_200_raises():
    transport = _transport(lambda request: httpx.Response(500, text="boom"))
    with pytest.raises(IntelError):
        otx.check("1.2.3.4", "otx-key", transport=transport)


class _FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def setex(self, key, ttl, value):
        self.store[key] = value


def test_cached_client_uses_redis_then_fetch():
    redis = _FakeRedis()
    client = CachedIntelClient(redis_client=redis)
    calls = []

    def fetch():
        calls.append(1)
        return {"a": 1}

    assert client._cached_get("k", 60, fetch) == {"a": 1}
    assert client._cached_get("k", 60, fetch) == {"a": 1}
    assert len(calls) == 1  # second call served from cache
    assert json.loads(redis.store["k"]) == {"a": 1}


def test_cached_client_without_redis_calls_fetch_directly():
    client = CachedIntelClient(redis_client=None)
    assert client._cached_get("k", 60, lambda: {"b": 2}) == {"b": 2}


def test_cached_client_redis_failure_falls_back():
    class _Broken:
        def get(self, key):
            raise ConnectionError("down")

        def setex(self, *args):
            raise ConnectionError("down")

    client = CachedIntelClient(redis_client=_Broken())
    assert client._cached_get("k", 60, lambda: {"c": 3}) == {"c": 3}


def _no_keys(monkeypatch):
    for key in ("ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "OTX_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("SENTINELX_INTEL_MOCK", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)


def test_private_ip_short_circuits(monkeypatch):
    _no_keys(monkeypatch)
    for ip in ("10.0.0.1", "192.168.1.5", "fd00::1", "127.0.0.1"):
        result = enrich.enrich_ip(ip)
        assert result["private"] is True
        assert result["boost"] == 0
        assert result["malicious"] is False


def test_mock_mode_fixture(monkeypatch):
    _no_keys(monkeypatch)
    monkeypatch.setenv("SENTINELX_INTEL_MOCK", "1")
    result = enrich.enrich_ip("8.8.8.8")
    assert result["mock"] is True
    assert result["boost"] == 0
    assert isinstance(result["boost"], int)
    assert result["sources"] == ["mock"]


def test_malicious_ip_boost_25(monkeypatch):
    _no_keys(monkeypatch)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    monkeypatch.setattr(
        "sentinelx.intel.enrich.abuseipdb.check",
        lambda ip, key, **kw: {"abuse_score": 90, "total_reports": 12, "country": "RU"},
    )
    result = enrich.enrich_ip("45.33.32.156")
    assert result["malicious"] is True
    assert result["boost"] == 25
    assert result["abuse_score"] == 90
    assert result["sources"] == ["abuseipdb"]


def test_suspicious_ip_boost_10(monkeypatch):
    _no_keys(monkeypatch)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
    monkeypatch.setattr(
        "sentinelx.intel.enrich.virustotal.check",
        lambda ip, key, **kw: {"vt_malicious": 2, "vt_reputation": -5},
    )
    result = enrich.enrich_ip("45.33.32.157")
    assert result["malicious"] is False
    assert result["boost"] == 10
    assert result["vt_positives"] == 2


def test_clean_ip_boost_0(monkeypatch):
    _no_keys(monkeypatch)
    result = enrich.enrich_ip("45.33.32.158")
    assert result == {
        "private": False,
        "malicious": False,
        "boost": 0,
        "ip": "45.33.32.158",
        "sources": [],
        "abuse_score": 0,
        "vt_positives": 0,
        "otx_pulses": 0,
    }


def test_provider_failure_does_not_break_enrich(monkeypatch):
    _no_keys(monkeypatch)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")

    def boom(ip, key, **kw):
        raise IntelError("provider down")

    monkeypatch.setattr("sentinelx.intel.enrich.abuseipdb.check", boom)
    result = enrich.enrich_ip("45.33.32.159")
    assert result["boost"] == 0
    assert result["sources"] == []
