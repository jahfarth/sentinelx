"""API tests: ingest (both body shapes), alerts CRUD/filters, stats, stream.

Runs against a tmp sqlite DB with REDIS_URL unset (no network, no redis).
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from sentinelx.api.db import AlertRow, EventRow, get_session, init_db
from sentinelx.api.main import app
from sentinelx.api.redis_client import reset_redis_client


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.delenv("REDIS_URL", raising=False)
    reset_redis_client()
    init_db()
    return TestClient(app)


def _seed_alert(**kwargs) -> str:
    alert_id = uuid.uuid4().hex
    defaults = {
        "id": alert_id,
        "timestamp": _now(),
        "rule_id": "brute-force",
        "rule_name": "SSH brute force",
        "title": "Possible brute force",
        "description": "many failed logins",
        "severity": "high",
        "score": 70,
        "tactic": "Credential Access",
        "technique_id": "T1110.001",
        "technique": "Brute Force: Password Guessing",
        "src_ip": "203.0.113.7",
        "dst_ip": None,
        "host": "web-01",
        "user": "root",
        "mitre": {"tactic": "Credential Access", "technique_id": "T1110.001",
                  "technique": "Brute Force: Password Guessing"},
        "evidence": {},
        "intel": {},
        "status": "new",
    }
    defaults.update(kwargs)
    with get_session() as session:
        session.add(AlertRow(**defaults))
    return alert_id


def _seed_event(timestamp=None, src_ip="1.2.3.4"):
    with get_session() as session:
        session.add(EventRow(
            timestamp=timestamp or _now(),
            host="web-01",
            source="syslog",
            event_type="system",
            src_ip=src_ip,
            dst_ip=None,
            user=None,
            data={},
        ))


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_ingest_lines_shape(client):
    lines = [
        "Oct 16 10:00:00 h sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
        "Oct 16 10:00:01 h sshd[1]: Accepted password for a from 1.2.3.5 port 22 ssh2",
        "not a log line at all",
    ]
    resp = client.post("/api/v1/ingest", json={"host": "h", "source": "auth", "lines": lines})
    assert resp.status_code == 200
    assert resp.json() == {"received": 3, "normalized": 2}
    overview = client.get("/api/v1/stats/overview").json()
    assert overview["total_events"] == 2


def test_ingest_events_shape(client):
    event = {
        "timestamp": "2026-10-16T10:00:00",
        "host": "h",
        "source": "syslog",
        "event_type": "system",
        "message": "hello",
    }
    resp = client.post("/api/v1/ingest", json={"events": [event, {"bogus": True}]})
    assert resp.status_code == 200
    assert resp.json() == {"received": 2, "normalized": 1}


def test_ingest_unknown_source_is_422(client):
    resp = client.post("/api/v1/ingest",
                       json={"host": "h", "source": "nope", "lines": ["x"]})
    assert resp.status_code == 422


def test_alerts_list_and_filters(client):
    _seed_alert(severity="high", status="new", rule_id="brute-force", src_ip="1.1.1.1")
    _seed_alert(severity="critical", status="acknowledged", rule_id="port-scan", src_ip="2.2.2.2")
    _seed_alert(severity="low", status="new", rule_id="brute-force", src_ip="1.1.1.1")

    body = client.get("/api/v1/alerts").json()
    assert body["total"] == 3
    assert len(body["alerts"]) == 3

    assert client.get("/api/v1/alerts", params={"severity": "critical"}).json()["total"] == 1
    assert client.get("/api/v1/alerts", params={"status": "new"}).json()["total"] == 2
    assert client.get("/api/v1/alerts", params={"rule_id": "port-scan"}).json()["total"] == 1
    assert client.get("/api/v1/alerts", params={"src_ip": "1.1.1.1"}).json()["total"] == 2

    page = client.get("/api/v1/alerts", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 3
    assert len(page["alerts"]) == 1


def test_get_alert_and_404(client):
    alert_id = _seed_alert()
    resp = client.get(f"/api/v1/alerts/{alert_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == alert_id
    assert body["severity"] == "high"
    assert body["mitre"]["technique_id"] == "T1110.001"

    assert client.get("/api/v1/alerts/does-not-exist").status_code == 404


def test_patch_alert_status(client):
    alert_id = _seed_alert(status="new")
    resp = client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "acknowledged"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "acknowledged"

    assert client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "snoozed"}).status_code == 422
    assert client.patch("/api/v1/alerts/nope", json={"status": "resolved"}).status_code == 404


def test_stats_overview(client):
    _seed_event()
    _seed_alert(severity="critical")
    _seed_alert(severity="high")
    _seed_alert(severity="low", timestamp=_now() - timedelta(hours=30))

    body = client.get("/api/v1/stats/overview").json()
    assert body["total_events"] == 1
    assert body["total_alerts_24h"] == 2
    assert body["critical_24h"] == 1
    assert body["alerts_by_severity"] == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    assert body["top_attackers"][0]["ip"] == "203.0.113.7"
    assert body["top_attackers"][0]["count"] == 2


def test_stats_timeline(client):
    _seed_event(timestamp=_now() - timedelta(hours=2))
    _seed_event(timestamp=_now() - timedelta(hours=30))  # outside the 24h window
    _seed_alert(severity="critical")

    body = client.get("/api/v1/stats/timeline", params={"hours": 24}).json()
    buckets = body["buckets"]
    assert len(buckets) == 24
    assert sum(b["count"] for b in buckets) == 1
    assert sum(b["critical"] for b in buckets) == 1
    assert all("ts" in b for b in buckets)


def test_attackers_geo(client):
    _seed_alert(src_ip="10.0.0.5")
    _seed_alert(src_ip="10.0.0.5")
    _seed_alert(src_ip="8.8.8.8")

    body = client.get("/api/v1/attackers", params={"limit": 20}).json()
    attackers = {a["ip"]: a for a in body["attackers"]}
    assert attackers["10.0.0.5"]["alerts"] == 2
    assert attackers["10.0.0.5"]["country"] == "Private"
    assert attackers["10.0.0.5"]["lat"] == 0.0
    assert attackers["8.8.8.8"]["country"] == "Unknown"


def test_stream_without_redis_closes_gracefully(client):
    resp = client.get("/api/v1/stream")
    assert resp.status_code == 200
    assert "redis unavailable" in resp.text
