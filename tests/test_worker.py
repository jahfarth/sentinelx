"""Worker tests: RedisState (in-memory fallback) and the event pipeline."""

import sys
import time
import types
from datetime import UTC, datetime

import pytest

from sentinelx.api.db import AlertRow, get_session, init_db
from sentinelx.common.models import Alert, Event
from sentinelx.worker.pipeline import PipelineDeps, process_event
from sentinelx.worker.state import RedisState


@pytest.fixture()
def worker_db(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/worker.db")
    init_db()


def _event(**kwargs) -> Event:
    base = {
        "timestamp": datetime.now(UTC).replace(tzinfo=None),
        "host": "h",
        "source": "auth",
        "event_type": "authentication",
    }
    base.update(kwargs)
    return Event(**base)


def _alert(**kwargs) -> Alert:
    base = {
        "timestamp": datetime.now(UTC).replace(tzinfo=None),
        "rule_id": "brute-force",
        "rule_name": "SSH brute force",
        "title": "t",
        "description": "d",
        "severity": "high",
        "score": 70,
        "mitre": {"tactic": "Credential Access", "technique_id": "T1110.001",
                  "technique": "Brute Force: Password Guessing"},
    }
    base.update(kwargs)
    return Alert(**base)


class StubEngine:
    """Minimal detection engine double."""

    def __init__(self, alerts):
        self.alerts = alerts
        self.seen = []

    def evaluate(self, event, ctx):
        self.seen.append(event)
        return self.alerts


def _deps(**kwargs) -> PipelineDeps:
    params = {"session_factory": get_session, "redis": None,
              "state": RedisState(None), "engine": None}
    params.update(kwargs)
    return PipelineDeps(**params)


# --------------------------------------------------------------------------- #
# RedisState
# --------------------------------------------------------------------------- #
def test_make_key_format():
    assert RedisState.make_key("r1", "src_ip", "1.2.3.4") == "sentinelx:state:r1:src_ip:1.2.3.4"


def test_count_increments_in_memory():
    state = RedisState(None)
    key = RedisState.make_key("r", "ip", "1.1.1.1")
    assert state.count(key, 60) == 1
    assert state.count(key, 60) == 2
    assert state.count(key, 60) == 3


def test_count_window_expiry_in_memory():
    state = RedisState(None)
    key = RedisState.make_key("r", "ip", "1.1.1.1")
    assert state.count(key, 0.05) == 1
    assert state.count(key, 0.05) == 2
    time.sleep(0.07)
    assert state.count(key, 0.05) == 1


def test_sadd_window_cardinality_and_expiry_in_memory():
    state = RedisState(None)
    key = RedisState.make_key("r", "ports", "1.1.1.1")
    assert state.sadd_window(key, "22", 60) == 1
    assert state.sadd_window(key, "22", 60) == 1  # duplicate member
    assert state.sadd_window(key, "80", 60) == 2
    time.sleep(0.07)
    assert state.sadd_window(key, "443", 0.05) == 1  # old members expired


def test_state_keys_are_independent():
    state = RedisState(None)
    assert state.count(RedisState.make_key("r", "ip", "1.1.1.1"), 60) == 1
    assert state.count(RedisState.make_key("r", "ip", "2.2.2.2"), 60) == 1


# --------------------------------------------------------------------------- #
# pipeline
# --------------------------------------------------------------------------- #
def test_pipeline_persists_engine_alert(worker_db):
    engine = StubEngine([_alert()])
    deps = _deps(engine=engine)
    event = _event()
    alerts = process_event(event, deps)

    assert len(alerts) == 1
    assert engine.seen == [event]
    with get_session() as session:
        rows = session.query(AlertRow).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.rule_id == "brute-force"
        assert row.severity == "high"  # score 70, no intel boost without src_ip
        assert row.score == 70
        assert row.status == "new"
        assert row.technique_id == "T1110.001"


def test_pipeline_no_engine_no_modules(worker_db):
    # sentinelx.detection / ml / intel / response are not installed: skip cleanly.
    deps = _deps(engine=None)
    assert process_event(_event(), deps) == []
    with get_session() as session:
        assert session.query(AlertRow).count() == 0


def _install_fake_ml(monkeypatch, score):
    ml_pkg = types.ModuleType("sentinelx.ml")
    scoring_mod = types.ModuleType("sentinelx.ml.scoring")
    scoring_mod.score_event = lambda event: score
    ml_pkg.scoring = scoring_mod
    monkeypatch.setitem(sys.modules, "sentinelx.ml", ml_pkg)
    monkeypatch.setitem(sys.modules, "sentinelx.ml.scoring", scoring_mod)


def test_pipeline_ml_anomaly_creates_alert(worker_db, monkeypatch):
    _install_fake_ml(monkeypatch, 0.95)
    deps = _deps(engine=StubEngine([]))
    alerts = process_event(_event(), deps)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "ml-anomaly"
    assert alert.severity == "medium"
    assert alert.mitre["technique_id"] == "T1078"
    assert alert.evidence["ml_score"] == 0.95
    with get_session() as session:
        assert session.query(AlertRow).count() == 1


def test_pipeline_ml_score_attached_to_rule_alert(worker_db, monkeypatch):
    _install_fake_ml(monkeypatch, 0.5)  # below threshold: no standalone alert
    deps = _deps(engine=StubEngine([_alert()]))
    alerts = process_event(_event(), deps)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "brute-force"
    assert alerts[0].evidence["ml_score"] == 0.5


def test_pipeline_intel_boosts_score(worker_db, monkeypatch):
    intel_pkg = types.ModuleType("sentinelx.intel")
    enrich_mod = types.ModuleType("sentinelx.intel.enrich")
    enrich_mod.enrich_ip = lambda ip: {"boost": 20, "reputation": "bad"}
    intel_pkg.enrich = enrich_mod
    monkeypatch.setitem(sys.modules, "sentinelx.intel", intel_pkg)
    monkeypatch.setitem(sys.modules, "sentinelx.intel.enrich", enrich_mod)
    monkeypatch.delenv("SENTINELX_INTEL_MOCK", raising=False)

    deps = _deps(engine=StubEngine([_alert(score=70, severity="high")]))
    alerts = process_event(_event(src_ip="8.8.8.8"), deps)

    assert len(alerts) == 1
    assert alerts[0].score == 90
    assert alerts[0].severity == "critical"
    assert alerts[0].intel["reputation"] == "bad"
    with get_session() as session:
        row = session.query(AlertRow).one()
        assert row.score == 90
        assert row.severity == "critical"


def test_pipeline_publishes_to_redis_when_available(worker_db):
    published = []

    class FakeRedis:
        def publish(self, channel, payload):
            published.append((channel, payload))

    deps = _deps(engine=StubEngine([_alert()]), redis=FakeRedis())
    process_event(_event(), deps)
    assert len(published) == 1
    assert published[0][0] == "sentinelx:alerts"
    assert "brute-force" in published[0][1]
