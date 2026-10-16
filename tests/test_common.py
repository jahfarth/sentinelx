"""Tests for shared contracts: models, severity helpers, MITRE table."""

import pytest
from pydantic import ValidationError

from sentinelx.common import mitre as mitre_mod
from sentinelx.common.models import Alert, Event
from sentinelx.common.severity import compute_score, score_to_level


def _event_kwargs(**overrides):
    base = {
        "timestamp": "2026-10-16T10:00:00",
        "host": "web-01",
        "source": "syslog",
        "event_type": "system",
    }
    base.update(overrides)
    return base


def test_event_valid():
    event = Event(**_event_kwargs(src_ip="10.0.0.1", message="hi"))
    assert event.host == "web-01"
    assert event.src_ip == "10.0.0.1"
    assert event.raw == {}
    assert event.message == "hi"


def test_event_defaults_are_optional():
    event = Event(**_event_kwargs())
    assert event.src_ip is None
    assert event.user is None
    assert event.http_status is None


def test_event_rejects_bad_source():
    with pytest.raises(ValidationError):
        Event(**_event_kwargs(source="carrier-pigeon"))


def test_event_rejects_bad_event_type():
    with pytest.raises(ValidationError):
        Event(**_event_kwargs(event_type="nope"))


def test_alert_defaults():
    alert = Alert(
        timestamp="2026-10-16T10:00:00",
        rule_id="r1",
        rule_name="R1",
        title="t",
        description="d",
        severity="high",
        score=70,
    )
    assert len(alert.id) == 32
    assert all(c in "0123456789abcdef" for c in alert.id)
    assert alert.status == "new"
    assert alert.mitre == {}
    assert alert.evidence == {}


def test_alert_unique_ids():
    a1 = Alert(
        timestamp="2026-10-16T10:00:00", rule_id="r", rule_name="r",
        title="t", description="d", severity="low", score=1,
    )
    a2 = Alert(
        timestamp="2026-10-16T10:00:00", rule_id="r", rule_name="r",
        title="t", description="d", severity="low", score=1,
    )
    assert a1.id != a2.id


@pytest.mark.parametrize("score", [-1, 101])
def test_alert_score_out_of_range(score):
    with pytest.raises(ValidationError):
        Alert(
            timestamp="2026-10-16T10:00:00", rule_id="r", rule_name="r",
            title="t", description="d", severity="low", score=score,
        )


def test_alert_rejects_bad_status():
    with pytest.raises(ValidationError):
        Alert(
            timestamp="2026-10-16T10:00:00", rule_id="r", rule_name="r",
            title="t", description="d", severity="low", score=1, status="snoozed",
        )


@pytest.mark.parametrize(
    "score,expected",
    [(100, "critical"), (85, "critical"), (84, "high"), (65, "high"),
     (64, "medium"), (40, "medium"), (39, "low"), (0, "low")],
)
def test_score_to_level_boundaries(score, expected):
    assert score_to_level(score) == expected


def test_compute_score_adds_boost():
    assert compute_score(50, 10) == 60


def test_compute_score_caps_at_100():
    assert compute_score(90, 20) == 100


def test_compute_score_floors_at_0():
    assert compute_score(10, -25) == 0


def test_mitre_table_exact_entries():
    expected = {
        "T1110.001": ("Credential Access", "Brute Force: Password Guessing"),
        "T1046": ("Discovery", "Network Service Discovery"),
        "T1190": ("Initial Access", "Exploit Public-Facing Application"),
        "T1068": ("Privilege Escalation", "Exploitation for Privilege Escalation"),
        "T1078": ("Persistence", "Valid Accounts"),
        "T1059": ("Execution", "Command and Scripting Interpreter"),
        "T1133": ("Initial Access", "External Remote Services"),
    }
    assert set(mitre_mod.TECHNIQUES) == set(expected)
    for tid, (tactic, technique) in expected.items():
        entry = mitre_mod.TECHNIQUES[tid]
        assert entry["tactic"] == tactic
        assert entry["technique"] == technique


def test_mitre_lookup_unknown():
    assert mitre_mod.lookup("T9999") == {"tactic": "Unknown", "technique": "Unknown"}
