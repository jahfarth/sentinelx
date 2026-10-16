"""Shared test doubles for the detection test-suite.

``FakeCtx`` implements the rule-context interface (``count`` / ``sadd_window``)
with real sliding-window expiry. Time is driven explicitly through ``now``
(epoch seconds); the ``run_sequence`` helper advances it from each event's
timestamp, mirroring how a worker would feed events in arrival order.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from sentinelx.common import Event

BASE_TIME = datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC)


class FakeCtx:
    """In-memory stand-in for the worker's windowed state backend."""

    def __init__(self) -> None:
        self.now: float = time.time()
        self._counts: dict[str, list[float]] = {}
        self._sets: dict[str, dict[str, float]] = {}

    def set_time(self, ts: float) -> None:
        """Advance the fake clock (epoch seconds)."""
        self.now = ts

    def count(self, key: str, window_s: int) -> int:
        """Record one hit for *key* and return hits inside the window."""
        stamps = self._counts.setdefault(key, [])
        cutoff = self.now - window_s
        stamps[:] = [t for t in stamps if t > cutoff]
        stamps.append(self.now)
        return len(stamps)

    def sadd_window(self, key: str, member: str, window_s: int) -> int:
        """Add *member* to the windowed set and return distinct member count."""
        members = self._sets.setdefault(key, {})
        cutoff = self.now - window_s
        for stale in [m for m, t in members.items() if t <= cutoff]:
            del members[stale]
        members[member] = self.now
        return len(members)


def make_event(**kwargs: Any) -> Event:
    """Build an Event with sane defaults; override any field via kwargs."""
    base: dict[str, Any] = {
        "timestamp": BASE_TIME,
        "host": "web01",
        "source": "auth",
        "event_type": "authentication",
    }
    base.update(kwargs)
    return Event(**base)


def event_at(seconds: int, **kwargs: Any) -> Event:
    """Build an Event *seconds* after BASE_TIME."""
    return make_event(timestamp=BASE_TIME + timedelta(seconds=seconds), **kwargs)


def run_sequence(rule: Any, events: list[Event]) -> list[list[Any]]:
    """Evaluate *rule* over *events* in order, driving FakeCtx time from timestamps."""
    ctx = FakeCtx()
    results = []
    for event in events:
        ctx.set_time(event.timestamp.timestamp())
        results.append(rule.evaluate(event, ctx))
    return results


@pytest.fixture
def ctx() -> FakeCtx:
    return FakeCtx()
