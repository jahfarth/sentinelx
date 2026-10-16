"""Feature extraction for the ML anomaly detectors.

Two aggregate feature sets:

* ``login_features`` — one row per ``(host, user)`` pair:
  ``[hour_sin, hour_cos, n_failed_last_20, unique_src_ips, is_unusual_hour]``.
* ``traffic_features`` — one row per ``host``:
  ``[req_rate, err_ratio, uri_entropy, unique_uris]``.

Formulas:

* ``hour_sin``/``hour_cos`` — circular encoding of the group's mean login
  hour ``h``: ``sin(2*pi*h/24)``, ``cos(2*pi*h/24)``.
* ``n_failed_last_20`` — number of failed authentication events among the
  last 20 events of the group (a failed login has
  ``action`` in ``{"login_failed", "auth_failed", "failed"}`` or the word
  "fail" in its message).
* ``uri_entropy`` — Shannon entropy of the character distribution of all
  ``http_uri`` values in the group concatenated together.
* ``req_rate`` — events per minute over the group's time span
  (``n_events / (span_seconds / 60)``, span floored at 1 second).
* ``err_ratio`` — fraction of events with ``http_status >= 400``.
"""

from collections import defaultdict
from datetime import datetime

import numpy as np

from sentinelx.common.models import Event

_FAILED_ACTIONS = frozenset({"login_failed", "auth_failed", "failed", "failure"})
_UNUSUAL_START = 6
_UNUSUAL_END = 22


def _is_failure(event: Event) -> bool:
    """Decide whether *event* represents a failed authentication."""
    if event.action and event.action.lower() in _FAILED_ACTIONS:
        return True
    return "fail" in event.message.lower()


def _hour_of(ts: datetime) -> float:
    """Hour of day as a float in [0, 24)."""
    return ts.hour + ts.minute / 60.0 + ts.second / 3600.0


def _uri_entropy(uris: list[str]) -> float:
    """Shannon entropy of the character distribution of *uris* concatenated."""
    text = "".join(uris)
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    probs = np.fromiter(counts.values(), dtype=float) / total
    return float(-np.sum(probs * np.log2(probs)))


def _cyclic_hour(mean_hour: float) -> tuple[float, float]:
    """Circular encoding of an hour of day as (sin, cos)."""
    angle = 2.0 * np.pi * mean_hour / 24.0
    return float(np.sin(angle)), float(np.cos(angle))


def login_features(events: list[Event]) -> np.ndarray:
    """Aggregate *events* into one feature row per ``(host, user)``.

    Columns: ``[hour_sin, hour_cos, n_failed_last_20, unique_src_ips,
    is_unusual_hour]`` where ``is_unusual_hour`` is 1.0 when the group's
    mean hour is before 06:00 or at/after 22:00, else 0.0.
    """
    groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        if event.event_type != "authentication":
            continue
        groups[(event.host, event.user or "")].append(event)

    rows: list[list[float]] = []
    for group in groups.values():
        ordered = sorted(group, key=lambda e: e.timestamp)
        mean_hour = sum(_hour_of(e.timestamp) for e in ordered) / len(ordered)
        hour_sin, hour_cos = _cyclic_hour(mean_hour)
        recent = ordered[-20:]
        n_failed = sum(1 for e in recent if _is_failure(e))
        unique_ips = len({e.src_ip for e in ordered if e.src_ip})
        unusual = 1.0 if (mean_hour < _UNUSUAL_START or mean_hour >= _UNUSUAL_END) else 0.0
        rows.append([hour_sin, hour_cos, float(n_failed), float(unique_ips), unusual])

    return np.asarray(rows, dtype=float).reshape(-1, 5)


def traffic_features(events: list[Event]) -> np.ndarray:
    """Aggregate web *events* into one feature row per ``host``.

    Columns: ``[req_rate, err_ratio, uri_entropy, unique_uris]``.
    """
    groups: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.event_type != "web":
            continue
        groups[event.host].append(event)

    rows: list[list[float]] = []
    for group in groups.values():
        ordered = sorted(group, key=lambda e: e.timestamp)
        span_s = (ordered[-1].timestamp - ordered[0].timestamp).total_seconds()
        span_s = max(span_s, 1.0)
        req_rate = len(ordered) / (span_s / 60.0)
        statuses = [e.http_status for e in ordered if e.http_status is not None]
        err_ratio = (
            sum(1 for s in statuses if s >= 400) / len(statuses) if statuses else 0.0
        )
        uris = [e.http_uri or "" for e in ordered]
        entropy = _uri_entropy(uris)
        unique_uris = len(set(uris))
        rows.append([req_rate, err_ratio, entropy, float(unique_uris)])

    return np.asarray(rows, dtype=float).reshape(-1, 4)


def single_login_vector(event: Event) -> np.ndarray:
    """Build a login-style feature row from one authentication *event*.

    Used at scoring time when no aggregate history is available: the
    hour comes from the event timestamp, ``n_failed_last_20`` is 1.0 when
    the event itself failed, and ``unique_src_ips`` is 1.
    """
    hour = _hour_of(event.timestamp)
    hour_sin, hour_cos = _cyclic_hour(hour)
    n_failed = 1.0 if _is_failure(event) else 0.0
    unusual = 1.0 if (hour < _UNUSUAL_START or hour >= _UNUSUAL_END) else 0.0
    return np.array([[hour_sin, hour_cos, n_failed, 1.0, unusual]], dtype=float)


def single_traffic_vector(event: Event) -> np.ndarray:
    """Build a traffic-style feature row from one web *event*.

    ``req_rate`` is 0 (no window for a single event); ``err_ratio`` is 1.0
    when the event's status is >= 400, else 0.0.
    """
    err_ratio = 1.0 if (event.http_status is not None and event.http_status >= 400) else 0.0
    entropy = _uri_entropy([event.http_uri or ""])
    return np.array([[0.0, err_ratio, entropy, 1.0]], dtype=float)
