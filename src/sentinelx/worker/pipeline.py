"""Event processing pipeline: detection -> ML -> intel -> persist -> publish -> respond.

Each stage is defensive: the detection engine (``sentinelx.detection``), the
ML scorer (``sentinelx.ml``), the intel enricher (``sentinelx.intel``) and the
response policy (``sentinelx.response``) are all optional sibling packages and
are imported lazily. Missing stages are skipped with a log message so the
worker keeps running on partial installs.
"""

import ipaddress
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sentinelx.api.db import AlertRow
from sentinelx.common import mitre
from sentinelx.common.models import Alert, Event
from sentinelx.common.severity import compute_score, score_to_level
from sentinelx.worker.state import RedisState

log = logging.getLogger(__name__)

ML_ANOMALY_THRESHOLD = 0.7
_INTEL_TTL_S = 24 * 3600

_intel_cache: dict[str, tuple[float, dict]] = {}


@dataclass
class PipelineDeps:
    """Dependencies injected into :func:`process_event`."""

    session_factory: Callable[[], Any]
    redis: Any | None = None
    state: RedisState | None = None
    engine: Any | None = None


def _load_engine():
    """Build the detection engine, or return None when unavailable."""
    try:
        from sentinelx.detection import DetectionEngine
    except ImportError:
        log.debug("sentinelx.detection not installed; skipping rule evaluation")
        return None
    try:
        return DetectionEngine()
    except Exception:
        log.exception("failed to construct DetectionEngine")
        return None


def _ml_score(event: Event) -> float | None:
    """Return the ML anomaly score for *event*, or None when unavailable."""
    try:
        from sentinelx.ml import scoring
    except ImportError:
        return None
    try:
        score = scoring.score_event(event)
    except Exception:
        log.warning("ml scoring failed", exc_info=True)
        return None
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None
    return float(score)


def _anomaly_alert(event: Event, ml_score: float) -> Alert:
    """Build a standalone alert for an ML-flagged event with no rule hit."""
    technique = {"technique_id": "T1078", **mitre.lookup("T1078")}
    return Alert(
        timestamp=event.timestamp,
        rule_id="ml-anomaly",
        rule_name="ML anomaly detection",
        title=f"Anomalous {event.event_type} event on {event.host}",
        description=(
            f"ML model flagged this event as anomalous (score {ml_score:.2f}, "
            f"threshold {ML_ANOMALY_THRESHOLD})."
        ),
        severity="medium",
        score=50,
        mitre=technique,
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        host=event.host,
        user=event.user,
        evidence={"ml_score": ml_score, "event_type": event.event_type},
    )


def _is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _fetch_intel(ip: str) -> dict:
    if os.environ.get("SENTINELX_INTEL_MOCK", "") == "1":
        return {"mock": True, "ip": ip, "boost": 0, "reputation": "unknown"}
    try:
        from sentinelx.intel import enrich
    except ImportError:
        return {}
    try:
        result = enrich.enrich_ip(ip)
    except Exception:
        log.warning("intel enrichment failed for %s", ip, exc_info=True)
        return {}
    return dict(result) if isinstance(result, dict) else {}


def _intel_for(event: Event) -> tuple[dict, int]:
    """Return (intel dict, score boost) for the event's src_ip, cached 24h."""
    ip = event.src_ip
    if not ip or not _is_public_ip(ip):
        return {}, 0
    now = time.monotonic()
    cached = _intel_cache.get(ip)
    if cached is not None and now - cached[0] < _INTEL_TTL_S:
        intel = cached[1]
    else:
        intel = _fetch_intel(ip)
        _intel_cache[ip] = (now, intel)
    try:
        boost = int(intel.get("boost", 0) or 0)
    except (TypeError, ValueError):
        boost = 0
    return intel, boost


def _persist_alerts(alerts: list[Alert], session_factory: Callable[[], Any]) -> None:
    with session_factory() as session:
        for alert in alerts:
            session.add(
                AlertRow(
                    id=alert.id,
                    timestamp=alert.timestamp,
                    rule_id=alert.rule_id,
                    rule_name=alert.rule_name,
                    title=alert.title,
                    description=alert.description,
                    severity=alert.severity,
                    score=alert.score,
                    tactic=alert.mitre.get("tactic", ""),
                    technique_id=alert.mitre.get("technique_id", ""),
                    technique=alert.mitre.get("technique", ""),
                    src_ip=alert.src_ip,
                    dst_ip=alert.dst_ip,
                    host=alert.host,
                    user=alert.user,
                    mitre=alert.mitre,
                    evidence=alert.evidence,
                    intel=alert.intel,
                    status=alert.status,
                )
            )


def _publish_alerts(alerts: list[Alert], redis_client: Any | None) -> None:
    if redis_client is None:
        return
    for alert in alerts:
        try:
            redis_client.publish("sentinelx:alerts", alert.model_dump_json())
        except Exception:
            log.warning("failed to publish alert %s", alert.id, exc_info=True)


def _run_response(alerts: list[Alert]) -> None:
    try:
        from sentinelx.response import policy
    except ImportError:
        return
    for alert in alerts:
        try:
            policy.act(alert)
        except Exception:
            log.warning("response policy failed for alert %s", alert.id, exc_info=True)


def process_event(event: Event, deps: PipelineDeps) -> list[Alert]:
    """Run one event through the full pipeline and return produced alerts.

    Stages: rule detection -> ML scoring -> threat-intel enrichment ->
    DB persistence -> Redis publish -> automated response.
    """
    alerts: list[Alert] = []

    # 1) rule-based detection
    engine = deps.engine if deps.engine is not None else _load_engine()
    if engine is not None:
        try:
            found = engine.evaluate(event, {"state": deps.state, "redis": deps.redis})
            alerts.extend(found or [])
        except Exception:
            log.exception("detection engine evaluation failed")

    # 2) ML anomaly scoring
    ml_score = _ml_score(event)
    if ml_score is not None:
        for alert in alerts:
            alert.evidence["ml_score"] = ml_score
        if not alerts and ml_score >= ML_ANOMALY_THRESHOLD:
            alerts.append(_anomaly_alert(event, ml_score))

    # 3) threat-intel enrichment (public src_ip only), boosting scores
    intel, boost = _intel_for(event)
    for alert in alerts:
        alert.intel = intel
        alert.score = compute_score(alert.score, boost)
        alert.severity = score_to_level(alert.score)

    if not alerts:
        return []

    # 4) persist
    _persist_alerts(alerts, deps.session_factory)

    # 5) publish for the live SSE stream
    _publish_alerts(alerts, deps.redis)

    # 6) automated response
    _run_response(alerts)

    return alerts
