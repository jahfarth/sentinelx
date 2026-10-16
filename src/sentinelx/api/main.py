"""SentinelX REST API.

Endpoints:
    POST /api/v1/ingest          normalize + store events, queue them for the worker
    GET  /api/v1/alerts          list alerts with filters
    GET  /api/v1/alerts/{id}     single alert
    PATCH /api/v1/alerts/{id}    update alert status
    GET  /api/v1/stats/overview  dashboard counters
    GET  /api/v1/stats/timeline  hourly event/alert buckets
    GET  /api/v1/attackers       top attacker IPs with coarse geo
    GET  /api/v1/stream         server-sent event stream of new alerts
    GET  /healthz                liveness probe
"""

import asyncio
import ipaddress
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, get_args

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, func
from sse_starlette.sse import EventSourceResponse

from sentinelx.api.db import AlertRow, EventRow, get_session, init_db
from sentinelx.api.redis_client import get_redis
from sentinelx.common.models import Alert, Event, EventSource
from sentinelx.ingestion.normalizers import normalize

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create DB tables on startup."""
    init_db()
    yield


app = FastAPI(title="SentinelX API", version="0.1.0", lifespan=lifespan)


# --------------------------------------------------------------------------- #
# request / response models
# --------------------------------------------------------------------------- #
class IngestLines(BaseModel):
    """Ingest raw log lines for one host/source pair."""

    host: str
    source: str
    lines: list[str]


class IngestEvents(BaseModel):
    """Ingest already-normalized event dicts."""

    events: list[dict[str, Any]]


class StatusUpdate(BaseModel):
    """Alert status change payload."""

    status: Literal["new", "acknowledged", "resolved"]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _event_to_row(event: Event) -> EventRow:
    data = {
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "process": event.process,
        "action": event.action,
        "http_method": event.http_method,
        "http_uri": event.http_uri,
        "http_status": event.http_status,
        "user_agent": event.user_agent,
        "message": event.message,
        "raw": event.raw,
    }
    return EventRow(
        timestamp=event.timestamp,
        host=event.host,
        source=event.source,
        event_type=event.event_type,
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        user=event.user,
        data=data,
    )


def _row_to_alert_dict(row: AlertRow) -> dict[str, Any]:
    alert = Alert(
        id=row.id,
        timestamp=row.timestamp,
        rule_id=row.rule_id,
        rule_name=row.rule_name,
        title=row.title,
        description=row.description,
        severity=row.severity,  # type: ignore[arg-type]
        score=row.score,
        mitre=row.mitre or {},
        src_ip=row.src_ip,
        dst_ip=row.dst_ip,
        host=row.host,
        user=row.user,
        evidence=row.evidence or {},
        intel=row.intel or {},
        status=row.status,  # type: ignore[arg-type]
    )
    return alert.model_dump(mode="json")


def _push_event(event: Event) -> None:
    client = get_redis()
    if client is None:
        return
    try:
        client.rpush("sentinelx:events", event.model_dump_json())
    except Exception as exc:
        log.warning("failed to queue event: %s", exc)


def _geo(ip: str | None) -> tuple[str, float, float]:
    """Coarse geo for an IP without any external lookup.

    RFC1918/loopback/link-local addresses map to ``"Private"``; everything
    else is ``"Unknown"``. Coordinates are always 0.0 (no geolocation DB).
    """
    if not ip:
        return "Unknown", 0.0, 0.0
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return "Unknown", 0.0, 0.0
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return "Private", 0.0, 0.0
    return "Unknown", 0.0, 0.0


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #
@app.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


@app.post("/api/v1/ingest")
def ingest(body: IngestLines | IngestEvents) -> dict[str, int]:
    """Normalize/store events and queue them for the detection worker.

    Accepts either ``{"host", "source", "lines"}`` (raw log lines) or
    ``{"events": [...]}`` (already-normalized event dicts).
    """
    events: list[Event] = []
    if isinstance(body, IngestLines):
        if body.source not in get_args(EventSource):
            raise HTTPException(status_code=422, detail=f"unknown source: {body.source!r}")
        received = len(body.lines)
        for line in body.lines:
            if not line.strip():
                continue
            try:
                events.append(normalize(body.source, body.host, line))
            except ValueError as exc:
                log.warning("ingest: skipping line: %s", exc)
    else:
        received = len(body.events)
        for raw in body.events:
            try:
                events.append(Event.model_validate(raw))
            except Exception as exc:
                log.warning("ingest: skipping invalid event: %s", exc)

    with get_session() as session:
        for event in events:
            session.add(_event_to_row(event))
    for event in events:
        _push_event(event)
    return {"received": received, "normalized": len(events)}


@app.get("/api/v1/alerts")
def list_alerts(
    severity: str | None = None,
    status: str | None = None,
    rule_id: str | None = None,
    src_ip: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """List alerts with optional filters, newest first."""
    with get_session() as session:
        query = session.query(AlertRow)
        if severity:
            query = query.filter(AlertRow.severity == severity)
        if status:
            query = query.filter(AlertRow.status == status)
        if rule_id:
            query = query.filter(AlertRow.rule_id == rule_id)
        if src_ip:
            query = query.filter(AlertRow.src_ip == src_ip)
        total = query.count()
        rows = query.order_by(desc(AlertRow.timestamp)).limit(limit).offset(offset).all()
        alerts = [_row_to_alert_dict(row) for row in rows]
    return {"total": total, "alerts": alerts}


@app.get("/api/v1/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict[str, Any]:
    """Fetch a single alert by id (404 when missing)."""
    with get_session() as session:
        row = session.get(AlertRow, alert_id)
        if row is None:
            raise HTTPException(status_code=404, detail="alert not found")
        return _row_to_alert_dict(row)


@app.patch("/api/v1/alerts/{alert_id}")
def update_alert(alert_id: str, update: StatusUpdate) -> dict[str, Any]:
    """Update an alert's status. Invalid status values yield 422."""
    with get_session() as session:
        row = session.get(AlertRow, alert_id)
        if row is None:
            raise HTTPException(status_code=404, detail="alert not found")
        row.status = update.status
        session.add(row)
        session.flush()
        return _row_to_alert_dict(row)


@app.get("/api/v1/stats/overview")
def stats_overview() -> dict[str, Any]:
    """Dashboard counters: totals, last-24h alerts, top attackers by alert."""
    cutoff = _utcnow() - timedelta(hours=24)
    with get_session() as session:
        total_events = session.query(func.count(EventRow.id)).scalar() or 0
        total_alerts_24h = (
            session.query(func.count(AlertRow.id))
            .filter(AlertRow.timestamp >= cutoff)
            .scalar()
            or 0
        )
        critical_24h = (
            session.query(func.count(AlertRow.id))
            .filter(AlertRow.timestamp >= cutoff, AlertRow.severity == "critical")
            .scalar()
            or 0
        )
        top_rows = (
            session.query(AlertRow.src_ip, func.count(AlertRow.id).label("cnt"))
            .filter(AlertRow.timestamp >= cutoff, AlertRow.src_ip.isnot(None))
            .group_by(AlertRow.src_ip)
            .order_by(desc("cnt"))
            .limit(10)
            .all()
        )
        sev_rows = (
            session.query(AlertRow.severity, func.count(AlertRow.id))
            .filter(AlertRow.timestamp >= cutoff)
            .group_by(AlertRow.severity)
            .all()
        )
    alerts_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sev, count in sev_rows:
        if sev in alerts_by_severity:
            alerts_by_severity[sev] = count
    return {
        "total_events": total_events,
        "total_alerts_24h": total_alerts_24h,
        "critical_24h": critical_24h,
        "top_attackers": [{"ip": ip, "count": count} for ip, count in top_rows],
        "alerts_by_severity": alerts_by_severity,
    }


@app.get("/api/v1/stats/timeline")
def stats_timeline(hours: int = Query(default=24, ge=1, le=168)) -> dict[str, Any]:
    """Hourly buckets of event volume and critical alerts for the last N hours."""
    now = _utcnow()
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    start_range = current_hour - timedelta(hours=hours - 1)
    with get_session() as session:
        event_ts = [
            row[0] for row in session.query(EventRow.timestamp)
            .filter(EventRow.timestamp >= start_range).all()
        ]
        crit_ts = [
            row[0] for row in session.query(AlertRow.timestamp)
            .filter(AlertRow.timestamp >= start_range, AlertRow.severity == "critical").all()
        ]
    buckets = []
    for i in range(hours):
        bucket_start = start_range + timedelta(hours=i)
        bucket_end = bucket_start + timedelta(hours=1)
        count = sum(1 for ts in event_ts if bucket_start <= ts < bucket_end)
        critical = sum(1 for ts in crit_ts if bucket_start <= ts < bucket_end)
        buckets.append({"ts": bucket_start.isoformat(), "count": count, "critical": critical})
    return {"buckets": buckets}


@app.get("/api/v1/attackers")
def attackers(limit: int = Query(default=20, ge=1, le=200)) -> dict[str, Any]:
    """Top attacker IPs by alert count, with coarse geo (no external lookup)."""
    with get_session() as session:
        rows = (
            session.query(AlertRow.src_ip, func.count(AlertRow.id).label("cnt"))
            .filter(AlertRow.src_ip.isnot(None))
            .group_by(AlertRow.src_ip)
            .order_by(desc("cnt"))
            .limit(limit)
            .all()
        )
    result = []
    for ip, count in rows:
        country, lat, lon = _geo(ip)
        result.append({"ip": ip, "alerts": count, "country": country, "lat": lat, "lon": lon})
    return {"attackers": result}


@app.get("/api/v1/stream")
async def stream() -> EventSourceResponse:
    """Server-sent event stream of new alerts.

    Subscribes to the ``sentinelx:alerts`` Redis channel. Without Redis,
    sends a comment heartbeat and closes gracefully.
    """

    async def event_generator():
        client = get_redis()
        if client is None:
            yield {"comment": "redis unavailable - live alert stream disabled"}
            return
        pubsub = client.pubsub()
        await asyncio.to_thread(pubsub.subscribe, "sentinelx:alerts")
        try:
            while True:
                message = await asyncio.to_thread(pubsub.get_message, timeout=15.0)
                if message and message.get("type") == "message":
                    yield {"data": message["data"]}
                else:
                    yield {"comment": "heartbeat"}
        finally:
            await asyncio.to_thread(pubsub.close)

    return EventSourceResponse(event_generator())
