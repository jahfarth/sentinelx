"""Normalizers: parse raw log lines into :class:`~sentinelx.common.models.Event`.

Supported sources:

- ``syslog`` — RFC3164 ``<pri>MMM DD HH:MM:SS host tag: message``.
- ``auth`` — OpenSSH auth lines (``Failed``/``Accepted password for ...``).
- ``nginx`` / ``apache`` — HTTP combined log format.
- ``windows`` — Windows Security event JSON (EventID 4624/4625/4672/4720).
- ``netflow`` — JSON or CSV flow records.

Every ``parse_*`` function returns ``Event | None``: ``None`` means the line
did not match the expected format. :func:`normalize` dispatches on *source*
and raises :class:`ValueError` for unknown sources; :func:`normalize_batch`
skips unparseable lines with a logged warning.
"""

import json
import logging
import re
from datetime import UTC, datetime

from sentinelx.common.models import Event

log = logging.getLogger(__name__)

_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

# RFC3164: <34>Oct 11 22:14:15 myhost sshd[1234]: Failed password for root ...
_SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^:]+):\s*"
    r"(?P<msg>.*)$"
)

# sshd[1234] -> sshd
_TAG_PID_RE = re.compile(r"^(?P<tag>[^\[]+)(?:\[\d+\])?$")

# Failed password for invalid user bob from 203.0.113.7 port 52341
# Accepted password for alice from 198.51.100.9 port 51230 ssh2
# (matched with search: the sshd message may carry a syslog prefix)
_AUTH_RE = re.compile(
    r"(?P<result>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /x HTTP/1.0" 200 2326 "-" "UA"
_HTTP_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r"\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\S+)\s+"
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<ua>[^"]*)"'
)

_REQUEST_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+HTTP/\S+)?$")

_NETFLOW_CSV_FIELDS = ("src_ip", "src_port", "dst_ip", "dst_port", "protocol", "bytes")


def _utcnow() -> datetime:
    """Current UTC time as a naive datetime (consistent with parsed log times)."""
    return datetime.now(UTC).replace(tzinfo=None)


def parse_syslog_line(line: str) -> Event | None:
    """Parse an RFC3164 syslog line into an :class:`Event`.

    Returns ``None`` when *line* does not match the syslog format.
    """
    match = _SYSLOG_RE.match(line.strip())
    if not match:
        return None
    parts = match.groupdict()
    month = _MONTHS.get(parts["mon"])
    if month is None:
        return None
    try:
        timestamp = datetime(
            datetime.now(UTC).year,
            month,
            int(parts["day"]),
            int(parts["hour"]),
            int(parts["min"]),
            int(parts["sec"]),
        )
    except ValueError:
        return None
    tag_match = _TAG_PID_RE.match(parts["tag"].strip())
    process = tag_match.group("tag") if tag_match else parts["tag"].strip()
    return Event(
        timestamp=timestamp,
        host=parts["host"],
        source="syslog",
        event_type="system",
        process=process,
        message=parts["msg"],
        raw={"priority": int(parts["pri"])},
    )


def parse_auth_log_line(line: str) -> Event | None:
    """Parse an OpenSSH auth line into an authentication :class:`Event`.

    Handles ``Failed password for [invalid user] USER from IP port P`` and
    ``Accepted password for USER from IP port P``. Returns ``None`` for
    non-matching lines.
    """
    match = _AUTH_RE.search(line)
    if not match:
        return None
    result = match.group("result")
    action = "auth_success" if result == "Accepted" else "auth_failed"
    return Event(
        timestamp=_utcnow(),
        host="",
        source="auth",
        event_type="authentication",
        src_ip=match.group("ip"),
        src_port=int(match.group("port")),
        user=match.group("user"),
        action=action,
        message=line.strip(),
    )


def _parse_http_combined(line: str, source: str) -> Event | None:
    """Shared parser for nginx/apache combined log format lines."""
    match = _HTTP_COMBINED_RE.match(line.strip())
    if not match:
        return None
    parts = match.groupdict()
    try:
        timestamp = datetime.strptime(parts["time"], "%d/%b/%Y:%H:%M:%S %z")
        timestamp = timestamp.astimezone(UTC).replace(tzinfo=None)
    except ValueError:
        return None
    method: str | None = None
    uri: str | None = None
    req_match = _REQUEST_RE.match(parts["request"])
    if req_match:
        method = req_match.group("method")
        uri = req_match.group("uri")
    user = parts["user"] if parts["user"] != "-" else None
    user_agent = parts["ua"] if parts["ua"] != "-" else None
    return Event(
        timestamp=timestamp,
        host="",
        source=source,  # type: ignore[arg-type]
        event_type="web",
        src_ip=parts["ip"],
        user=user,
        http_method=method,
        http_uri=uri,
        http_status=int(parts["status"]),
        user_agent=user_agent,
        message=line.strip(),
        raw={"referer": parts["referer"], "size": parts["size"]},
    )


def parse_nginx_line(line: str) -> Event | None:
    """Parse an nginx combined-format access line into a web :class:`Event`."""
    return _parse_http_combined(line, "nginx")


def parse_apache_line(line: str) -> Event | None:
    """Parse an Apache combined-format access line into a web :class:`Event`."""
    return _parse_http_combined(line, "apache")


def parse_windows_json(obj: dict) -> Event | None:
    """Parse a Windows Security event dict into an :class:`Event`.

    Supports logon success/failure (4624/4625), special logon (4672) and
    user creation (4720). Returns ``None`` for other event IDs or malformed
    payloads.
    """
    if not isinstance(obj, dict):
        return None
    event = obj.get("Event", obj)
    if not isinstance(event, dict):
        return None
    system = event.get("System", {})
    data = event.get("EventData", {})
    try:
        event_id = int(system.get("EventID", 0))
    except (TypeError, ValueError):
        return None

    actions = {
        4624: ("authentication", "logon_success"),
        4625: ("authentication", "logon_failed"),
        4672: ("authentication", "special_logon"),
        4720: ("system", "user_created"),
    }
    mapping = actions.get(event_id)
    if mapping is None:
        return None
    event_type, action = mapping

    system_time = (system.get("TimeCreated") or {}).get("SystemTime", "")
    timestamp = _utcnow()
    if system_time:
        try:
            parsed = datetime.fromisoformat(str(system_time).replace("Z", "+00:00"))
            timestamp = parsed.astimezone(UTC).replace(tzinfo=None)
        except ValueError:
            pass

    ip = data.get("IpAddress")
    src_ip = None if ip in (None, "", "-") else str(ip)
    user = data.get("TargetUserName") or data.get("TargetUser")
    return Event(
        timestamp=timestamp,
        host=str(system.get("Computer", "")),
        source="windows",
        event_type=event_type,  # type: ignore[arg-type]
        src_ip=src_ip,
        user=str(user) if user not in (None, "", "-") else None,
        action=action,
        message=f"Windows EventID {event_id}: {action}",
        raw={"event_id": event_id},
    )


def _parse_netflow_line(line: str, host: str) -> Event | None:
    """Parse a netflow record given as JSON or CSV into a network :class:`Event`.

    JSON form: ``{"src_ip": ..., "src_port": ..., "dst_ip": ..., "dst_port": ...}``.
    CSV form: ``src_ip,src_port,dst_ip,dst_port,protocol,bytes``.
    """
    record: dict = {}
    stripped = line.strip()
    if stripped.startswith("{"):
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            return None
    else:
        fields = [f.strip() for f in stripped.split(",")]
        if len(fields) < 4:
            return None
        record = dict(zip(_NETFLOW_CSV_FIELDS, fields, strict=False))

    src_ip = record.get("src_ip") or record.get("src")
    dst_ip = record.get("dst_ip") or record.get("dst")
    if not src_ip or not dst_ip:
        return None

    def _to_int(value: object) -> int | None:
        try:
            return int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None

    return Event(
        timestamp=_utcnow(),
        host=host,
        source="netflow",
        event_type="network",
        src_ip=str(src_ip),
        dst_ip=str(dst_ip),
        src_port=_to_int(record.get("src_port")),
        dst_port=_to_int(record.get("dst_port")),
        action="flow",
        message=stripped,
        raw={k: v for k, v in record.items() if k not in ("src_ip", "dst_ip")},
    )


def normalize(source: str, host: str, line: str) -> Event:
    """Normalize a single *line* from *source* into an :class:`Event`.

    The ``windows`` source expects *line* to be a JSON-encoded event object.
    Raises :class:`ValueError` for unknown sources and when the line cannot
    be parsed.
    """
    parsers = {
        "syslog": parse_syslog_line,
        "auth": parse_auth_log_line,
        "nginx": parse_nginx_line,
        "apache": parse_apache_line,
    }
    if source == "windows":
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"windows source expects JSON lines: {exc}") from exc
        event = parse_windows_json(obj)
    elif source == "netflow":
        event = _parse_netflow_line(line, host)
    elif source in parsers:
        event = parsers[source](line)
    else:
        raise ValueError(f"unknown source: {source!r}")

    if event is None:
        raise ValueError(f"could not parse line for source {source!r}: {line[:80]!r}")
    if host and not event.host:
        event.host = host
    return event


def normalize_batch(source: str, host: str, lines: list[str]) -> list[Event]:
    """Normalize many lines, skipping unparseable ones with a warning."""
    events: list[Event] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            events.append(normalize(source, host, line))
        except ValueError as exc:
            log.warning("skipping unparseable line: %s", exc)
    return events
