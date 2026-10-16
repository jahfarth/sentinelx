"""Core pydantic v2 contracts shared by every SentinelX component.

Every event that flows through the platform is normalized into :class:`Event`
and every detection result is an :class:`Alert`.
"""

from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field

EventSource = Literal["syslog", "auth", "nginx", "apache", "windows", "netflow"]
EventType = Literal["authentication", "network", "web", "process", "system"]
Severity = Literal["critical", "high", "medium", "low"]
AlertStatus = Literal["new", "acknowledged", "resolved"]


class Event(BaseModel):
    """A single normalized security-relevant event."""

    timestamp: datetime
    host: str
    source: EventSource
    event_type: EventType
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    user: str | None = None
    process: str | None = None
    action: str | None = None
    http_method: str | None = None
    http_uri: str | None = None
    http_status: int | None = None
    user_agent: str | None = None
    message: str = ""
    raw: dict = {}


class Alert(BaseModel):
    """A detection result produced by the worker pipeline."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    timestamp: datetime
    rule_id: str
    rule_name: str
    title: str
    description: str
    severity: Severity
    score: int = Field(ge=0, le=100)
    mitre: dict = {}
    src_ip: str | None = None
    dst_ip: str | None = None
    host: str | None = None
    user: str | None = None
    evidence: dict = {}
    intel: dict = {}
    status: AlertStatus = "new"
