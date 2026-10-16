"""SQLAlchemy 2.0 persistence for events and alerts.

``DATABASE_URL`` (env, default ``sqlite:///./sentinelx.db``) selects the
backend; SQLite for dev/tests, Postgres for production. :func:`init_db`
creates the tables and :func:`get_session` is a commit-on-success
context manager.
"""

import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all SentinelX tables."""


class EventRow(Base):
    """Stored normalized event."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class AlertRow(Base):
    """Stored alert."""

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    rule_name: Mapped[str] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    score: Mapped[int] = mapped_column(Integer)
    tactic: Mapped[str] = mapped_column(String(128), default="")
    technique_id: Mapped[str] = mapped_column(String(32), default="")
    technique: Mapped[str] = mapped_column(String(255), default="")
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mitre: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    intel: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)


_engine = None
_engine_url: str | None = None


def database_url() -> str:
    """Return the configured database URL (env ``DATABASE_URL``)."""
    return os.environ.get("DATABASE_URL", "sqlite:///./sentinelx.db")


def get_engine():
    """Return a cached engine for the current ``DATABASE_URL``."""
    global _engine, _engine_url
    url = database_url()
    if _engine is None or _engine_url != url:
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_engine(url, future=True, connect_args=connect_args)
        _engine_url = url
    return _engine


def init_db() -> None:
    """Create all tables if they do not exist yet."""
    Base.metadata.create_all(get_engine())


@contextmanager
def get_session() -> Iterator[Session]:
    """Yield a session; commits on success, rolls back on error."""
    session = Session(get_engine())
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
