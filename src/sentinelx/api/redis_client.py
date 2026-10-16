"""Redis access with graceful degradation.

:func:`get_redis` returns a connected client, or ``None`` when ``REDIS_URL``
is unset or the connection fails. Every queue/cache operation in the API
must guard on the ``None`` case instead of crashing.
"""

import logging
import os

log = logging.getLogger(__name__)

_client = None
_client_url: str | None = None


def get_redis():
    """Return a Redis client, or ``None`` when Redis is unavailable.

    The client is cached per ``REDIS_URL`` value; a failed connection attempt
    logs a warning and yields ``None`` so callers skip queue operations.
    """
    global _client, _client_url
    url = os.environ.get("REDIS_URL")
    if not url:
        return None
    if _client is None or _client_url != url:
        _client = None
        _client_url = url
        try:
            import redis

            candidate = redis.Redis.from_url(url, socket_connect_timeout=3, decode_responses=True)
            candidate.ping()
            _client = candidate
        except Exception as exc:  # connection refused, DNS failure, auth error, ...
            log.warning("redis unavailable at %s: %s", url, exc)
            _client = None
    return _client


def reset_redis_client() -> None:
    """Drop the cached client (used by tests to re-read ``REDIS_URL``)."""
    global _client, _client_url
    _client = None
    _client_url = None
