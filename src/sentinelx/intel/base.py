"""Shared base for the threat-intel provider clients.

:class:`IntelError` is raised for provider failures (HTTP errors, bad
payloads). :class:`CachedIntelClient` wraps expensive provider lookups with
an optional Redis cache: when no Redis client is supplied (or Redis is
unreachable) the fetch runs directly.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

log = logging.getLogger(__name__)


class IntelError(RuntimeError):
    """Raised when a threat-intel provider request fails."""


class CachedIntelClient:
    """Threat-intel client with optional Redis response caching."""

    def __init__(self, redis_client: Any | None = None, mock: bool = False) -> None:
        self.redis = redis_client
        self.mock = mock

    def _cache_get(self, key: str) -> dict | None:
        if self.redis is None:
            return None
        try:
            raw = self.redis.get(key)
        except Exception:
            log.warning("intel redis GET failed; skipping cache", exc_info=True)
            return None
        if raw is None:
            return None
        try:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            return json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            log.warning("intel redis cache held invalid JSON for %s", key)
            return None

    def _cache_set(self, key: str, ttl_s: int, value: dict) -> None:
        if self.redis is None:
            return
        try:
            self.redis.setex(key, ttl_s, json.dumps(value))
        except Exception:
            log.warning("intel redis SETEX failed; continuing uncached", exc_info=True)

    def _cached_get(self, cache_key: str, ttl_s: int, fetch_fn: Callable[[], dict]) -> dict:
        """Return the cached value for *cache_key* or fetch and store it.

        Falls back to a direct fetch whenever Redis is absent or errors.
        """
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        result = fetch_fn()
        if isinstance(result, dict):
            self._cache_set(cache_key, ttl_s, result)
        return result
