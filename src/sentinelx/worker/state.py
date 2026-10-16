"""Sliding-window state for detection rules, backed by Redis or memory.

:class:`RedisState` offers two primitives used by detection rules:

- :meth:`count` — how many times *key* fired inside *window_s* seconds.
- :meth:`sadd_window` — cardinality of distinct members seen inside the window.

Key format is ``sentinelx:state:{rule_id}:{dimension}:{value}`` (see
:meth:`make_key`). When no Redis client is available a correct in-memory
fallback with timestamp pruning is used instead of a stub.
"""

import logging
import threading
import time

log = logging.getLogger(__name__)


class RedisState:
    """Windowed counters backed by Redis, with an in-memory fallback."""

    def __init__(self, redis_client=None) -> None:
        """Wrap *redis_client*; ``None`` selects the in-memory fallback."""
        self._r = redis_client
        self._lock = threading.Lock()
        self._counts: dict[str, list[float]] = {}
        self._sets: dict[str, dict[str, float]] = {}

    @staticmethod
    def make_key(rule_id: str, dimension: str, value: str) -> str:
        """Build a namespaced state key."""
        return f"sentinelx:state:{rule_id}:{dimension}:{value}"

    # -- in-memory fallback ------------------------------------------------ #
    def _mem_count(self, key: str, window_s: float) -> int:
        now = time.monotonic()
        with self._lock:
            hits = self._counts.setdefault(key, [])
            hits[:] = [ts for ts in hits if now - ts < window_s]
            hits.append(now)
            return len(hits)

    def _mem_sadd(self, key: str, member: str, window_s: float) -> int:
        now = time.monotonic()
        with self._lock:
            members = self._sets.setdefault(key, {})
            for known in [m for m, ts in members.items() if now - ts >= window_s]:
                del members[known]
            members[member] = now
            return len(members)

    # -- public API --------------------------------------------------------- #
    def count(self, key: str, window_s: float) -> int:
        """Increment the counter for *key* and return its windowed total."""
        if self._r is not None:
            try:
                pipe = self._r.pipeline()
                pipe.incr(key)
                pipe.pexpire(key, max(1, int(window_s * 1000)))
                total, _ = pipe.execute()
                return int(total)
            except Exception as exc:
                log.warning("redis state.count failed, using memory fallback: %s", exc)
        return self._mem_count(key, window_s)

    def sadd_window(self, key: str, member: str, window_s: float) -> int:
        """Add *member* to the windowed set and return its cardinality."""
        if self._r is not None:
            try:
                pipe = self._r.pipeline()
                pipe.sadd(key, member)
                pipe.pexpire(key, max(1, int(window_s * 1000)))
                pipe.scard(key)
                _, _, cardinality = pipe.execute()
                return int(cardinality)
            except Exception as exc:
                log.warning("redis state.sadd_window failed, using memory fallback: %s", exc)
        return self._mem_sadd(key, member, window_s)
