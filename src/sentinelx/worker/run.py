"""Worker entry point: ``python -m sentinelx.worker.run``.

Consumes events from the ``sentinelx:events`` Redis list (BLPOP, 5s timeout),
runs each through :func:`sentinelx.worker.pipeline.process_event`, logs
errors without stopping, and shuts down gracefully on SIGINT/SIGTERM. Redis
is optional: without it the worker waits and retries instead of crashing.
"""

import logging
import signal
import threading

from sentinelx.api.db import get_session, init_db
from sentinelx.api.redis_client import get_redis
from sentinelx.common.models import Event
from sentinelx.worker.pipeline import PipelineDeps, process_event
from sentinelx.worker.state import RedisState

log = logging.getLogger(__name__)


def main() -> None:
    """Run the consume/process loop until interrupted."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    init_db()

    stop = threading.Event()

    def _handle(signum, frame):
        log.info("received signal %s, shutting down", signum)
        stop.set()

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    deps = PipelineDeps(session_factory=get_session, redis=None, state=RedisState(None))
    log.info("worker started, waiting for events")

    while not stop.is_set():
        client = get_redis()
        if client is None:
            log.warning("redis unavailable; retrying in 5s")
            stop.wait(5)
            continue
        deps.redis = client
        deps.state = RedisState(client)
        try:
            item = client.blpop("sentinelx:events", timeout=5)
        except Exception as exc:
            log.error("redis blpop failed: %s", exc)
            stop.wait(5)
            continue
        if not item:
            continue
        _, payload = item
        try:
            event = Event.model_validate_json(payload)
        except Exception:
            log.exception("dropping malformed event payload")
            continue
        try:
            alerts = process_event(event, deps)
            if alerts:
                log.info("event produced %d alert(s)", len(alerts))
        except Exception:
            log.exception("failed to process event")


if __name__ == "__main__":
    main()
