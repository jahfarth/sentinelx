"""Event worker: consumes queued events, runs detection, persists alerts.

Run with ``python -m sentinelx.worker.run``.
"""

from sentinelx.worker.pipeline import PipelineDeps, process_event
from sentinelx.worker.state import RedisState

__all__ = ["PipelineDeps", "RedisState", "process_event"]
