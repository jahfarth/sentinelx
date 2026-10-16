"""SentinelX — open-source mini SOC platform.

Packages:
    sentinelx.common: shared pydantic models, MITRE mapping, severity helpers.
    sentinelx.ingestion: log normalizers (syslog, auth, nginx, apache, windows, netflow).
    sentinelx.api: FastAPI service with ingest/alert/stats/stream endpoints.
    sentinelx.agent: log shipper agent that tails files and POSTs batches to the API.
    sentinelx.worker: event queue consumer that runs detection, ML, intel and response.
"""

__all__ = ["__version__"]
__version__ = "0.1.0"
