"""Log shipper agent: tails log files and POSTs batches to the SentinelX API.

Run with ``python -m sentinelx.agent --config agent.yml``.
"""

from sentinelx.agent.shipper import AgentConfig, FileSpec, FileTailer, Shipper

__all__ = ["AgentConfig", "FileSpec", "FileTailer", "Shipper"]
