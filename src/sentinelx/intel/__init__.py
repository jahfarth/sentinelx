"""Threat-intelligence enrichment for SentinelX.

``enrich_ip`` is the entry point used by the worker pipeline; the
per-provider clients live in ``abuseipdb``, ``virustotal`` and ``otx``.
Set ``SENTINELX_INTEL_MOCK=1`` for deterministic offline fixtures.
"""

from sentinelx.intel.base import CachedIntelClient, IntelError
from sentinelx.intel.enrich import enrich_ip

__all__ = ["CachedIntelClient", "IntelError", "enrich_ip"]
