"""ML anomaly detection for SentinelX.

``features`` turns raw events into aggregate feature vectors, ``models``
wraps the sklearn detectors, ``scoring`` exposes the ``score_event`` entry
point used by the worker pipeline, and ``train`` / ``sample_data`` support
the offline training workflow.
"""

from sentinelx.ml.scoring import score_event

__all__ = ["score_event"]
