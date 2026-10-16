"""Per-event anomaly scoring used by the worker pipeline.

``score_event`` picks a feature path from the event's type/source, builds a
single-row feature vector, and averages the available trained models for
that kind. Models are loaded lazily from ``SENTINELX_MODEL_DIR`` (default
``./models``) and cached at module level. When no models are available the
function logs at debug level and returns ``0.0``.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import numpy as np

from sentinelx.common.models import Event
from sentinelx.ml.features import single_login_vector, single_traffic_vector
from sentinelx.ml.models import AutoencoderModel, IsolationForestModel

log = logging.getLogger(__name__)

_LOGIN_SOURCES = frozenset({"auth", "windows", "syslog"})
_TRAFFIC_SOURCES = frozenset({"nginx", "apache"})

_MODEL_FILES = {
    "login": ("login_iforest.joblib", "login_autoencoder.joblib"),
    "traffic": ("traffic_iforest.joblib", "traffic_autoencoder.joblib"),
}

_models: dict[str, list] | None = None


def _reset_cache() -> None:
    """Clear the module-level model cache (used by tests)."""
    global _models
    _models = None


def _model_dir() -> Path:
    return Path(os.environ.get("SENTINELX_MODEL_DIR", "./models"))


def _load_models() -> dict[str, list]:
    """Load (and cache) whatever trained models exist under the model dir."""
    global _models
    if _models is not None:
        return _models
    loaded: dict[str, list] = {"login": [], "traffic": []}
    directory = _model_dir()
    for kind, (iforest_name, auto_name) in _MODEL_FILES.items():
        iforest_path = directory / iforest_name
        auto_path = directory / auto_name
        if iforest_path.exists():
            try:
                loaded[kind].append(IsolationForestModel.load(iforest_path))
            except Exception:
                log.warning("failed to load %s", iforest_path, exc_info=True)
        if auto_path.exists():
            try:
                loaded[kind].append(AutoencoderModel.load(auto_path))
            except Exception:
                log.warning("failed to load %s", auto_path, exc_info=True)
    _models = loaded
    return loaded


def _kind_for(event: Event) -> str:
    """Pick the ``login`` or ``traffic`` feature path for *event*."""
    if event.event_type == "authentication":
        return "login"
    if event.event_type == "web":
        return "traffic"
    if event.source in _TRAFFIC_SOURCES:
        return "traffic"
    return "login"


def score_event(event: Event) -> float:
    """Return the anomaly score for *event* in ``[0, 1]``.

    Higher means more anomalous. Returns ``0.0`` when no trained models
    are available for the event's feature kind.
    """
    kind = _kind_for(event)
    models = _load_models().get(kind, [])
    if not models:
        log.debug("no %s models available; returning 0.0", kind)
        return 0.0
    vector = single_login_vector(event) if kind == "login" else single_traffic_vector(event)
    scores = []
    for model in models:
        try:
            scores.append(float(np.asarray(model.score(vector)).ravel()[0]))
        except Exception:
            log.warning("model scoring failed", exc_info=True)
    if not scores:
        return 0.0
    return float(np.clip(sum(scores) / len(scores), 0.0, 1.0))
