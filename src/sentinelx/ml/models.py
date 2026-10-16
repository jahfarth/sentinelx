"""Anomaly model wrappers around scikit-learn estimators.

Both models expose ``fit(X)``, ``score(X) -> np.ndarray`` (values in
``[0, 1]``, higher = more anomalous) and joblib ``save``/``load``
round-trips.

* :class:`IsolationForestModel` — sklearn ``IsolationForest``; the raw
  ``decision_function`` (higher = more normal) is mapped to 0..1 via
  min-max scaling on the *training* scores, then flipped so higher means
  more anomalous.
* :class:`AutoencoderModel` — sklearn ``MLPRegressor`` with
  ``hidden_layer_sizes=(32, 16, 32)`` trained to reconstruct its input;
  the anomaly score is the per-row mean-squared reconstruction error
  normalized by the 95th percentile of the training errors, clipped to
  ``[0, 1]``.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler


class IsolationForestModel:
    """Isolation-Forest anomaly model with 0..1 scores."""

    def __init__(self, contamination: float = 0.05, random_state: int = 42) -> None:
        self.model = IsolationForest(contamination=contamination, random_state=random_state)
        self._score_min: float = 0.0
        self._score_max: float = 1.0
        self._fitted = False

    def fit(self, X: np.ndarray) -> IsolationForestModel:
        """Fit on the (assumed mostly-normal) training matrix *X*."""
        X = np.asarray(X, dtype=float)
        self.model.fit(X)
        train_scores = self.model.decision_function(X)
        self._score_min = float(train_scores.min())
        self._score_max = float(train_scores.max())
        if self._score_max <= self._score_min:
            self._score_max = self._score_min + 1e-9
        self._fitted = True
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        """Return per-row anomaly scores in ``[0, 1]`` (higher = anomalous)."""
        if not self._fitted:
            raise RuntimeError("IsolationForestModel must be fitted before scoring")
        raw = self.model.decision_function(np.asarray(X, dtype=float))
        scaled = (raw - self._score_min) / (self._score_max - self._score_min)
        return 1.0 - np.clip(scaled, 0.0, 1.0)

    def save(self, path: str | Path) -> Path:
        """Persist the fitted model (with its scaling stats) to *path*."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        return path

    @classmethod
    def load(cls, path: str | Path) -> IsolationForestModel:
        """Load a model previously saved with :meth:`save`."""
        model = joblib.load(path)
        if not isinstance(model, cls):
            raise TypeError(f"expected {cls.__name__} in {path}, got {type(model).__name__}")
        return model


class AutoencoderModel:
    """MLP autoencoder; anomaly score = normalized reconstruction error.

    Features are standardized internally (``StandardScaler`` fit on the
    training matrix) because MLPs need scaled inputs to learn a
    generalizing manifold instead of memorizing training points; the
    scaler is persisted together with the model.
    """

    def __init__(
        self,
        hidden_layer_sizes: tuple[int, ...] = (32, 16, 32),
        max_iter: int = 500,
        random_state: int = 42,
    ) -> None:
        self.scaler = StandardScaler()
        self.model = MLPRegressor(
            hidden_layer_sizes=hidden_layer_sizes,
            max_iter=max_iter,
            random_state=random_state,
        )
        self._p95_error: float = 1.0
        self._fitted = False

    @staticmethod
    def _reconstruction_error(X: np.ndarray, reconstructed: np.ndarray) -> np.ndarray:
        """Per-row mean-squared error between *X* and its reconstruction."""
        return np.mean((X - reconstructed) ** 2, axis=1)

    def fit(self, X: np.ndarray) -> AutoencoderModel:
        """Train the autoencoder to reconstruct the (normal) matrix *X*."""
        Xs = self.scaler.fit_transform(np.asarray(X, dtype=float))
        self.model.fit(Xs, Xs)
        train_errors = self._reconstruction_error(Xs, self.model.predict(Xs))
        self._p95_error = float(np.percentile(train_errors, 95))
        if self._p95_error <= 0.0:
            self._p95_error = 1e-9
        self._fitted = True
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        """Return per-row anomaly scores in ``[0, 1]`` (higher = anomalous)."""
        if not self._fitted:
            raise RuntimeError("AutoencoderModel must be fitted before scoring")
        Xs = self.scaler.transform(np.asarray(X, dtype=float))
        errors = self._reconstruction_error(Xs, self.model.predict(Xs))
        return np.clip(errors / self._p95_error, 0.0, 1.0)

    def save(self, path: str | Path) -> Path:
        """Persist the fitted model (with its p95 stat) to *path*."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        return path

    @classmethod
    def load(cls, path: str | Path) -> AutoencoderModel:
        """Load a model previously saved with :meth:`save`."""
        model = joblib.load(path)
        if not isinstance(model, cls):
            raise TypeError(f"expected {cls.__name__} in {path}, got {type(model).__name__}")
        return model
