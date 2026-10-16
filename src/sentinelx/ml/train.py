"""Train the SentinelX anomaly models from CSV event data.

Usage::

    python -m sentinelx.ml.train --kind login --data data/login.csv --out models/
    python -m sentinelx.ml.train --kind traffic --data data/traffic.csv --out models/

Login CSV columns: ``timestamp,host,user,src_ip,success``.
Traffic CSV columns: ``timestamp,host,src_ip,http_method,http_uri,http_status``.

For each kind an IsolationForest and an autoencoder are fitted on the
aggregate feature vectors and saved as ``<kind>_iforest.joblib`` and
``<kind>_autoencoder.joblib`` under ``--out``.
"""

from __future__ import annotations

import argparse
import csv
import logging
from datetime import datetime
from pathlib import Path

from sentinelx.common.models import Event
from sentinelx.ml.features import login_features, traffic_features
from sentinelx.ml.models import AutoencoderModel, IsolationForestModel

log = logging.getLogger(__name__)


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def load_login_events(csv_path: str | Path) -> list[Event]:
    """Read a login CSV into :class:`Event` objects (authentication type)."""
    events: list[Event] = []
    with Path(csv_path).open(newline="") as fh:
        for row in csv.DictReader(fh):
            success = str(row.get("success", "1")).strip() == "1"
            events.append(
                Event(
                    timestamp=_parse_ts(row["timestamp"]),
                    host=row["host"],
                    source="auth",
                    event_type="authentication",
                    src_ip=row.get("src_ip") or None,
                    user=row.get("user") or None,
                    action="login_success" if success else "login_failed",
                    message="login succeeded" if success else "login failed",
                )
            )
    return events


def load_traffic_events(csv_path: str | Path) -> list[Event]:
    """Read a traffic CSV into :class:`Event` objects (web type)."""
    events: list[Event] = []
    with Path(csv_path).open(newline="") as fh:
        for row in csv.DictReader(fh):
            events.append(
                Event(
                    timestamp=_parse_ts(row["timestamp"]),
                    host=row["host"],
                    source="nginx",
                    event_type="web",
                    src_ip=row.get("src_ip") or None,
                    http_method=row.get("http_method") or None,
                    http_uri=row.get("http_uri") or None,
                    http_status=int(row["http_status"]) if row.get("http_status") else None,
                )
            )
    return events


def train_models(kind: str, csv_path: str | Path, out_dir: str | Path) -> dict[str, Path]:
    """Fit both models for *kind* on *csv_path* and save them to *out_dir*.

    Returns a mapping of model name -> saved path.
    """
    if kind == "login":
        events = load_login_events(csv_path)
        X = login_features(events)
    elif kind == "traffic":
        events = load_traffic_events(csv_path)
        X = traffic_features(events)
    else:
        raise ValueError(f"unknown kind: {kind!r} (expected 'login' or 'traffic')")
    if X.shape[0] == 0:
        raise ValueError(f"no {kind} feature rows could be built from {csv_path}")

    out = Path(out_dir)
    iforest = IsolationForestModel().fit(X)
    auto = AutoencoderModel().fit(X)
    saved = {
        "iforest": iforest.save(out / f"{kind}_iforest.joblib"),
        "autoencoder": auto.save(out / f"{kind}_autoencoder.joblib"),
    }
    log.info(
        "trained %s models on %d rows (%d events): %s",
        kind,
        X.shape[0],
        len(events),
        ", ".join(str(p) for p in saved.values()),
    )
    return saved


def main(argv: list[str] | None = None) -> dict[str, Path]:
    """CLI entry point: parse args, train, and return the saved paths."""
    parser = argparse.ArgumentParser(description="Train SentinelX anomaly models")
    parser.add_argument("--kind", required=True, choices=["login", "traffic"])
    parser.add_argument("--data", required=True, help="input CSV path")
    parser.add_argument("--out", required=True, help="output directory for .joblib files")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    saved = train_models(args.kind, args.data, args.out)
    for name, path in saved.items():
        print(f"saved {name}: {path}")
    return saved


if __name__ == "__main__":
    main()
