"""Deterministic synthetic training-data generators.

The CSVs mirror the formats consumed by ``sentinelx.ml.train``:

* login CSV columns: ``timestamp,host,user,src_ip,success``
* traffic CSV columns: ``timestamp,host,src_ip,http_method,http_uri,http_status``

Normal rows model business-hours logins with few failures (or steady GET
200 traffic); anomalous rows model 3am logins with many failures from new
IPs (or request bursts with 404/500 ratios and high-entropy URIs).
Everything is drawn from ``numpy.random.default_rng(seed)`` so output is
reproducible for a given seed.
"""

from __future__ import annotations

import csv
import string
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np

_LOGIN_FIELDS = ["timestamp", "host", "user", "src_ip", "success"]
_TRAFFIC_FIELDS = ["timestamp", "host", "src_ip", "http_method", "http_uri", "http_status"]

_NORMAL_URIS = ["/", "/index.html", "/login", "/api/status", "/static/app.js", "/favicon.ico"]
_ATTACK_URIS = [
    "/wp-admin",
    "/.git/config",
    "/phpmyadmin",
    "/admin.php",
    "/backup.sql",
    "/server-status",
]

_BASE_TIME = datetime(2026, 10, 1, 0, 0, 0, tzinfo=UTC)


def _ts(rng: np.random.Generator, hour: int) -> str:
    """ISO timestamp on a deterministic day with a random minute/second."""
    day = int(rng.integers(0, 14))
    minute = int(rng.integers(0, 60))
    second = int(rng.integers(0, 60))
    moment = _BASE_TIME + timedelta(days=day, hours=hour, minutes=minute, seconds=second)
    return moment.isoformat()


def _burst_ts(rng: np.random.Generator, day: int, hour: int, spread_min: int = 10) -> str:
    """ISO timestamp clustered inside a short burst window (attack traffic)."""
    minute = int(rng.integers(0, spread_min))
    second = int(rng.integers(0, 60))
    moment = _BASE_TIME + timedelta(days=day, hours=hour, minutes=minute, seconds=second)
    return moment.isoformat()


def _write_csv(path: str | Path, fields: list[str], rows: list[dict[str, object]]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return path


def generate_login_csv(
    path: str | Path, n_normal: int = 2000, n_anomalous: int = 50, seed: int = 42
) -> Path:
    """Write a synthetic login CSV to *path* and return the path.

    Normal rows: business-hours (08:00-18:00) logins, 5% failures. Each
    row models an individual login (one event per user), so the
    per-(host, user) aggregates used in training match the single-event
    vectors built at scoring time. Anomalous rows: brute-force bursts —
    a handful of attacker users each making many failed logins at ~03:00
    from previously unseen IPs.
    """
    rng = np.random.default_rng(seed)
    rows: list[dict[str, object]] = []

    # One login per user: aggregates then describe individual logins,
    # which is exactly what score_event() builds vectors for.
    normal_users = [f"user{i:04d}" for i in range(max(n_normal, 1))]
    normal_hosts = [f"ws{i:02d}" for i in range(10)]
    normal_ips = [f"10.0.1.{i}" for i in range(1, 31)]
    for i in range(n_normal):
        user = normal_users[i % len(normal_users)]
        rows.append(
            {
                "timestamp": _ts(rng, int(rng.integers(8, 18))),
                "host": str(rng.choice(normal_hosts)),
                "user": user,
                "src_ip": str(rng.choice(normal_ips)),
                "success": 0 if rng.random() < 0.05 else 1,
            }
        )

    # Brute-force bursts: a few attackers, many failed attempts each.
    n_attackers = min(5, n_anomalous)
    for a in range(n_attackers):
        attempts = n_anomalous // n_attackers + (1 if a < n_anomalous % n_attackers else 0)
        attacker_ip = f"198.51.100.{(a % 200) + 1}"
        for _ in range(attempts):
            rows.append(
                {
                    "timestamp": _ts(rng, 3),
                    "host": str(rng.choice(normal_hosts)),
                    "user": f"attacker{a:03d}",
                    "src_ip": attacker_ip,
                    "success": 0 if rng.random() < 0.8 else 1,
                }
            )

    return _write_csv(path, _LOGIN_FIELDS, rows)


def _random_uri(rng: np.random.Generator, length: int) -> str:
    alphabet = string.ascii_letters + string.digits + "%?&=./-_"
    return "/" + "".join(rng.choice(list(alphabet)) for _ in range(length))


def generate_traffic_csv(
    path: str | Path, n_normal: int = 2000, n_anomalous: int = 50, seed: int = 42,
    n_hosts: int = 12,
) -> Path:
    """Write a synthetic web-traffic CSV to *path* and return the path.

    Normal rows: steady ``GET`` requests returning 200 for a handful of
    known URIs, spread over ``n_hosts`` hosts. Anomalous rows: a burst
    from one host inside a ~10-minute window with high 404/500 ratios,
    scanner-style URIs and high-entropy random URIs.
    """
    rng = np.random.default_rng(seed)
    rows: list[dict[str, object]] = []

    hosts = [f"web{i:02d}" for i in range(n_hosts)]
    # Each host serves a small subset of URIs, like a real web app.
    host_uris = {
        host: rng.choice(_NORMAL_URIS, size=int(rng.integers(2, 4)), replace=False).tolist()
        for host in hosts
    }
    for _ in range(n_normal):
        host = str(rng.choice(hosts))
        rows.append(
            {
                "timestamp": _ts(rng, int(rng.integers(6, 22))),
                "host": host,
                "src_ip": f"203.0.113.{int(rng.integers(1, 100))}",
                "http_method": "GET",
                "http_uri": str(rng.choice(host_uris[host])),
                "http_status": 200 if rng.random() < 0.98 else 404,
            }
        )

    burst_day = int(rng.integers(0, 14))
    burst_hour = int(rng.integers(0, 24))
    for _ in range(n_anomalous):
        host = "web99"
        style = rng.random()
        if style < 0.4:
            uri = str(rng.choice(_ATTACK_URIS))
            status = 404
        elif style < 0.7:
            uri = _random_uri(rng, int(rng.integers(24, 64)))
            status = 404
        else:
            uri = str(rng.choice(_NORMAL_URIS))
            status = 500
        rows.append(
            {
                "timestamp": _burst_ts(rng, burst_day, burst_hour),
                "host": host,
                "src_ip": "198.51.100.66",
                "http_method": "GET",
                "http_uri": uri,
                "http_status": status,
            }
        )

    return _write_csv(path, _TRAFFIC_FIELDS, rows)
