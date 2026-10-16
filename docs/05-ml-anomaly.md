# ML Anomaly Detection

How SentinelX scores events for anomalous behavior: feature extraction,
the two detector models, the offline training workflow, and how the
worker pipeline consumes the scores.

## Architecture

```
Event --> score_event(event) --> float in [0, 1]
            |
            +-- pick feature path by event_type/source
            +-- build single-row feature vector
            +-- average the trained models for that kind
```

`src/sentinelx/ml/scoring.py::score_event` is the pipeline entry point
(`worker/pipeline.py` calls it per event). Models are loaded lazily from
`SENTINELX_MODEL_DIR` (default `./models`) and cached at module level.
When no trained models exist for the event's kind, it logs at debug
level and returns `0.0` — the pipeline then skips ML for that event.

Feature-path routing:

| event_type | source              | kind    |
|------------|---------------------|---------|
| authentication | any             | login   |
| web        | any                 | traffic |
| other      | nginx, apache       | traffic |
| other      | auth, windows, syslog, netflow | login |

## Features

`src/sentinelx/ml/features.py`, pure NumPy.

**Login** — one row per `(host, user)` aggregate:

| column | formula |
|---|---|
| `hour_sin`, `hour_cos` | circular encoding of the group's mean login hour `h`: `sin(2πh/24)`, `cos(2πh/24)` |
| `n_failed_last_20` | failed authentications among the group's last 20 events (`action` in `{login_failed, auth_failed, failed, failure}` or "fail" in the message) |
| `unique_src_ips` | distinct `src_ip` count in the group |
| `is_unusual_hour` | 1.0 when the mean hour is before 06:00 or at/after 22:00, else 0.0 |

**Traffic** — one row per `host`:

| column | formula |
|---|---|
| `req_rate` | events per minute over the group's span (`n / (span_seconds / 60)`, span floored at 1s) |
| `err_ratio` | fraction of events with `http_status >= 400` |
| `uri_entropy` | Shannon entropy of the character distribution of all `http_uri`s concatenated |
| `unique_uris` | distinct `http_uri` count |

At scoring time there is no group history, so `single_login_vector` /
`single_traffic_vector` build the honest one-event row (event hour,
`n_failed` = 1 if the event itself failed, `unique_src_ips` = 1, etc.).
The sample-data generators model individual logins, so training rows
and serving rows come from the same distribution.

## Models

`src/sentinelx/ml/models.py`. Both expose `fit(X)`, `score(X) -> np.ndarray`
in `[0, 1]` (higher = more anomalous), and joblib `save(path)` /
`load(path)` classmethods.

- **IsolationForestModel** — sklearn `IsolationForest`; the raw
  `decision_function` (higher = more normal) is min-max scaled on the
  *training* scores, then flipped: `1 - clip((df - min) / (max - min))`.
- **AutoencoderModel** — sklearn `MLPRegressor(hidden_layer_sizes=(32, 16, 32),
  max_iter=500)` trained to reconstruct its input (features are
  standardized internally with a `StandardScaler` fit on the training
  matrix, persisted with the model). Anomaly score = per-row MSE
  reconstruction error divided by the 95th percentile of the training
  errors, clipped to `[0, 1]`.

`score_event` averages the available models for the event's kind.

## Training workflow

Generate synthetic data, then train:

```bash
python -m sentinelx.ml.sample_data  # (or import generate_login_csv / generate_traffic_csv)
python -m sentinelx.ml.train --kind login   --data data/login.csv   --out models/
python -m sentinelx.ml.train --kind traffic --data data/traffic.csv --out models/
```

The CLI (`train_models(kind, csv_path, out_dir)`) parses the CSV into
`Event`s, builds the aggregate features, fits both models, and writes
`<kind>_iforest.joblib` + `<kind>_autoencoder.joblib` into `--out`.

Login CSV columns: `timestamp,host,user,src_ip,success`.
Traffic CSV columns: `timestamp,host,src_ip,http_method,http_uri,http_status`.

`generate_login_csv(path, n_normal=2000, n_anomalous=50, seed=42)`:
normal = business-hours logins, 5% failures, one login per user;
anomalies = brute-force bursts (a few attackers × many failed 03:00
logins from new IPs). `generate_traffic_csv(...)`: normal = steady GET
200s (each host serves a small URI subset); anomalies = a 10-minute
burst from one host with 404/500 ratios, scanner URIs and high-entropy
random URIs. Both are deterministic for a given `seed`.

## Scoring integration

In `worker/pipeline.py`:

1. Every event is scored; the score lands in `alert.evidence["ml_score"]`
   for rule-fired alerts.
2. When **no** rule fired and the score is `>= 0.7`
   (`ML_ANOMALY_THRESHOLD`), the pipeline creates a standalone
   `ml-anomaly` alert (MITRE T1078, severity medium, score 50).

Typical scores with the sample-data models: ~0.13 for a normal
business-hours login, ~0.96 for a 3am brute-force login, ~0.63 for
normal web traffic, ~0.73+ for scan bursts.
