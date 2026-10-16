# API Reference

Base URL: `http://localhost:8000`. All responses are JSON.

## `GET /healthz`

Liveness probe.

```json
{ "status": "ok" }
```

## `POST /api/v1/ingest`

Normalize and store events, queue them for the worker.

**Request** — raw lines shape:

```json
{
  "host": "web-01",
  "source": "nginx",
  "lines": ["203.0.113.7 - - [16/Oct/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\""]
}
```

**Request** — pre-normalized events shape:

```json
{
  "events": [
    {
      "timestamp": "2026-10-16T10:00:00",
      "host": "web-01",
      "source": "syslog",
      "event_type": "system",
      "message": "something happened"
    }
  ]
}
```

**Response** `200`:

```json
{ "received": 1, "normalized": 1 }
```

Unknown `source` values yield `422`. Unparseable lines are skipped (counted
in `received` but not `normalized`).

## `GET /api/v1/alerts`

List alerts, newest first. Query params: `severity`, `status`, `rule_id`,
`src_ip` (all optional filters), `limit` (default 50, max 500), `offset`
(default 0).

```json
{
  "total": 2,
  "alerts": [
    {
      "id": "9f2c...",
      "timestamp": "2026-10-16T10:05:00",
      "rule_id": "brute-force",
      "rule_name": "SSH brute force",
      "title": "Possible brute force against web-01",
      "description": "25 failed logins from 203.0.113.7 in 5 minutes",
      "severity": "high",
      "score": 72,
      "mitre": {"tactic": "Credential Access", "technique_id": "T1110.001", "technique": "Brute Force: Password Guessing"},
      "src_ip": "203.0.113.7",
      "dst_ip": null,
      "host": "web-01",
      "user": "root",
      "evidence": {"failures": 25},
      "intel": {},
      "status": "new"
    }
  ]
}
```

## `GET /api/v1/alerts/{id}`

Single alert. `404` when the id does not exist.

## `PATCH /api/v1/alerts/{id}`

Update alert status.

```json
{ "status": "acknowledged" }
```

`status` must be one of `new`, `acknowledged`, `resolved` — anything else
yields `422`. `404` when the id does not exist. Returns the updated alert.

## `GET /api/v1/stats/overview`

Dashboard counters.

```json
{
  "total_events": 12345,
  "total_alerts_24h": 37,
  "critical_24h": 2,
  "top_attackers": [{"ip": "203.0.113.7", "count": 21}],
  "alerts_by_severity": {"critical": 2, "high": 9, "medium": 20, "low": 6}
}
```

## `GET /api/v1/stats/timeline?hours=24`

Hourly buckets for the last `hours` hours (1–168).

```json
{
  "buckets": [
    {"ts": "2026-10-16T09:00:00", "count": 412, "critical": 1},
    {"ts": "2026-10-16T10:00:00", "count": 388, "critical": 0}
  ]
}
```

`count` is events per bucket; `critical` is critical-severity alerts per bucket.

## `GET /api/v1/attackers?limit=20`

Top attacker source IPs by alert count. Geo is coarse and local-only:
RFC1918/loopback addresses report `"Private"`, everything else `"Unknown"`;
coordinates are always `0.0` (no external lookup is performed).

```json
{
  "attackers": [
    {"ip": "203.0.113.7", "alerts": 21, "country": "Unknown", "lat": 0.0, "lon": 0.0},
    {"ip": "10.0.0.5", "alerts": 3, "country": "Private", "lat": 0.0, "lon": 0.0}
  ]
}
```

## `GET /api/v1/stream`

Server-sent events stream of new alerts. Subscribes to the Redis channel
`sentinelx:alerts`; each published alert arrives as an SSE `data` event.
When Redis is unavailable the endpoint sends a comment heartbeat and closes
gracefully.

```text
event: message
data: {"id": "9f2c...", "rule_id": "brute-force", ...}
```
