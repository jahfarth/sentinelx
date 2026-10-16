# Ingestion

SentinelX ingests logs in two ways:

1. **Shipper agent** (`python -m sentinelx.agent --config agent.yml`) tails log
   files on the monitored host and POSTs batches to `POST /api/v1/ingest`.
2. **Direct API calls** to `POST /api/v1/ingest` with either raw lines or
   already-normalized event dicts.

Every accepted line is normalized into the shared `Event` contract
(`src/sentinelx/common/models.py`), stored in the database, and pushed onto
the Redis list `sentinelx:events` for the worker. Redis is optional: when
`REDIS_URL` is unset or unreachable, queueing is skipped with a warning and
events are still stored.

## Supported log sources

| Source    | Format | Notes |
|-----------|--------|-------|
| `syslog`  | RFC3164 `<pri>MMM DD HH:MM:SS host tag: message` | `event_type=system`, tag becomes `process` |
| `auth`    | OpenSSH auth lines | `Failed`/`Accepted password for [invalid user] USER from IP port P` → `event_type=authentication`, `action=auth_failed`/`auth_success` |
| `nginx`   | HTTP combined log format | `event_type=web`, extracts method/URI/status/user-agent/src IP |
| `apache`  | HTTP combined log format | same as nginx |
| `windows` | Windows Security event JSON | EventIDs 4624/4625 (logon success/failure), 4672 (special logon), 4720 (user created) |
| `netflow` | JSON or CSV flow record | JSON `{"src_ip","src_port","dst_ip","dst_port",...}` or CSV `src_ip,src_port,dst_ip,dst_port,protocol,bytes` → `event_type=network` |

## Normalizer details

Parsers live in `src/sentinelx/ingestion/normalizers.py`:

- `parse_syslog_line(line) -> Event | None` — strict RFC3164 match; the year
  is assumed to be the current year (syslog has none).
- `parse_auth_log_line(line) -> Event | None` — matches sshd password lines,
  including the `invalid user` variant; anything else returns `None`.
- `parse_nginx_line` / `parse_apache_line` — combined format
  `IP - user [10/Oct/2000:13:55:36 -0700] "GET /x HTTP/1.0" 200 123 "-" "UA"`;
  `-` placeholders become `None`; a malformed request string leaves
  `http_method`/`http_uri` empty instead of failing.
- `parse_windows_json(obj) -> Event | None` — accepts both
  `{"Event": {"System": ..., "EventData": ...}}` and flattened payloads;
  `IpAddress` of `"-"` becomes `None`; unknown EventIDs return `None`.
- `normalize(source, host, line) -> Event` — dispatches on `source`; fills in
  `host` when the parser left it empty (web/auth/netflow lines carry no host);
  raises `ValueError` on unknown sources or unparseable lines.
- `normalize_batch(source, host, lines) -> list[Event]` — normalizes many
  lines, logging a warning and skipping lines that fail.

## Agent config reference

```yaml
api_url: http://localhost:8000   # SentinelX API base URL (required)
batch_size: 100                  # flush when a per-source buffer reaches this
batch_interval_s: 5              # flush partial buffers at least this often
host: web-01                     # defaults to socket.gethostname()
files:                           # files to tail
  - path: /var/log/auth.log
    source: auth                 # one of syslog|auth|nginx|apache|windows|netflow
  - path: /var/log/nginx/access.log
    source: nginx
```

Behavior notes:

- The tailer implements `tail -F` semantics: inode changes (log rotation)
  and file truncation are detected and the file is reopened automatically.
- Batches POST to `{api_url}/api/v1/ingest` as `{"host","source","lines"}`.
- Failed POSTs retry with exponential backoff (max 5 retries, 1s base);
  after that the batch is dropped with an error log, never blocking the loop.
- An example config ships at `agents/shipper/agent.example.yml`.
