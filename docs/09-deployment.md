# 09 — Deployment

How to run SentinelX with Docker Compose, from laptop dev to a small
production host.

## Services

| Service   | Image / build                              | Ports | Depends on            | Notes                                  |
|-----------|--------------------------------------------|-------|-----------------------|----------------------------------------|
| postgres  | `postgres:15`                              | —     | —                     | Persistent volume `pgdata`; `pg_isready` healthcheck |
| redis     | `redis:7`                                  | —     | —                     | AOF enabled; `redis-cli ping` healthcheck |
| api       | `services/api/Dockerfile` (context: repo root) | `8000:8000` | postgres, redis (healthy) | FastAPI; serves the UI via dashboard proxy too |
| worker    | `services/worker/Dockerfile` (context: repo root) | — | redis, postgres (healthy) | Detection/response pipeline consumer |
| dashboard | `dashboard/Dockerfile` (context: repo root) | `80:80` | api | React SPA behind nginx; proxies `/api/` and `/healthz` to the api service |
| target    | `lab/target`                               | `5000:5000`, `2222:22` | — | **Lab profile only** (`--profile lab`); intentionally vulnerable |

## Quick start

```bash
cp .env.example .env        # fill in anything you need
docker compose up -d --build
curl http://localhost:8000/healthz
```

Dashboard: http://localhost — API: http://localhost:8000

Bring up the attack-lab target as well:

```bash
docker compose --profile lab up -d target
```

## Environment variables

Loaded from `.env` (`env_file: .env` on api/worker); compose-level
defaults apply when a variable is unset.

| Variable               | Default (compose)                                                | Purpose                                    |
|------------------------|------------------------------------------------------------------|--------------------------------------------|
| `DATABASE_URL`         | `postgresql+psycopg2://sentinelx:sentinelx@postgres:5432/sentinelx` | SQLAlchemy URL for the API/worker         |
| `REDIS_URL`            | `redis://redis:6379/0`                                           | Queue/cache URL for the API/worker        |
| `SENTINELX_INTEL_MOCK` | `1`                                                              | `1` = mock threat-intel enrichment (no API keys needed) |
| `SENTINELX_DRY_RUN`    | `1`                                                              | `1` = response actions are logged, not executed |
| `SLACK_WEBHOOK_URL`    | —                                                                | Slack alert notifications                  |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | —                                                  | Telegram alert notifications               |
| `VITE_API_URL`         | `http://localhost:8000`                                          | API base URL baked into the dashboard build |

See `.env.example` for the full list. **Never commit a real `.env`.**

## Profiles

- Default profile: `postgres`, `redis`, `api`, `worker`, `dashboard`.
- `lab` profile: adds `target`, the intentionally vulnerable box used by
  `lab/attacks`. It never starts unless you ask:
  `docker compose --profile lab up -d target`.

## Healthchecks

- `postgres`: `pg_isready -U sentinelx -d sentinelx` every 5s (10s start
  grace).
- `redis`: `redis-cli ping` every 5s (5s start grace).
- `api` and `worker` wait on both via
  `depends_on: { condition: service_healthy }`, so they only start once
  the data stores are actually ready — no crash-looping on boot.

## Logs

```bash
docker compose logs -f api worker        # follow service logs
docker compose logs --tail=100 postgres  # last 100 lines
docker compose ps                        # service status
```

## Scaling the worker

The worker is stateless apart from Redis/Postgres, so it scales
horizontally:

```bash
docker compose up -d --scale worker=3
```

Give each worker enough Redis connection headroom and watch queue depth
in the dashboard when tuning the replica count.

## Production notes

- **Secrets:** generate a strong `POSTGRES_PASSWORD` (don't keep the dev
  default) and inject it via a secrets manager or an env file with
  restricted permissions — never bake secrets into images.
- **Postgres backups:** schedule regular `pg_dump` against the `pgdata`
  volume, e.g. a nightly cron writing to off-host storage, and test
  restores.
- **TLS:** terminate HTTPS in front of the stack (reverse proxy or LB);
  the compose file serves plain HTTP for dev.
- **Dry-run off:** set `SENTINELX_DRY_RUN=0` only when you have reviewed
  the automated-response actions (`docs/07-response.md`) and accept them
  running real commands (e.g. iptables) on the host.
- **Intel keys:** unset `SENTINELX_INTEL_MOCK` (or set to `0`) and provide
  real `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` / `OTX_API_KEY` for live
  enrichment.
- **Updates:** pin image digests for `postgres:15` / `redis:7` /
  `nginx:alpine` in production and rebuild on a cadence.
