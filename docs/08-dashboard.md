# Dashboard

Single-page React (Vite + TypeScript) SOC dashboard for SentinelX. Dark theme,
no CSS framework, no router — one page with tab state. Every panel renders
real data from the SentinelX API; every panel has loading, error-with-retry,
and empty states.

## Features

| Tab | Panels |
|-----|--------|
| **Overview** | Stat cards (total events, alerts 24h, critical 24h, top attacker), alerts-by-severity donut, 24h event/critical timeline, top-attacker bars, latest-alerts vertical timeline, live SSE alert feed |
| **Alerts** | Server-side filtered alert table (severity / status / rule_id / src_ip), in-page text search, pagination (`limit`/`offset`), expandable rows with MITRE ATT&CK details, evidence and threat-intel JSON, acknowledge/resolve actions via `PATCH /api/v1/alerts/{id}` |
| **Attackers** | World map (react-leaflet) with circle markers sized by alert volume and popups (IP, alert count, country), top-attacker bar list |
| **Timeline** | Full-width 24h event/critical chart, latest alerts, live feed |

Shared chrome:

- **Health indicator** in the header polls `GET /healthz` every 30 seconds
  (green = API online, red = API offline).
- **⟳ Refresh** button re-fetches every panel.
- **Live alert feed**: SSE subscription to `GET /api/v1/stream` with automatic
  3s reconnect, pause/resume, and severity filter pills; new alerts are
  prepended (deduplicated by id).

### Map coordinates note

The API reports `lat`/`lon` as `0.0` for every attacker (SentinelX performs no
external GeoIP lookup; RFC1918/loopback IPs are labelled "Private"). The map
still renders those markers at 0,0 and says so in a note under the map rather
than hiding them.

## Screenshots

Screenshots are not bundled in the repo. To capture them: run the attack lab
(`docs/10-attack-lab.md` if present), start the stack, open the dashboard, and
screenshot each tab. Suggested captures: Overview (with donut + timeline
populated), Alerts tab with one expanded row, Attackers map, Timeline tab.

## Development

```bash
cd dashboard
npm install
npm run dev      # http://localhost:5173 — /api and /healthz proxied to http://localhost:8000
```

The API must be running (`uvicorn sentinelx.api.main:app --port 8000` or via
docker compose). The vite dev server proxies `/api/*` and `/healthz` to it, so
no CORS or env configuration is needed locally.

### Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `VITE_API_URL` | _(empty)_ | API base URL. Empty = same-origin `/api` (vite dev proxy / nginx handle routing). Set it when the dashboard is served from a different origin than the API, e.g. `VITE_API_URL=http://localhost:8000`. |

Copy `.env.example` to `.env` and adjust. Note: `VITE_*` vars are baked in at
**build** time.

## Production build

```bash
cd dashboard
npm run build    # runs `tsc --noEmit && vite build` -> dist/
```

### Docker / nginx

```bash
# Build context is the REPO ROOT (same convention as services/api):
docker build -f dashboard/Dockerfile -t sentinelx-dashboard .
docker run -p 8080:80 sentinelx-dashboard
```

The image is multi-stage: `node:20-alpine` compiles the app, `nginx:alpine`
serves `dist/` with `dashboard/nginx.conf`:

- `location = /healthz` → `proxy_pass http://api:8000` (API liveness probe)
- `location /api/` → `proxy_pass http://api:8000` — **no trailing slash**, so
  the `/api/` prefix is preserved (the backend serves `/api/v1/...`).
- `location = /api/v1/stream` → same proxy with buffering disabled so SSE
  alerts arrive in real time.
- `location /` → `try_files $uri $uri/ /index.html` SPA fallback.

The upstream host `api` is the docker-compose service name of the FastAPI
backend. In compose the dashboard therefore depends on the `api` service:

```yaml
dashboard:
  build:
    context: .
    dockerfile: dashboard/Dockerfile
  ports:
    - "8080:80"
  depends_on:
    - api
```

## File layout

```
dashboard/
├── Dockerfile          # multi-stage node build -> nginx
├── nginx.conf          # SPA fallback + /api reverse proxy
├── package.json        # react, react-dom, recharts, leaflet, react-leaflet
├── vite.config.ts      # dev proxy /api + /healthz -> localhost:8000
├── tsconfig.json       # strict
├── index.html
├── .env.example
└── src/
    ├── main.tsx        # entrypoint, imports leaflet CSS
    ├── App.tsx         # tab nav, health poll, refresh wiring
    ├── index.css       # hand-rolled dark SOC theme
    ├── lib/api.ts      # typed fetch wrappers, SSE helper, useApiData hook
    └── components/
        ├── ui.tsx            # Skeleton / Spinner / ErrorBox / EmptyState
        ├── StatCards.tsx
        ├── SeverityDonut.tsx
        ├── TimelineChart.tsx
        ├── LiveAlertFeed.tsx
        ├── AlertsTable.tsx
        ├── AttackersMap.tsx
        ├── AttackTimeline.tsx
        └── TopAttackers.tsx
```
