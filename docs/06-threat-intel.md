# Threat Intelligence

How SentinelX enriches alert source IPs with AbuseIPDB, VirusTotal and
AlienVault OTX: the provider clients, the 24h Redis cache, the score
boost, and the offline mock mode.

## Architecture

```
alert.src_ip --> enrich_ip(ip) --> verdict dict (always has int "boost")
                    |
                    +-- private/non-global IP? -> short-circuit, no network
                    +-- SENTINELX_INTEL_MOCK=1? -> deterministic fixture
                    +-- else: query each configured provider (cached 24h),
                              combine into malicious/boost verdict
```

`src/sentinelx/intel/enrich.py::enrich_ip` is the pipeline entry point
(`worker/pipeline.py` calls it for public `src_ip`s and caches the
result in-process for 24h). Every provider lookup is individually
guarded: a missing API key skips that source, a failed request logs a
warning — enrichment never breaks the pipeline.

## Providers

| module | endpoint | auth | parsed fields |
|---|---|---|---|
| `intel/abuseipdb.py` | `GET https://api.abuseipdb.com/api/v2/check` (`ipAddress`, `maxAgeInDays=90`) | `Key` header | `abuse_score` (abuseConfidenceScore), `total_reports`, `country` |
| `intel/virustotal.py` | `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}` | `x-apikey` header | `vt_malicious` (last_analysis_stats.malicious), `vt_reputation` |
| `intel/otx.py` | `GET https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general` | `X-OTX-API-KEY` header | `otx_pulses` (pulse_info.count), `otx_reputation` |

API keys come from the environment: `ABUSEIPDB_API_KEY`,
`VIRUSTOTAL_API_KEY`, `OTX_API_KEY`. All calls use `httpx` with a
10-second timeout; non-200 responses raise `intel.base.IntelError`.

## Caching

`intel/base.py::CachedIntelClient` wraps provider calls with an optional
Redis cache (`SETEX`/`GET` with JSON, 24h TTL, keys like
`sentinelx:intel:abuseipdb:{ip}`). Redis comes from `REDIS_URL`; when it
is unset or unreachable the client logs a warning and fetches directly —
Redis is optional everywhere, never required.

## Scoring boost

`enrich_ip` returns a dict that always includes:

- `boost: int` — added to the alert score by the worker
  (`compute_score` clamps the total to 0–100)
- `malicious: bool`
- `abuse_score`, `vt_positives`, `otx_pulses`
- `sources: list[str]` — providers that actually answered
- per-source details under `{provider}_detail`

Verdict logic:

- `malicious = abuse_score >= 75 or vt_positives >= 5 or otx_pulses >= 3`
- `boost = 25` if malicious, else `10` if suspicious
  (`abuse_score >= 25` or `vt_positives >= 1`), else `0`

Private, loopback and other non-global IPs short-circuit to
`{"private": True, "boost": 0, ...}` with zero network calls.

## Mock mode

Set `SENTINELX_INTEL_MOCK=1` for a deterministic offline fixture
(`boost: 0`, `malicious: False`, `sources: ["mock"]`) — used by the
test-suite and local demos so no API keys or network are needed.
