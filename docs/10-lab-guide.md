# 10 — Lab Guide

A hands-on walkthrough of the SentinelX attack lab: start the vulnerable
target, run each attack, and watch detections land in the dashboard and
the API.

> **Safety:** the lab target (`lab/target`) is intentionally vulnerable
> (SQL injection, reflected XSS, weak credentials). Run it only inside
> the isolated compose `lab` profile on a machine/network you control.
> Never point the attack scripts at anything but your own lab container.

## 1. Start the stack and the target

```bash
cd ~/workspace/sentinelx   # repo root
cp .env.example .env        # first time only

docker compose up -d --build
docker compose --profile lab up -d target

curl http://localhost:8000/healthz   # expect {"status":"ok", ...}
```

Sanity-check the target from the host (compose publishes its ports):

```bash
curl -s http://localhost:5000/ | head -5
```

## 2. Generate a benign baseline

The ML anomaly detector compares live traffic against "normal", so seed
normal first:

```bash
cd lab/attacks
./05_baseline.py --rounds 20 --sleep 1
```

This loads the index page, performs innocent searches, and logs in with
valid credentials.

## 3. Run each attack

You can run the full scenario with `./run_all.sh`, or step through the
scripts individually to watch detections arrive one at a time. All
scripts honor `TARGET` (default `127.0.0.1`; use `TARGET=target` when
running from inside the lab network).

### 01 — Reconnaissance

```bash
./01_recon.sh
```

nmap sweeps every port and fingerprints services. Expect
**SX-PORT-SCAN** (T1046, medium) once the scan touches enough distinct
ports inside the rule window.

### 02 — Brute force (SSH + HTTP login)

```bash
./02_bruteforce.sh
```

Hydra guesses passwords against SSH (`labuser` on port 2222) and the
Flask login form (`user`/`pass` fields on port 5000). Repeated failed
logins from one source IP fire **SX-BRUTE-FORCE** (T1110.001, high).
(Hydra exits non-zero when nothing matches — the script treats that as
normal.)

### 03 — SQL injection probing

```bash
./03_sqli.sh     # requires sqlmap: https://sqlmap.org/
```

sqlmap fuzzes `POST /login` with classic payloads (`' OR 1=1 --`,
`UNION SELECT`, …). The payload signatures fire **SX-WEB-ATTACK**
(T1190, high). If you don't have sqlmap, try a manual probe:

```bash
curl -s -X POST http://localhost:5000/login \
  --data-urlencode "user=admin' OR '1'='1" \
  --data-urlencode "pass=x" | head -3
```

### 04 — Reflected XSS probing

```bash
python3 04_xss.py
```

Sends `<script>alert(1)</script>`-style payloads to `/search?q=` and
reports which were reflected verbatim. Each reflected payload fires
**SX-WEB-ATTACK** (T1190, high).

## 4. What to look for in the dashboard / API

Open the dashboard at http://localhost and watch the alerts feed, or
query the API directly:

```bash
# newest alerts
curl -s http://localhost:8000/api/v1/alerts | python3 -m json.tool | head -40

# only high-severity alerts
curl -s "http://localhost:8000/api/v1/alerts?severity=high"

# alerts from a single rule
curl -s "http://localhost:8000/api/v1/alerts?rule_id=SX-WEB-ATTACK"

# alerts from your attacker IP (e.g. the docker bridge address)
curl -s "http://localhost:8000/api/v1/alerts?src_ip=172.18.0.1"

# overview + timeline for the attack window
curl -s http://localhost:8000/api/v1/stats/overview
curl -s "http://localhost:8000/api/v1/stats/timeline?hours=2"

# live stream (Server-Sent Events)
curl -N http://localhost:8000/api/v1/stream
```

(Through the dashboard's nginx these are also reachable at
`http://localhost/api/v1/...`.)

For each alert, verify:

1. **Rule id** matches the expected mapping (`lab/README.md` table).
2. **MITRE technique** is attached (T1046 / T1110.001 / T1190).
3. **Severity** matches expectations (medium for recon, high for the
   rest).
4. **Evidence** names the offending IP, port count, or matched payload.

Don't be surprised if the ML anomaly detector fires extra alerts during
the attack bursts — that means the baseline comparison is working.

## 5. Capturing screenshots

Good shots for the portfolio README or a demo:

1. Dashboard alerts list mid-attack (run `./run_all.sh`, refresh).
2. An alert detail view showing rule id, MITRE technique, and evidence.
3. The stats timeline spiking during the attack window vs. the flat
   baseline before it.
4. Terminal output of `04_xss.py` next to the fired SX-WEB-ATTACK alert.

## 6. Teardown

```bash
docker compose --profile lab down   # stop/remove the vulnerable target
docker compose down                 # stop the core stack
```
