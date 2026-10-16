#!/bin/bash
# run_all.sh — orchestrator for the SentinelX attack lab.
#
# Runs the baseline generator first (so the ML model sees normal traffic),
# then the attack scripts in order, with banners and pauses between steps.
# Missing tools are reported as warnings, not hard crashes.
#
# Usage: TARGET=target ./run_all.sh
set -euo pipefail

TARGET="${TARGET:-127.0.0.1}"
export TARGET
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "WARNING: '$1' not found — related steps will be skipped."
        return 1
    fi
    return 0
}

banner() {
    echo
    echo "############################################################"
    echo "# $1"
    echo "############################################################"
}

pause() { sleep "${PAUSE_BETWEEN:-5}"; }

banner "SentinelX attack lab — target: ${TARGET}"
echo "Baseline first (trains the anomaly model), then attacks."

if need python3; then
    banner "[baseline] benign traffic"
    python3 "${SCRIPT_DIR}/05_baseline.py" --rounds 15 --sleep 0.5
    pause
fi

if need nmap; then
    banner "[01] reconnaissance"
    bash "${SCRIPT_DIR}/01_recon.sh"
    pause
fi

if need hydra; then
    banner "[02] brute force (SSH + HTTP login)"
    bash "${SCRIPT_DIR}/02_bruteforce.sh"
    pause
fi

if need sqlmap; then
    banner "[03] SQL injection"
    bash "${SCRIPT_DIR}/03_sqli.sh"
    pause
else
    echo "WARNING: sqlmap not installed — skipping [03] SQL injection step."
fi

banner "[04] reflected XSS"
python3 "${SCRIPT_DIR}/04_xss.py"
pause

banner "Lab run complete — check the dashboard / alerts API for detections."
