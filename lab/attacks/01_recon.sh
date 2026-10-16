#!/bin/bash
# 01_recon.sh — port/service reconnaissance against the lab target.
# Expected detection: SX-PORT-SCAN (T1046, medium).
#
# Usage: TARGET=target ./01_recon.sh
# (default TARGET=127.0.0.1; inside the compose lab network use TARGET=target)
set -euo pipefail

TARGET="${TARGET:-127.0.0.1}"

echo "=== [01] Recon: nmap service scan against ${TARGET} ==="
nmap -sV -p- --open -T4 "$TARGET"
echo "=== [01] done ==="
