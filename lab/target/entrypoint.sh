#!/bin/bash
# Entrypoint for the lab target container: start sshd, then the Flask app.
# LAB USE ONLY — this box is intentionally weak (labuser:lab12345 over SSH).
set -euo pipefail

echo "[lab-target] starting sshd..."
service ssh start

echo "[lab-target] initializing database..."
python3 -c "import app; app.init_db()"

echo "[lab-target] starting Flask app on 0.0.0.0:5000..."
exec python3 app.py
