#!/usr/bin/env python3
"""05_baseline.py — benign traffic generator for training data.

Hits the lab target the way a normal user would: loads the index page,
does a few innocent searches, and performs a couple of valid logins.
Run this BEFORE the attack scripts so the ML anomaly model learns what
"normal" looks like for this target.

Usage: TARGET=target python3 05_baseline.py [--rounds N] [--sleep S]
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time

import requests

TARGET = os.environ.get("TARGET", "127.0.0.1")
BASE = f"http://{TARGET}:5000"

BENIGN_SEARCHES = [
    "hello",
    "welcome",
    "lab demo",
    "sentinelx",
    "test page",
]
VALID_LOGINS = [
    ("admin", "password123"),
    ("labuser", "lab12345"),
]


def benign_round(session: requests.Session) -> None:
    session.get(f"{BASE}/", timeout=10)
    session.get(f"{BASE}/search", params={"q": random.choice(BENIGN_SEARCHES)}, timeout=10)  # noqa: S311
    user, password = random.choice(VALID_LOGINS)  # noqa: S311
    session.post(f"{BASE}/login", data={"user": user, "pass": password}, timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate benign lab traffic.")
    parser.add_argument("--rounds", type=int, default=20, help="benign rounds to run")
    parser.add_argument("--sleep", type=float, default=1.0, help="seconds between rounds")
    args = parser.parse_args()

    session = requests.Session()
    print(f"=== [05] Baseline: {args.rounds} benign rounds against {BASE} ===")
    ok = 0
    for i in range(1, args.rounds + 1):
        try:
            benign_round(session)
            ok += 1
        except requests.RequestException as exc:
            print(f"  round {i}: ERROR {exc}")
        if i < args.rounds:
            time.sleep(args.sleep)
    print(f"=== [05] done: {ok}/{args.rounds} rounds succeeded ===")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
