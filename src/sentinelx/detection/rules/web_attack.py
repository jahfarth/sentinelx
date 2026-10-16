"""Web attack detection (T1190) — single-event pattern matching.

Scans ``http_uri``, ``user_agent`` and ``message`` for SQL injection, XSS and
path-traversal signatures. The first matching category wins (SQLi > XSS >
traversal) and the alert title names the ``attack_type`` (``sqli`` | ``xss`` |
``traversal``). Evidence carries the regex that fired (``pattern``) and the
exact substring it caught (``matched``).
"""

from __future__ import annotations

import re
from typing import Any

from sentinelx.common import Alert, Event
from sentinelx.detection.engine import Rule
from sentinelx.detection.rules import build_alert

# (attack_type, compiled regex) — order defines precedence on multi-match.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "sqli",
        re.compile(
            r"union\s+select"
            r"|'\s*or\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+"
            r"|information_schema"
            r"|--\s"
            r"|;\s*drop\s+table"
            r"|exec\s*\("
            r"|benchmark\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "xss",
        re.compile(
            r"<script"
            r"|javascript:"
            r"|onerror\s*="
            r"|<img[^>]*onerror"
            r"|alert\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "traversal",
        re.compile(r"\.\./|%2e%2e", re.IGNORECASE),
    ),
]

_FIELD_LABELS = (("http_uri", "http_uri"), ("user_agent", "user_agent"), ("message", "message"))


class WebAttackRule(Rule):
    """Malicious payload signatures in HTTP fields -> web attack probe."""

    id = "SX-WEB-ATTACK"
    name = "Web attack probe detected"
    description = (
        "HTTP request fields contain SQL injection, cross-site scripting or "
        "path traversal signatures, consistent with exploitation of a "
        "public-facing application."
    )
    mitre = {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
    }
    severity = "high"
    base_score = 80

    def evaluate(self, event: Event, ctx: Any) -> list[Alert]:
        for attack_type, pattern in _PATTERNS:
            for attr, label in _FIELD_LABELS:
                value = getattr(event, attr, None)
                if not value:
                    continue
                found = pattern.search(str(value))
                if found:
                    return [
                        build_alert(
                            self,
                            event,
                            title=f"[{attack_type}] Possible web attack probe from "
                            f"{event.src_ip or 'unknown'}",
                            evidence={
                                "attack_type": attack_type,
                                "pattern": pattern.pattern,
                                "matched": found.group(0),
                                "field": label,
                            },
                        )
                    ]
        return []
