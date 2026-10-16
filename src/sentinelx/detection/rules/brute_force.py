"""Brute-force login detection (T1110.001).

Fires when 5 or more failed authentications are seen from one source IP
inside a 300-second sliding window. ``ctx.count`` records the current event
as part of the count, so the 5th failure is the first one that alerts — and
every further failure while the window stays hot alerts again.
"""

from __future__ import annotations

from typing import Any

from sentinelx.common import Alert, Event
from sentinelx.detection.engine import Rule
from sentinelx.detection.rules import build_alert

FAILED_ACTIONS = frozenset({"auth_failed", "logon_failed"})
WINDOW_S = 300
THRESHOLD = 5


class BruteForceRule(Rule):
    """5+ failed logins from one src_ip within 300s -> possible brute force."""

    id = "SX-BRUTE-FORCE"
    name = "Possible brute-force login activity"
    description = (
        "Multiple failed authentication attempts from a single source IP "
        "inside a short window, consistent with password guessing."
    )
    mitre = {
        "tactic": "Credential Access",
        "technique_id": "T1110.001",
        "technique": "Brute Force: Password Guessing",
    }
    severity = "high"
    base_score = 75

    def evaluate(self, event: Event, ctx: Any) -> list[Alert]:
        if event.event_type != "authentication":
            return []
        if (event.action or "") not in FAILED_ACTIONS:
            return []
        key = f"brute_force:{event.src_ip or 'unknown'}"
        fail_count = ctx.count(key, WINDOW_S)
        if fail_count < THRESHOLD:
            return []
        return [
            build_alert(
                self,
                event,
                title=(
                    f"Possible brute force: {fail_count} failed logins from "
                    f"{event.src_ip or 'unknown'} in {WINDOW_S}s"
                ),
                evidence={"fail_count": fail_count, "window_s": WINDOW_S},
            )
        ]
