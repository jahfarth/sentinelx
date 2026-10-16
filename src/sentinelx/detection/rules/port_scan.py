"""Port-scan detection (T1046).

Fires when a single source IP touches 15 or more *distinct* destination ports
inside a 60-second sliding window. Distinctness comes from
``ctx.sadd_window``, so hammering one port never trips the rule.
"""

from __future__ import annotations

from typing import Any

from sentinelx.common import Alert, Event
from sentinelx.detection.engine import Rule
from sentinelx.detection.rules import build_alert

WINDOW_S = 60
THRESHOLD = 15


class PortScanRule(Rule):
    """15+ distinct dst_ports from one src_ip within 60s -> possible port scan."""

    id = "SX-PORT-SCAN"
    name = "Possible port scan"
    description = (
        "A single source IP probed many distinct destination ports in a short "
        "window, consistent with network service discovery."
    )
    mitre = {
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique": "Network Service Discovery",
    }
    severity = "medium"
    base_score = 55

    def evaluate(self, event: Event, ctx: Any) -> list[Alert]:
        if event.dst_port is None:
            return []
        if event.src_ip is None:
            return []
        key = f"port_scan:{event.src_ip}"
        port_count = ctx.sadd_window(key, str(event.dst_port), WINDOW_S)
        if port_count < THRESHOLD:
            return []
        return [
            build_alert(
                self,
                event,
                title=(
                    f"Possible port scan: {port_count} distinct ports probed by "
                    f"{event.src_ip} in {WINDOW_S}s"
                ),
                evidence={"port_count": port_count, "window_s": WINDOW_S},
            )
        ]
