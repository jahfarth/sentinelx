"""Builtin Python detection rules for SentinelX.

Each rule is a :class:`~sentinelx.detection.engine.Rule` subclass. Stateful
correlation goes through the duck-typed ``ctx`` (``count`` / ``sadd_window``);
the shared :func:`build_alert` helper keeps Alert construction uniform so
``score_to_level(score) == severity`` always holds.
"""

from __future__ import annotations

from typing import Any

from sentinelx.common import Alert, Event
from sentinelx.common.severity import compute_score, score_to_level

__all__ = ["BUILTIN_RULES", "build_alert"]


def build_alert(
    rule: Any,
    event: Event,
    title: str,
    evidence: dict[str, Any],
    description: str = "",
    intel: dict[str, Any] | None = None,
) -> Alert:
    """Build an :class:`Alert` for *rule* firing on *event*.

    The score comes from ``compute_score(rule.base_score)`` and the severity
    is derived from the score via ``score_to_level``, keeping the two
    consistent by construction.
    """
    score = compute_score(rule.base_score)
    return Alert(
        timestamp=event.timestamp,
        rule_id=rule.id,
        rule_name=rule.name,
        title=title,
        description=description or rule.description,
        severity=score_to_level(score),  # type: ignore[arg-type]
        score=score,
        mitre=dict(rule.mitre),
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        host=event.host,
        user=event.user,
        evidence=evidence,
        intel=intel or {},
    )


# Imported after build_alert is defined: rule modules import the helper
# from this package while it is still initializing.
from sentinelx.detection.rules.brute_force import BruteForceRule  # noqa: E402
from sentinelx.detection.rules.port_scan import PortScanRule  # noqa: E402
from sentinelx.detection.rules.priv_esc import PrivEscRule  # noqa: E402
from sentinelx.detection.rules.web_attack import WebAttackRule  # noqa: E402

#: The rules loaded by DetectionEngine when no explicit rule list is given.
BUILTIN_RULES: list[Any] = [
    BruteForceRule(),
    PortScanRule(),
    WebAttackRule(),
    PrivEscRule(),
]

__all__ += ["BruteForceRule", "PortScanRule", "PrivEscRule", "WebAttackRule"]
