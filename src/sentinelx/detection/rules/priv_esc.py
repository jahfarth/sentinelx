"""Privilege-escalation detection (T1068).

Three independent signals, any of which fires the rule:

* a ``sudo``/``su`` process whose message shows an interactive root shell
  (``-i``, ``su -`` or ``sudo su``) — normal invocations like ``sudo ls``
  do not match;
* Windows Security event 4672 (special privileges assigned at logon), read
  from ``event.raw["EventID"]`` — the Sigma rule
  ``windows_special_privileges_4672``-style coverage lives in
  ``sigma_rules/``; this Python rule covers the same signal for pipelines
  that do not run the Sigma set;
* an explicit ``action == "privilege_escalation"`` normalized by upstream
  parsers.

Note on severity: the base score is 85, and ``score_to_level(85)`` is
``"critical"``, so the rule reports ``critical`` (not ``high``) to keep
``severity`` consistent with ``score``.
"""

from __future__ import annotations

from typing import Any

from sentinelx.common import Alert, Event
from sentinelx.detection.engine import Rule
from sentinelx.detection.rules import build_alert

_PRIV_ESCALATION_EVENT_ID = 4672
_SHELL_PROCESSES = frozenset({"sudo", "su"})
_SHELL_MARKERS = ("-i", "su -", "sudo su")
_RELEVANT_TYPES = frozenset({"authentication", "process", "system"})


def _process_basename(process: str | None) -> str:
    """Last path component of a process image, tolerant of ``/`` and ``\\\\``."""
    if not process:
        return ""
    return process.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _coerce_int(value: Any) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


class PrivEscRule(Rule):
    """Privilege-escalation signals -> T1068."""

    id = "SX-PRIV-ESC"
    name = "Possible privilege escalation"
    description = (
        "Signals consistent with exploitation for privilege escalation: an "
        "interactive root shell via sudo/su, Windows event 4672 (special "
        "privileges assigned), or a normalized privilege_escalation action."
    )
    mitre = {
        "tactic": "Privilege Escalation",
        "technique_id": "T1068",
        "technique": "Exploitation for Privilege Escalation",
    }
    severity = "critical"
    base_score = 85

    def evaluate(self, event: Event, ctx: Any) -> list[Alert]:
        method = self._detect_method(event)
        if method is None:
            return []
        return [
            build_alert(
                self,
                event,
                title=f"Possible privilege escalation via {method}",
                evidence={"method": method},
            )
        ]

    def _detect_method(self, event: Event) -> str | None:
        if event.event_type in _RELEVANT_TYPES:
            if _process_basename(event.process) in _SHELL_PROCESSES:
                message = event.message or ""
                if any(marker in message for marker in _SHELL_MARKERS):
                    return f"{_process_basename(event.process)} to root shell"
        if _coerce_int(event.raw.get("EventID")) == _PRIV_ESCALATION_EVENT_ID:
            return "windows special privileges assigned (EventID 4672)"
        if (event.action or "") == "privilege_escalation":
            return "privilege_escalation action"
        return None
