"""Detection engine: runs every registered rule against each event.

The engine is intentionally dumb on purpose: it owns no state itself. All
temporal/stateful correlation lives behind the duck-typed ``ctx`` object
(``ctx.count(key, window_s)`` / ``ctx.sadd_window(key, member, window_s)``),
so rules stay pure and unit-testable with an in-memory fake.

A rule that raises is logged and skipped; one broken rule never blocks the
rest of the pipeline.
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from sentinelx.common import Alert, Event
from sentinelx.common.mitre import TECHNIQUES
from sentinelx.common.severity import compute_score, score_to_level
from sentinelx.detection.loader import CompiledSigmaRule, load_sigma_rules
from sentinelx.detection.sigma import LEVEL_SCORES

logger = logging.getLogger(__name__)

#: Default location of the bundled Sigma rules, relative to this file.
DEFAULT_SIGMA_DIR = Path(__file__).resolve().parent / "sigma_rules"

__all__ = [
    "DEFAULT_SIGMA_DIR",
    "DetectionEngine",
    "Rule",
    "SigmaRuleAdapter",
    "mitre_from_tags",
]


class Rule(ABC):
    """Abstract detection rule.

    Concrete rules set the class/instance attributes below and implement
    :meth:`evaluate`.
    """

    id: str
    name: str
    description: str
    mitre: dict[str, str]
    severity: str
    base_score: int

    @abstractmethod
    def evaluate(self, event: Event, ctx: Any) -> list[Alert]:
        """Inspect *event* (using *ctx* for windowed state) and return alerts."""
        raise NotImplementedError


def mitre_from_tags(tags: tuple[str, ...] | list[str]) -> dict[str, str]:
    """Resolve the first ``attack.<technique_id>`` tag to a MITRE metadata dict.

    Returns ``{"tactic": ..., "technique_id": ..., "technique": ...}`` or an
    empty dict when no tag maps to a known technique. Tolerates both tuple
    ``(tactic, technique)`` and mapping shaped entries in
    :data:`~sentinelx.common.mitre.TECHNIQUES`.
    """
    for tag in tags:
        if not tag.lower().startswith("attack.t"):
            continue
        technique_id = tag[len("attack.t") :].upper().replace("_", ".")
        if not technique_id.startswith("T"):
            technique_id = "T" + technique_id
        entry = TECHNIQUES.get(technique_id)
        if entry is None:
            continue
        if isinstance(entry, dict):
            tactic = str(entry.get("tactic", ""))
            technique = str(entry.get("technique", entry.get("name", "")))
        else:
            tactic, technique = entry[0], entry[1]
        return {
            "tactic": tactic,
            "technique_id": technique_id,
            "technique": technique,
        }
    return {}


class SigmaRuleAdapter(Rule):
    """Adapt a compiled Sigma rule to the :class:`Rule` interface.

    Severity/score derive from the Sigma level so that
    ``score_to_level(score) == severity`` always holds:
    informational 10, low 30, medium 55, high 75, critical 90.
    """

    def __init__(self, record: CompiledSigmaRule) -> None:
        self.id = record.rule_id
        self.name = record.name
        self.description = record.description or "Sigma rule match"
        self.mitre = mitre_from_tags(record.tags)
        self.base_score = LEVEL_SCORES[record.level]
        self.severity = score_to_level(compute_score(self.base_score))
        self._record = record

    def evaluate(self, event: Event, ctx: Any) -> list[Alert]:
        if not self._record.match(event):
            return []
        score = compute_score(self.base_score)
        return [
            Alert(
                timestamp=event.timestamp,
                rule_id=self.id,
                rule_name=self.name,
                title=f"Sigma rule matched: {self.name}",
                description=self.description,
                severity=score_to_level(score),  # type: ignore[arg-type]
                score=score,
                mitre=dict(self.mitre),
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                host=event.host,
                user=event.user,
                evidence={"sigma_level": self._record.level, "tags": list(self._record.tags)},
                intel={},
            )
        ]


class DetectionEngine:
    """Run a set of rules over events.

    With ``rules=None`` (the default) the engine loads the builtin Python
    rules plus every Sigma rule found in ``SENTINELX_SIGMA_DIR`` or, when
    unset, the bundled ``sigma_rules/`` directory. Pass an explicit list to
    take full control (useful in tests).
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        sigma_dir: str | Path | None = None,
    ) -> None:
        if rules is not None:
            self.rules: list[Rule] = list(rules)
        else:
            # Imported lazily to avoid a package import cycle:
            # sentinelx.detection.rules imports nothing from engine, but
            # keeping builtin assembly here documents the wiring in one place.
            from sentinelx.detection.rules import BUILTIN_RULES

            self.rules = list(BUILTIN_RULES)
            directory = sigma_dir or os.environ.get("SENTINELX_SIGMA_DIR") or DEFAULT_SIGMA_DIR
            for record in load_sigma_rules(directory):
                self.rules.append(SigmaRuleAdapter(record))
        logger.info("DetectionEngine initialized with %d rules", len(self.rules))

    def evaluate(self, event: Event, ctx: Any) -> list[Alert]:
        """Run every rule against *event*; per-rule exceptions are logged and skipped."""
        alerts: list[Alert] = []
        for rule in self.rules:
            try:
                found = rule.evaluate(event, ctx)
            except Exception:
                logger.exception(
                    "Rule %s (%s) failed on event; skipping",
                    getattr(rule, "id", "?"),
                    getattr(rule, "name", "?"),
                )
                continue
            if found:
                alerts.extend(found)
        return alerts
