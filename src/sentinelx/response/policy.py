"""Response policy engine: map alerts to automated actions.

Policies live in ``policies/policy.yaml`` (overridable via
``SENTINELX_POLICY_PATH``). Each rule has a ``match`` section — any of
``severity``, ``status`` and ``rule_id`` lists, all of which must match —
and an ``actions`` list of ``block`` / ``slack`` / ``telegram`` steps.

``act`` never raises: every action is wrapped so a broken notifier or
missing credential degrades to a log line. It returns the names of the
actions that were taken, e.g. ``["block_ip:1.2.3.4", "slack"]``.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from pathlib import Path
from typing import Any

import yaml

from sentinelx.common.models import Alert
from sentinelx.response import blocker
from sentinelx.response import slack as slack_mod
from sentinelx.response import telegram as telegram_mod

log = logging.getLogger(__name__)


def default_policy_path() -> Path:
    """Locate the bundled ``policies/policy.yaml`` next to the package."""
    return Path(__file__).resolve().parents[3] / "policies" / "policy.yaml"


def load_policy(path: str | Path | None = None) -> dict:
    """Load and return the policy document from *path* (or the default)."""
    policy_path = Path(path) if path else Path(
        os.environ.get("SENTINELX_POLICY_PATH", default_policy_path())
    )
    with policy_path.open() as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"policy file {policy_path} must contain a mapping")
    return data


def _matches(alert: Alert, match: dict[str, Any]) -> bool:
    """Check whether *alert* satisfies every criterion in *match*."""
    severities = match.get("severity")
    if severities and alert.severity not in severities:
        return False
    statuses = match.get("status")
    if statuses and alert.status not in statuses:
        return False
    rule_ids = match.get("rule_id")
    if rule_ids and alert.rule_id not in rule_ids:
        return False
    return True


def _is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _do_block(alert: Alert, action: dict[str, Any]) -> str | None:
    if not _is_public_ip(alert.src_ip):
        log.info("skipping block: no public src_ip on alert %s", alert.id)
        return None
    duration = int(action.get("duration_s", 3600))
    if blocker.block_ip(alert.src_ip, duration_s=duration):  # type: ignore[arg-type]
        return f"block_ip:{alert.src_ip}"
    return None


def _do_slack(alert: Alert) -> str | None:
    webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not webhook:
        log.info("skipping slack: SLACK_WEBHOOK_URL not set")
        return None
    if slack_mod.notify(alert, webhook):
        return "slack"
    return None


def _do_telegram(alert: Alert) -> str | None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        log.info("skipping telegram: TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID not set")
        return None
    if telegram_mod.notify(alert, token, chat_id):
        return "telegram"
    return None


def act(alert: Alert, policy: dict | None = None) -> list[str]:
    """Run the policy actions matching *alert*; return taken action names.

    ``policy`` may be a pre-loaded policy document (useful for tests);
    otherwise it is loaded from disk. Never raises.
    """
    try:
        doc = policy if policy is not None else load_policy()
    except Exception:
        log.exception("failed to load response policy")
        return []
    taken: list[str] = []
    for rule in doc.get("rules", []) or []:
        if not isinstance(rule, dict):
            continue
        try:
            if not _matches(alert, rule.get("match", {}) or {}):
                continue
            for action in rule.get("actions", []) or []:
                if not isinstance(action, dict):
                    continue
                kind = action.get("type")
                try:
                    if kind == "block":
                        name = _do_block(alert, action)
                    elif kind == "slack":
                        name = _do_slack(alert)
                    elif kind == "telegram":
                        name = _do_telegram(alert)
                    else:
                        log.warning("unknown action type %r; skipping", kind)
                        name = None
                    if name:
                        taken.append(name)
                except Exception:
                    log.warning("response action %r failed", kind, exc_info=True)
        except Exception:
            log.warning("policy rule failed", exc_info=True)
    return taken
