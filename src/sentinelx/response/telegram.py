"""Telegram notifier: send alert messages via a bot."""

from __future__ import annotations

import logging

import httpx

from sentinelx.common.models import Alert

log = logging.getLogger(__name__)


def build_message(alert: Alert) -> str:
    """Build the Markdown message text for *alert*."""
    technique = alert.mitre.get("technique_id", "")
    lines = [
        f"*{alert.severity.upper()}* — {alert.title}",
        f"Rule: {alert.rule_name} (`{alert.rule_id}`)",
        f"Score: {alert.score}/100",
    ]
    if alert.src_ip:
        lines.append(f"Source IP: `{alert.src_ip}`")
    if alert.host:
        lines.append(f"Host: `{alert.host}`")
    if alert.user:
        lines.append(f"User: `{alert.user}`")
    if technique:
        lines.append(f"MITRE: `{technique}` {alert.mitre.get('technique', '')}")
    lines.append(alert.description)
    return "\n".join(lines)


def notify(alert: Alert, bot_token: str, chat_id: str) -> bool:
    """Send *alert* to *chat_id* via the Telegram bot; ``True`` on ok."""
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": build_message(alert),
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }
    try:
        response = httpx.post(url, json=payload, timeout=10)
    except httpx.HTTPError as exc:
        log.error("telegram notify failed: %s", exc)
        return False
    try:
        ok = bool(response.json().get("ok"))
    except ValueError:
        ok = False
    if not ok:
        log.warning("telegram sendMessage returned HTTP %s", response.status_code)
    return ok
