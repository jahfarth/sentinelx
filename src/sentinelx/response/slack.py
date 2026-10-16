"""Slack notifier: post alert cards to an incoming webhook."""

from __future__ import annotations

import logging

import httpx

from sentinelx.common.models import Alert

log = logging.getLogger(__name__)

_SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":warning:",
    "medium": ":large_yellow_circle:",
    "low": ":large_green_circle:",
}


def build_payload(alert: Alert) -> dict:
    """Build the Block Kit payload (with a text fallback) for *alert*."""
    emoji = _SEVERITY_EMOJI.get(alert.severity, ":bell:")
    technique = alert.mitre.get("technique_id", "")
    lines = [
        f"{emoji} *[{alert.severity.upper()}] {alert.title}*",
        f"*Rule:* {alert.rule_name} (`{alert.rule_id}`)",
        f"*Score:* {alert.score}/100",
    ]
    if alert.src_ip:
        lines.append(f"*Source IP:* `{alert.src_ip}`")
    if alert.host:
        lines.append(f"*Host:* `{alert.host}`")
    if alert.user:
        lines.append(f"*User:* `{alert.user}`")
    if technique:
        lines.append(f"*MITRE:* `{technique}` {alert.mitre.get('technique', '')}")
    lines.append(alert.description)
    text = "\n".join(lines)
    return {
        "text": text,
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": text},
            }
        ],
    }


def notify(alert: Alert, webhook_url: str) -> bool:
    """POST *alert* to the Slack *webhook_url*; ``True`` on 2xx."""
    payload = build_payload(alert)
    try:
        response = httpx.post(webhook_url, json=payload, timeout=10)
    except httpx.HTTPError as exc:
        log.error("slack notify failed: %s", exc)
        return False
    if 200 <= response.status_code < 300:
        return True
    log.warning("slack webhook returned HTTP %s", response.status_code)
    return False
