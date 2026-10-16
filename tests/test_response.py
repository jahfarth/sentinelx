"""Tests for automated response: firewall blocker, notifiers, policy engine."""

from datetime import UTC, datetime

import httpx
import pytest

from sentinelx.common.models import Alert
from sentinelx.response import blocker, policy
from sentinelx.response import slack as slack_mod
from sentinelx.response import telegram as telegram_mod


def _alert(**kwargs) -> Alert:
    base = {
        "timestamp": datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC),
        "rule_id": "port-scan",
        "rule_name": "Port scan",
        "title": "Port scan detected",
        "description": "Host probed 50 ports",
        "severity": "critical",
        "score": 90,
        "src_ip": "45.33.32.156",
        "host": "web01",
        "status": "new",
    }
    base.update(kwargs)
    return Alert(**base)


def test_block_ip_dry_run_never_calls_subprocess(monkeypatch):
    monkeypatch.setenv("SENTINELX_DRY_RUN", "1")

    def boom(*args, **kwargs):
        raise AssertionError("subprocess must not run in dry-run mode")

    monkeypatch.setattr("sentinelx.response.blocker.subprocess.run", boom)
    assert blocker.block_ip("203.0.113.9") is True
    assert blocker.unblock_ip("203.0.113.9") is True


def test_block_ip_defaults_to_dry_run(monkeypatch):
    monkeypatch.delenv("SENTINELX_DRY_RUN", raising=False)

    def boom(*args, **kwargs):
        raise AssertionError("subprocess must not run by default")

    monkeypatch.setattr("sentinelx.response.blocker.subprocess.run", boom)
    assert blocker.block_ip("2001:db8::1") is True  # ipv6 dry-run also safe


def test_block_ip_invalid_raises():
    with pytest.raises(ValueError):
        blocker.block_ip("not-an-ip")
    with pytest.raises(ValueError):
        blocker.unblock_ip("999.999.999.999")


def test_block_ip_live_builds_iptables_command(monkeypatch):
    monkeypatch.setenv("SENTINELX_DRY_RUN", "0")
    seen = []

    def fake_run(cmd, **kwargs):
        seen.append(cmd)
        return None

    monkeypatch.setattr("sentinelx.response.blocker.subprocess.run", fake_run)
    assert blocker.block_ip("203.0.113.9", duration_s=600) is True
    assert seen[0] == ["iptables", "-I", "INPUT", "-s", "203.0.113.9", "-j", "DROP"]
    assert blocker.unblock_ip("203.0.113.9") is True
    assert seen[1] == ["iptables", "-D", "INPUT", "-s", "203.0.113.9", "-j", "DROP"]


def test_block_ip_live_uses_ip6tables_for_v6(monkeypatch):
    monkeypatch.setenv("SENTINELX_DRY_RUN", "0")
    seen = []
    monkeypatch.setattr(
        "sentinelx.response.blocker.subprocess.run", lambda cmd, **kw: seen.append(cmd)
    )
    blocker.block_ip("2001:db8::1")
    assert seen[0][0] == "ip6tables"


def test_block_ip_live_failure_returns_false(monkeypatch):
    import subprocess as sp

    monkeypatch.setenv("SENTINELX_DRY_RUN", "0")

    def fail(cmd, **kwargs):
        raise sp.CalledProcessError(1, cmd)

    monkeypatch.setattr("sentinelx.response.blocker.subprocess.run", fail)
    assert blocker.block_ip("203.0.113.9") is False


class _Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_slack_payload_shape_and_post(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return _Resp(200)

    monkeypatch.setattr(httpx, "post", fake_post)
    alert = _alert()
    assert slack_mod.notify(alert, "https://hooks.slack.test/abc") is True
    assert captured["url"] == "https://hooks.slack.test/abc"
    body = captured["json"]
    assert "text" in body and "blocks" in body
    assert body["blocks"][0]["type"] == "section"
    assert "Port scan detected" in body["text"]
    assert "45.33.32.156" in body["text"]


def test_slack_non_2xx_returns_false(monkeypatch):
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp(500))
    assert slack_mod.notify(_alert(), "https://hooks.slack.test/abc") is False


def test_slack_exception_returns_false(monkeypatch):
    def boom(*args, **kwargs):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "post", boom)
    assert slack_mod.notify(_alert(), "https://hooks.slack.test/abc") is False


def test_telegram_posts_markdown_message(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return _Resp(200, {"ok": True})

    monkeypatch.setattr(httpx, "post", fake_post)
    alert = _alert()
    assert telegram_mod.notify(alert, "tok123", "chat9") is True
    assert captured["url"] == "https://api.telegram.org/bottok123/sendMessage"
    body = captured["json"]
    assert body["chat_id"] == "chat9"
    assert body["parse_mode"] == "Markdown"
    assert "CRITICAL" in body["text"]
    assert "Port scan detected" in body["text"]


def test_telegram_ok_false_returns_false(monkeypatch):
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp(200, {"ok": False}))
    assert telegram_mod.notify(_alert(), "tok", "chat") is False


def _policy_env(monkeypatch):
    monkeypatch.setenv("SENTINELX_DRY_RUN", "1")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tok")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat")
    monkeypatch.setattr(slack_mod, "notify", lambda alert, url: True)
    monkeypatch.setattr(telegram_mod, "notify", lambda alert, token, chat: True)


def test_policy_act_critical_blocks_and_notifies(monkeypatch):
    _policy_env(monkeypatch)
    taken = policy.act(_alert())
    assert taken == ["block_ip:45.33.32.156", "slack", "telegram"]


def test_policy_act_skips_block_for_private_ip(monkeypatch):
    _policy_env(monkeypatch)
    taken = policy.act(_alert(src_ip="10.0.0.5"))
    assert taken == ["slack", "telegram"]


def test_policy_act_high_severity_slack_only(monkeypatch):
    _policy_env(monkeypatch)
    taken = policy.act(_alert(severity="high", score=70))
    assert taken == ["slack"]


def test_policy_act_low_severity_no_actions(monkeypatch):
    _policy_env(monkeypatch)
    assert policy.act(_alert(severity="low", score=10)) == []


def test_policy_act_missing_credentials_skips_quietly(monkeypatch):
    monkeypatch.setenv("SENTINELX_DRY_RUN", "1")
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    taken = policy.act(_alert())
    assert taken == ["block_ip:45.33.32.156"]


def test_policy_act_never_raises_on_broken_notifier(monkeypatch):
    _policy_env(monkeypatch)

    def boom(alert, url):
        raise RuntimeError("webhook exploded")

    monkeypatch.setattr(slack_mod, "notify", boom)
    taken = policy.act(_alert())
    assert "telegram" in taken  # other actions still ran


def test_load_policy_default_file():
    doc = policy.load_policy()
    assert isinstance(doc.get("rules"), list)
    assert len(doc["rules"]) >= 3
    assert all("match" in r and "actions" in r for r in doc["rules"])
