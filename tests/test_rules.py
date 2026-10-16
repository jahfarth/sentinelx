"""Tests for the builtin Python rules, driven with the in-memory FakeCtx."""

from __future__ import annotations

from conftest import FakeCtx, event_at, make_event, run_sequence

from sentinelx.common.severity import compute_score, score_to_level
from sentinelx.detection.rules.brute_force import BruteForceRule
from sentinelx.detection.rules.port_scan import PortScanRule
from sentinelx.detection.rules.priv_esc import PrivEscRule
from sentinelx.detection.rules.web_attack import WebAttackRule


def failed_login(seconds=0, src_ip="203.0.113.7", **kwargs):
    return event_at(
        seconds,
        event_type="authentication",
        action="auth_failed",
        src_ip=src_ip,
        user="root",
        message="Failed password for root",
        **kwargs,
    )


# -- brute force -----------------------------------------------------------


def test_brute_force_fires_on_fifth_not_fourth():
    rule = BruteForceRule()
    events = [failed_login(s) for s in range(5)]
    results = run_sequence(rule, events)
    assert all(r == [] for r in results[:4])
    assert len(results[4]) == 1
    alert = results[4][0]
    assert alert.rule_id == "SX-BRUTE-FORCE"
    assert alert.mitre["technique_id"] == "T1110.001"
    assert alert.severity == "high"
    assert alert.score == 75
    assert alert.evidence == {"fail_count": 5, "window_s": 300}
    assert score_to_level(alert.score) == alert.severity


def test_brute_force_window_expiry():
    rule = BruteForceRule()
    ctx = FakeCtx()
    # four failures, then a long gap: the early ones must fall out of the 300s window
    events = [failed_login(s) for s in (0, 60, 120, 180, 481)]
    for event in events:
        ctx.set_time(event.timestamp.timestamp())
        assert rule.evaluate(event, ctx) == []
    # four more in quick succession on the SAME ctx -> the 5th inside the window fires
    fired = []
    for event in (failed_login(s) for s in (482, 483, 484, 485)):
        ctx.set_time(event.timestamp.timestamp())
        fired.append(rule.evaluate(event, ctx))
    assert all(r == [] for r in fired[:3])
    assert len(fired[3]) == 1
    assert fired[3][0].evidence["fail_count"] == 5


def test_brute_force_ignores_successes_and_other_types():
    rule = BruteForceRule()
    events = [failed_login(0), failed_login(1)]
    events.append(
        event_at(2, event_type="authentication", action="auth_success", src_ip="203.0.113.7")
    )
    events.append(event_at(3, event_type="network", action="auth_failed", src_ip="203.0.113.7"))
    events += [failed_login(4), failed_login(5)]
    results = run_sequence(rule, events)
    # only 4 real failures counted -> no alert
    assert all(r == [] for r in results)


def test_brute_force_per_source_ip_isolation():
    rule = BruteForceRule()
    events = [failed_login(s, src_ip="10.0.0.1") for s in range(4)]
    events += [failed_login(s, src_ip="10.0.0.2") for s in range(4, 8)]
    results = run_sequence(rule, events)
    assert all(r == [] for r in results)


# -- port scan -------------------------------------------------------------


def scan_event(seconds, port, src_ip="198.51.100.9"):
    return event_at(seconds, event_type="network", src_ip=src_ip, dst_ip="10.1.2.3", dst_port=port)


def test_port_scan_fires_at_fifteen_distinct_ports():
    rule = PortScanRule()
    events = [scan_event(s, 1000 + s) for s in range(15)]
    results = run_sequence(rule, events)
    assert all(r == [] for r in results[:14])
    assert len(results[14]) == 1
    alert = results[14][0]
    assert alert.rule_id == "SX-PORT-SCAN"
    assert alert.mitre["technique_id"] == "T1046"
    assert alert.severity == "medium"
    assert alert.score == 55
    assert alert.evidence["port_count"] == 15
    assert score_to_level(alert.score) == alert.severity


def test_port_scan_repeated_same_port_never_fires():
    rule = PortScanRule()
    events = [scan_event(s, 443) for s in range(30)]
    results = run_sequence(rule, events)
    assert all(r == [] for r in results)


def test_port_scan_window_expiry():
    rule = PortScanRule()
    events = [scan_event(s, 2000 + s) for s in range(14)]  # t=0..13
    events.append(scan_event(70, 9999))  # outside the 60s window of the early ports
    results = run_sequence(rule, events)
    assert all(r == [] for r in results)


def test_port_scan_requires_dst_port():
    rule = PortScanRule()
    events = [event_at(s, event_type="network", src_ip="198.51.100.9") for s in range(20)]
    results = run_sequence(rule, events)
    assert all(r == [] for r in results)


# -- web attack ------------------------------------------------------------


def test_web_attack_sqli():
    rule = WebAttackRule()
    event = make_event(
        event_type="web",
        source="apache",
        src_ip="203.0.113.9",
        http_method="GET",
        http_uri="/search?q=' OR '1'='1",
    )
    alerts = rule.evaluate(event, None)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.mitre["technique_id"] == "T1190"
    assert alert.severity == "high"
    assert alert.score == 80
    assert "[sqli]" in alert.title
    assert alert.evidence["attack_type"] == "sqli"
    assert alert.evidence["matched"]
    assert alert.evidence["pattern"]
    assert score_to_level(alert.score) == alert.severity


def test_web_attack_sqli_union_select():
    rule = WebAttackRule()
    event = make_event(
        event_type="web", source="nginx", http_uri="/item?id=1 UNION SELECT password FROM users"
    )
    alerts = rule.evaluate(event, None)
    assert len(alerts) == 1
    assert alerts[0].evidence["attack_type"] == "sqli"


def test_web_attack_xss():
    rule = WebAttackRule()
    event = make_event(event_type="web", source="nginx", http_uri="/q?<script>alert(1)</script>")
    alerts = rule.evaluate(event, None)
    assert len(alerts) == 1
    assert "[xss]" in alerts[0].title
    assert alerts[0].evidence["attack_type"] == "xss"


def test_web_attack_traversal():
    rule = WebAttackRule()
    event = make_event(event_type="web", source="apache", http_uri="/static/../../etc/passwd")
    alerts = rule.evaluate(event, None)
    assert len(alerts) == 1
    assert "[traversal]" in alerts[0].title
    assert alerts[0].evidence["attack_type"] == "traversal"


def test_web_attack_encoded_traversal():
    rule = WebAttackRule()
    event = make_event(event_type="web", source="apache", http_uri="/%2e%2e/%2e%2e/etc/shadow")
    alerts = rule.evaluate(event, None)
    assert len(alerts) == 1
    assert alerts[0].evidence["attack_type"] == "traversal"


def test_web_attack_in_user_agent():
    rule = WebAttackRule()
    event = make_event(
        event_type="web",
        source="nginx",
        http_uri="/",
        user_agent="Mozilla/5.0 <script>alert(document.cookie)</script>",
    )
    alerts = rule.evaluate(event, None)
    assert len(alerts) == 1
    assert alerts[0].evidence["field"] == "user_agent"


def test_web_attack_ignores_benign():
    rule = WebAttackRule()
    for uri in ("/index.html", "/search?q=hello+world", "/api/v1/users?page=2"):
        event = make_event(event_type="web", source="nginx", http_uri=uri)
        assert rule.evaluate(event, None) == []


# -- privilege escalation --------------------------------------------------


def test_priv_esc_sudo_to_shell():
    rule = PrivEscRule()
    event = make_event(
        event_type="process",
        source="auth",
        process="sudo",
        user="alice",
        message="user alice ran 'sudo -i' on web01",
    )
    alerts = rule.evaluate(event, None)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "SX-PRIV-ESC"
    assert alert.mitre["technique_id"] == "T1068"
    assert alert.evidence["method"] == "sudo to root shell"
    assert score_to_level(alert.score) == alert.severity


def test_priv_esc_su_dash_with_path():
    rule = PrivEscRule()
    event = make_event(
        event_type="process",
        source="auth",
        process="/bin/su",
        message="session opened for root by bob (su -)",
    )
    alerts = rule.evaluate(event, None)
    assert len(alerts) == 1
    assert "su" in alerts[0].evidence["method"]


def test_priv_esc_ignores_normal_sudo():
    rule = PrivEscRule()
    event = make_event(
        event_type="process",
        source="auth",
        process="/usr/bin/sudo",
        user="bob",
        message="user bob ran 'sudo ls -la /tmp' on web01",
    )
    assert rule.evaluate(event, None) == []


def test_priv_esc_windows_4672():
    rule = PrivEscRule()
    event = make_event(
        event_type="system",
        source="windows",
        host="dc01",
        user="svc_backup",
        raw={"EventID": 4672},
        message="Special privileges assigned to new logon",
    )
    alerts = rule.evaluate(event, None)
    assert len(alerts) == 1
    assert alerts[0].evidence["method"] == "windows special privileges assigned (EventID 4672)"
    assert score_to_level(alerts[0].score) == alerts[0].severity


def test_priv_esc_explicit_action():
    rule = PrivEscRule()
    event = make_event(
        event_type="authentication", source="auth", action="privilege_escalation", user="bob"
    )
    alerts = rule.evaluate(event, None)
    assert len(alerts) == 1
    assert alerts[0].evidence["method"] == "privilege_escalation action"


def test_priv_esc_ignores_unrelated():
    rule = PrivEscRule()
    event = make_event(
        event_type="process", source="auth", process="nginx", message="worker started"
    )
    assert rule.evaluate(event, None) == []
    event = make_event(
        event_type="system", source="windows", raw={"EventID": 4624}, message="logon success"
    )
    assert rule.evaluate(event, None) == []


def test_rule_scores_consistent_with_severity():
    for rule in (BruteForceRule(), PortScanRule(), WebAttackRule(), PrivEscRule()):
        assert score_to_level(compute_score(rule.base_score)) == rule.severity
