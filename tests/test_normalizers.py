"""Tests for the log normalizers (positive and negative cases)."""

import json

import pytest

from sentinelx.ingestion.normalizers import (
    normalize,
    normalize_batch,
    parse_apache_line,
    parse_auth_log_line,
    parse_nginx_line,
    parse_syslog_line,
    parse_windows_json,
)


def test_parse_syslog_line():
    event = parse_syslog_line("<34>Oct 11 22:14:15 myhost sshd[1234]: Failed password for root")
    assert event is not None
    assert event.host == "myhost"
    assert event.source == "syslog"
    assert event.event_type == "system"
    assert event.process == "sshd"
    assert event.timestamp.month == 10
    assert event.timestamp.day == 11
    assert "Failed password" in event.message


def test_parse_syslog_line_no_match():
    assert parse_syslog_line("this is not syslog") is None
    assert parse_syslog_line("") is None


def test_parse_auth_failed():
    line = (
        "Oct 11 22:14:15 h sshd[1]: Failed password for invalid user bob "
        "from 203.0.113.7 port 52341 ssh2"
    )
    event = parse_auth_log_line(line)
    assert event is not None
    assert event.event_type == "authentication"
    assert event.action == "auth_failed"
    assert event.user == "bob"
    assert event.src_ip == "203.0.113.7"
    assert event.src_port == 52341


def test_parse_auth_accepted():
    line = (
        "Oct 11 22:14:15 h sshd[1]: Accepted password for alice "
        "from 198.51.100.9 port 51230 ssh2"
    )
    event = parse_auth_log_line(line)
    assert event is not None
    assert event.action == "auth_success"
    assert event.user == "alice"
    assert event.src_ip == "198.51.100.9"


def test_parse_auth_no_match():
    assert parse_auth_log_line("Oct 11 h sshd[1]: Connection closed by 1.2.3.4") is None


def test_parse_nginx_line():
    line = (
        '203.0.113.7 - frank [16/Oct/2026:10:00:00 +0000] '
        '"GET /admin HTTP/1.1" 404 123 "-" "curl/8.0"'
    )
    event = parse_nginx_line(line)
    assert event is not None
    assert event.source == "nginx"
    assert event.event_type == "web"
    assert event.src_ip == "203.0.113.7"
    assert event.user == "frank"
    assert event.http_method == "GET"
    assert event.http_uri == "/admin"
    assert event.http_status == 404
    assert event.user_agent == "curl/8.0"


def test_parse_apache_line():
    line = (
        '198.51.100.9 - - [16/Oct/2026:11:00:00 +0000] '
        '"POST /login HTTP/1.1" 200 456 "-" "Mozilla/5.0"'
    )
    event = parse_apache_line(line)
    assert event is not None
    assert event.source == "apache"
    assert event.http_method == "POST"
    assert event.http_uri == "/login"
    assert event.http_status == 200
    assert event.user is None  # "-" placeholder


def test_parse_http_no_match():
    assert parse_nginx_line("garbage line") is None
    assert parse_apache_line("") is None


def test_parse_windows_logon_failed():
    obj = {
        "Event": {
            "System": {
                "EventID": 4625,
                "Computer": "DC01",
                "TimeCreated": {"SystemTime": "2026-10-16T10:00:00Z"},
            },
            "EventData": {"TargetUserName": "bob", "IpAddress": "203.0.113.7"},
        }
    }
    event = parse_windows_json(obj)
    assert event is not None
    assert event.source == "windows"
    assert event.event_type == "authentication"
    assert event.action == "logon_failed"
    assert event.user == "bob"
    assert event.src_ip == "203.0.113.7"
    assert event.host == "DC01"


def test_parse_windows_user_created():
    obj = {
        "System": {"EventID": 4720, "Computer": "DC01"},
        "EventData": {"TargetUserName": "eve", "IpAddress": "-"},
    }
    event = parse_windows_json(obj)
    assert event is not None
    assert event.event_type == "system"
    assert event.action == "user_created"
    assert event.src_ip is None


def test_parse_windows_special_logon():
    obj = {"System": {"EventID": 4672, "Computer": "SRV"}, "EventData": {}}
    event = parse_windows_json(obj)
    assert event is not None
    assert event.action == "special_logon"


def test_parse_windows_unknown_event_id():
    obj = {"System": {"EventID": 9999}, "EventData": {}}
    assert parse_windows_json(obj) is None
    assert parse_windows_json({}) is None
    assert parse_windows_json("nope") is None


def test_normalize_dispatch_and_host_fill():
    event = normalize("auth", "myhost",
                      "Failed password for root from 1.2.3.4 port 22 ssh2")
    assert event.source == "auth"
    assert event.host == "myhost"  # auth lines carry no host; filled from arg


def test_normalize_windows_json_line():
    line = json.dumps({"System": {"EventID": 4624, "Computer": "PC1"},
                       "EventData": {"TargetUserName": "a", "IpAddress": "1.2.3.4"}})
    event = normalize("windows", "", line)
    assert event.action == "logon_success"
    assert event.host == "PC1"


def test_normalize_netflow_json_and_csv():
    as_json = normalize("netflow", "fw",
                        '{"src_ip": "1.1.1.1", "src_port": 1, "dst_ip": "2.2.2.2", "dst_port": 80}')
    assert as_json.event_type == "network"
    assert as_json.src_ip == "1.1.1.1"
    assert as_json.dst_port == 80

    as_csv = normalize("netflow", "fw", "1.1.1.1,443,2.2.2.2,80,tcp,1500")
    assert as_csv.src_port == 443
    assert as_csv.raw["protocol"] == "tcp"


def test_normalize_unknown_source():
    with pytest.raises(ValueError, match="unknown source"):
        normalize("carrier-pigeon", "h", "line")


def test_normalize_unparseable_line():
    with pytest.raises(ValueError, match="could not parse"):
        normalize("nginx", "h", "definitely not a log line")


def test_normalize_batch_skips_bad_lines():
    lines = [
        "Oct 11 22:14:15 h sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
        "garbage that matches nothing",
        "",
        "Oct 11 22:14:16 h sshd[1]: Accepted password for a from 1.2.3.5 port 22 ssh2",
    ]
    events = normalize_batch("auth", "h", lines)
    assert len(events) == 2
    assert events[0].action == "auth_failed"
    assert events[1].action == "auth_success"
