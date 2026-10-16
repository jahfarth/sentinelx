"""Tests for the Sigma compiler: parsing, matching, conditions, logsource."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from conftest import make_event

from sentinelx.detection.sigma import SigmaCompiler

COMPILER = SigmaCompiler()


def rule_dict(**overrides):
    base = {
        "title": "Test rule",
        "id": "00000000-0000-0000-0000-000000000001",
        "description": "A test rule",
        "logsource": {"category": "authentication"},
        "detection": {
            "selection": {"TargetUserName": "root", "action": "auth_failed"},
            "condition": "selection",
        },
        "level": "high",
    }
    base.update(overrides)
    return base


# -- basic compile + match -------------------------------------------------


def test_basic_positive_match():
    match = COMPILER.compile(rule_dict())
    event = make_event(user="root", action="auth_failed")
    assert match(event) is True


def test_basic_negative_wrong_user():
    match = COMPILER.compile(rule_dict())
    assert match(make_event(user="alice", action="auth_failed")) is False


def test_basic_negative_wrong_action():
    match = COMPILER.compile(rule_dict())
    assert match(make_event(user="root", action="auth_success")) is False


def test_logsource_category_mismatch_blocks():
    match = COMPILER.compile(rule_dict())
    event = make_event(user="root", action="auth_failed", event_type="web")
    assert match(event) is False


# -- field map -------------------------------------------------------------


def test_field_map_ipaddress_and_url():
    compiled = COMPILER.compile(
        rule_dict(
            logsource={"category": "web"},
            detection={
                "selection": {"c-ip": "10.0.0.5", "cs-uri-stem": "/admin*"},
                "condition": "selection",
            },
        )
    )
    ok_event = make_event(event_type="web", src_ip="10.0.0.5", http_uri="/admin/panel")
    assert compiled(ok_event) is True
    bad_ip = make_event(event_type="web", src_ip="10.0.0.9", http_uri="/admin/panel")
    assert compiled(bad_ip) is False
    bad_uri = make_event(event_type="web", src_ip="10.0.0.5", http_uri="/index")
    assert compiled(bad_uri) is False


def test_raw_dotted_path():
    compiled = COMPILER.compile(
        rule_dict(
            logsource={"product": "windows"},
            detection={"selection": {"EventID": 4625}, "condition": "selection"},
        )
    )
    assert compiled(make_event(source="windows", raw={"EventID": 4625})) is True
    assert compiled(make_event(source="windows", raw={"EventID": 4624})) is False
    # string "4625" in the event also matches the integer in the rule
    assert compiled(make_event(source="windows", raw={"EventID": "4625"})) is True


def test_product_windows_blocks_non_windows():
    compiled = COMPILER.compile(
        rule_dict(
            logsource={"product": "windows"},
            detection={"selection": {"EventID": 4625}, "condition": "selection"},
        )
    )
    assert compiled(make_event(source="auth", raw={"EventID": 4625})) is False


# -- modifiers -------------------------------------------------------------


def test_contains_modifier():
    compiled = COMPILER.compile(
        rule_dict(
            logsource={"category": "web"},
            detection={
                "selection": {"Url|contains": "union select"},
                "condition": "selection",
            },
        )
    )
    assert compiled(make_event(event_type="web", http_uri="/x?id=1 UNION SELECT 1")) is True
    assert compiled(make_event(event_type="web", http_uri="/index.html")) is False


def test_startswith_endswith_modifiers():
    compiled = COMPILER.compile(
        rule_dict(
            logsource={"category": "process_creation"},
            detection={
                "selection": {"Image|startswith": "/usr/bin/", "CommandLine|endswith": ".sh"},
                "condition": "selection",
            },
        )
    )
    event = make_event(
        event_type="process", process="/usr/bin/python", raw={"CommandLine": "run setup.sh"}
    )
    assert compiled(event) is True
    assert (
        compiled(make_event(event_type="process", process="/bin/ls", raw={"CommandLine": "x.sh"}))
        is False
    )


def test_re_modifier():
    compiled = COMPILER.compile(
        rule_dict(
            detection={"selection": {"TargetUserName|re": r"^adm[i1]n$"}, "condition": "selection"},
        )
    )
    assert compiled(make_event(user="admin")) is True
    assert compiled(make_event(user="adm1n")) is True
    assert compiled(make_event(user="administrator")) is False


def test_contains_all_modifier():
    compiled = COMPILER.compile(
        rule_dict(
            logsource={"category": "web"},
            detection={
                "selection": {"Url|contains|all": ["union", "select"]},
                "condition": "selection",
            },
        )
    )
    assert compiled(make_event(event_type="web", http_uri="/x?u=1 UNION SELECT")) is True
    assert compiled(make_event(event_type="web", http_uri="/x?u=1 UNION")) is False


def test_wildcard_case_insensitive():
    compiled = COMPILER.compile(
        rule_dict(
            logsource={"category": "process_creation"},
            detection={"selection": {"Image": "*SUDO*"}, "condition": "selection"},
        )
    )
    assert compiled(make_event(event_type="process", process="/usr/bin/sudo")) is True
    assert compiled(make_event(event_type="process", process="/usr/bin/ls")) is False


def test_list_value_is_or():
    compiled = COMPILER.compile(
        rule_dict(
            detection={
                "selection": {"action": ["auth_failed", "logon_failed"]},
                "condition": "selection",
            },
        )
    )
    assert compiled(make_event(action="auth_failed")) is True
    assert compiled(make_event(action="logon_failed")) is True
    assert compiled(make_event(action="auth_success")) is False


def test_selection_list_of_dicts_is_or():
    compiled = COMPILER.compile(
        rule_dict(
            detection={
                "selection": [{"TargetUserName": "root"}, {"TargetUserName": "admin"}],
                "condition": "selection",
            },
        )
    )
    assert compiled(make_event(user="root", action="auth_failed")) is True
    assert compiled(make_event(user="admin", action="auth_failed")) is True
    assert compiled(make_event(user="bob", action="auth_failed")) is False


# -- conditions ------------------------------------------------------------


def _cond_rule(condition, selections):
    detection = dict(selections)
    detection["condition"] = condition
    return COMPILER.compile(rule_dict(detection=detection))


def test_condition_and_or_not_parens():
    selections = {
        "sel_a": {"TargetUserName": "root"},
        "sel_b": {"action": "auth_failed"},
        "sel_c": {"IpAddress": "1.2.3.4"},
    }
    match = _cond_rule("sel_a and sel_b", selections)
    assert match(make_event(user="root", action="auth_failed")) is True
    assert match(make_event(user="root", action="auth_success")) is False

    match = _cond_rule("sel_a or sel_c", selections)
    assert match(make_event(user="root", src_ip="9.9.9.9")) is True
    assert match(make_event(user="root", src_ip="1.2.3.4")) is True
    assert match(make_event(user="bob", src_ip="9.9.9.9")) is False

    match = _cond_rule("sel_a and not sel_b", selections)
    assert match(make_event(user="root", action="auth_success")) is True
    assert match(make_event(user="root", action="auth_failed")) is False

    match = _cond_rule("sel_a and (sel_b or sel_c)", selections)
    assert match(make_event(user="root", action="auth_success", src_ip="1.2.3.4")) is True
    assert match(make_event(user="root", action="auth_success", src_ip="9.9.9.9")) is False


def test_condition_one_of_glob():
    selections = {
        "sel_login": {"action": "auth_failed"},
        "sel_logon": {"action": "logon_failed"},
        "sel_other": {"TargetUserName": "root"},
    }
    match = _cond_rule("1 of sel_*", selections)
    assert match(make_event(user="x", action="auth_failed")) is True
    assert match(make_event(user="x", action="logon_failed")) is True
    assert match(make_event(user="root", action="auth_success")) is True
    assert match(make_event(user="x", action="auth_success")) is False


def test_condition_all_of_glob():
    selections = {
        "sel_a": {"TargetUserName": "root"},
        "sel_b": {"TargetUserName": "r*"},
    }
    match = _cond_rule("all of sel_*", selections)
    assert match(make_event(user="root")) is True
    assert match(make_event(user="bob")) is False


def test_condition_one_of_them_and_all_of_them():
    selections = {
        "sel_a": {"TargetUserName": "root"},
        "sel_b": {"action": "auth_failed"},
    }
    one = _cond_rule("1 of them", selections)
    assert one(make_event(user="root", action="x")) is True
    assert one(make_event(user="bob", action="auth_failed")) is True
    assert one(make_event(user="bob", action="x")) is False

    all_ = _cond_rule("all of them", selections)
    assert all_(make_event(user="root", action="auth_failed")) is True
    assert all_(make_event(user="root", action="x")) is False


# -- invalid rules ---------------------------------------------------------


def test_missing_title_raises():
    with pytest.raises(ValueError):
        COMPILER.compile(rule_dict(title=""))


def test_missing_id_raises():
    with pytest.raises(ValueError):
        COMPILER.compile(rule_dict(id=None))


def test_missing_condition_raises():
    with pytest.raises(ValueError):
        COMPILER.compile(rule_dict(detection={"selection": {"a": "b"}}))


def test_unknown_selection_in_condition_raises():
    with pytest.raises(ValueError):
        COMPILER.compile(
            rule_dict(detection={"selection": {"a": "b"}, "condition": "selection and nope"})
        )


def test_broken_condition_syntax_raises():
    with pytest.raises(ValueError):
        COMPILER.compile(
            rule_dict(detection={"selection": {"a": "b"}, "condition": "selection and"})
        )


def test_condition_glob_matching_nothing_raises():
    with pytest.raises(ValueError):
        COMPILER.compile(rule_dict(detection={"selection": {"a": "b"}, "condition": "1 of zzz*"}))


def test_bad_level_raises():
    with pytest.raises(ValueError):
        COMPILER.compile(rule_dict(level="extreme"))


def test_bad_modifier_raises():
    with pytest.raises(ValueError):
        COMPILER.compile(
            rule_dict(detection={"selection": {"Url|fuzzy": "x"}, "condition": "selection"})
        )


def test_non_dict_rule_raises():
    with pytest.raises(ValueError):
        COMPILER.compile(["not", "a", "dict"])  # type: ignore[arg-type]


# -- compile_file ----------------------------------------------------------


def test_compile_file(tmp_path):
    path = tmp_path / "rule.yml"
    path.write_text(yaml.safe_dump(rule_dict()), encoding="utf-8")
    match = COMPILER.compile_file(path)
    assert match(make_event(user="root", action="auth_failed")) is True
    assert match(make_event(user="bob", action="auth_failed")) is False


def test_compile_file_invalid_yaml_mapping(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ValueError):
        COMPILER.compile_file(path)


def test_bundled_sigma_rules_all_compile():
    sigma_dir = (
        Path(__file__).resolve().parent.parent / "src" / "sentinelx" / "detection" / "sigma_rules"
    )
    files = sorted(sigma_dir.glob("*.yml"))
    assert len(files) == 8, f"expected 8 bundled Sigma rules, found {len(files)}"
    for file in files:
        record = COMPILER.compile_record(yaml.safe_load(file.read_text(encoding="utf-8")))
        assert record.rule_id and record.name and callable(record.match)
