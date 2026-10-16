"""Cross-cutting invariants: MITRE technique validity and score/severity consistency."""

from __future__ import annotations

from pathlib import Path

from sentinelx.common.mitre import TECHNIQUES
from sentinelx.common.severity import compute_score, score_to_level
from sentinelx.detection.engine import SigmaRuleAdapter
from sentinelx.detection.loader import load_sigma_rules
from sentinelx.detection.rules import BUILTIN_RULES

SIGMA_DIR = (
    Path(__file__).resolve().parent.parent / "src" / "sentinelx" / "detection" / "sigma_rules"
)


def all_rules():
    rules = list(BUILTIN_RULES)
    for record in load_sigma_rules(SIGMA_DIR):
        rules.append(SigmaRuleAdapter(record))
    return rules


def test_builtin_rule_techniques_exist():
    assert len(BUILTIN_RULES) == 4
    for rule in BUILTIN_RULES:
        tid = rule.mitre["technique_id"]
        assert tid in TECHNIQUES, f"{rule.id} references unknown technique {tid}"
        assert rule.mitre["tactic"] == TECHNIQUES[tid]["tactic"]
        assert rule.mitre["technique"] == TECHNIQUES[tid]["technique"]


def test_sigma_rule_techniques_exist():
    records = load_sigma_rules(SIGMA_DIR)
    assert len(records) == 8
    for record in records:
        adapter = SigmaRuleAdapter(record)
        assert adapter.mitre, f"sigma rule {record.rule_id} resolved no MITRE technique"
        tid = adapter.mitre["technique_id"]
        assert tid in TECHNIQUES, f"sigma rule {record.rule_id} references unknown {tid}"


def test_severity_consistent_with_score():
    for rule in all_rules():
        expected = score_to_level(compute_score(rule.base_score))
        assert rule.severity == expected, (
            f"{rule.id}: severity {rule.severity!r} != score_to_level({rule.base_score}) "
            f"= {expected!r}"
        )


def test_expected_technique_coverage():
    tids = {rule.mitre["technique_id"] for rule in all_rules()}
    assert {"T1110.001", "T1046", "T1190", "T1068", "T1078"} <= tids
