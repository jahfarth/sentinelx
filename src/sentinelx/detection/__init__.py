"""SentinelX detection package: Sigma compilation, rule engine, and builtin rules."""

from sentinelx.detection.engine import DetectionEngine, Rule, SigmaRuleAdapter
from sentinelx.detection.loader import CompiledSigmaRule, load_sigma_rules
from sentinelx.detection.rules import BUILTIN_RULES
from sentinelx.detection.sigma import SigmaCompiler

__all__ = [
    "BUILTIN_RULES",
    "CompiledSigmaRule",
    "DetectionEngine",
    "Rule",
    "SigmaCompiler",
    "SigmaRuleAdapter",
    "load_sigma_rules",
]
