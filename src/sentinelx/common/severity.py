"""Severity helpers: numeric score <-> severity level mapping."""


def score_to_level(score: int) -> str:
    """Map a 0-100 numeric *score* to a severity level string.

    Thresholds: >=85 critical, >=65 high, >=40 medium, otherwise low.
    """
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def compute_score(base: int, intel_boost: int = 0) -> int:
    """Combine a rule *base* score with a threat-intel *boost*.

    The result is clamped to the 0-100 range so it always stays a valid
    alert score.
    """
    return max(0, min(100, base + intel_boost))
