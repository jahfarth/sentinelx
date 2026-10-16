# Detection Engine

How SentinelX turns normalized `Event`s into `Alert`s: the `Rule` interface,
the `DetectionEngine` runner, the builtin Python rules, and how to write a new one.

## Architecture

```
Event --> DetectionEngine.evaluate(event, ctx) --> [Alert, ...]
                |
                +-- BruteForceRule ──────────────┐
                +-- PortScanRule                 │  each rule is independent;
                +-- WebAttackRule                │  exceptions are caught per rule,
                +-- PrivEscRule                  │  logged, and skipped
                +-- SigmaRuleAdapter (x8) ───────┘
```

The engine itself owns **no state**. All temporal correlation (sliding windows,
distinct counts) lives behind the duck-typed `ctx` object supplied by the worker:

- `ctx.count(key: str, window_s: int) -> int` — records the current hit for `key`
  and returns the number of hits inside the trailing `window_s` seconds.
- `ctx.sadd_window(key: str, member: str, window_s: int) -> int` — adds `member`
  to the windowed set for `key` and returns the distinct member count inside the window.

Both methods are *record-then-count*: the event being evaluated is included in
the returned number. Rules therefore never need a separate "add" call, and they
stay pure functions of `(event, ctx)` — trivially unit-testable with an
in-memory fake (see `tests/conftest.py::FakeCtx`).

## The Rule interface

`src/sentinelx/detection/engine.py`:

```python
class Rule(ABC):
    id: str            # stable rule identifier, e.g. "SX-BRUTE-FORCE"
    name: str          # human-readable name
    description: str
    mitre: dict        # {"tactic", "technique_id", "technique"}
    severity: str      # "critical" | "high" | "medium" | "low"
    base_score: int    # 0-100 nominal score

    @abstractmethod
    def evaluate(self, event: Event, ctx) -> list[Alert]: ...
```

`DetectionEngine(rules=None)`:

- `rules=None` (default): loads the four builtin rules plus every Sigma rule in
  `SENTINELX_SIGMA_DIR` (env var) or the bundled `src/sentinelx/detection/sigma_rules/`.
- explicit list: uses exactly those rules (used by tests).

`engine.evaluate(event, ctx)` runs each rule in order, catches *any* exception
per rule (logs it, continues), and returns the flattened alert list.

Alert construction goes through `build_alert(rule, event, title, evidence, ...)`
in `sentinelx/detection/rules/__init__.py`, which guarantees the invariant

```
alert.severity == score_to_level(compute_score(rule.base_score))
```

so severity and score can never disagree.

## Builtin rules

| id | signal | MITRE | severity (score) | evidence |
|----|--------|-------|------------------|----------|
| `SX-BRUTE-FORCE` | 5+ failed auth (`auth_failed`/`logon_failed`) from one `src_ip` in 300 s | T1110.001 | high (75) | `fail_count`, `window_s` |
| `SX-PORT-SCAN` | 15+ distinct `dst_port` from one `src_ip` in 60 s | T1046 | medium (55) | `port_count`, `window_s` |
| `SX-WEB-ATTACK` | SQLi / XSS / traversal regex on `http_uri`, `user_agent`, `message` | T1190 | high (80) | `attack_type`, `pattern`, `matched`, `field` |
| `SX-PRIV-ESC` | `sudo`/`su` to interactive root shell, Windows EventID 4672, or `action == "privilege_escalation"` | T1068 | critical (85) | `method` |

Notes:

- **Brute force** fires on the 5th failure and on every subsequent failure while
  the window stays hot. Successful logins and non-`authentication` events never count.
- **Port scan** counts *distinct* ports, so a busy HTTPS client never trips it.
- **Web attack** checks SQLi patterns first, then XSS, then traversal; the title
  is prefixed `[sqli]` / `[xss]` / `[traversal]`.
- **Privilege escalation**: `sudo ls` (no shell marker) does not match; only
  `-i`, `su -`, or `sudo su` in the message do. Windows 4672 is matched from
  `event.raw["EventID"]` (ints and numeric strings both work). Severity is
  `critical` because `score_to_level(85) == "critical"` — the severity always
  follows the score.

Sigma coverage ships alongside in `sigma_rules/` (8 rules); e.g. Windows 4672
privilege assignment is detectable both via Sigma and via `SX-PRIV-ESC`.

## Writing a new rule

1. Create `src/sentinelx/detection/rules/my_rule.py`:

```python
from typing import Any
from sentinelx.common import Alert, Event
from sentinelx.detection.engine import Rule
from sentinelx.detection.rules import build_alert

class MyRule(Rule):
    id = "SX-MY-RULE"
    name = "Short human name"
    description = "What it detects and why it matters."
    mitre = {
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
    }
    severity = "medium"
    base_score = 55  # must satisfy score_to_level(base_score) == severity

    def evaluate(self, event: Event, ctx: Any) -> list[Alert]:
        if event.event_type != "process":
            return []
        # ... stateful correlation via ctx if needed ...
        return [build_alert(self, event, title="...", evidence={"key": "value"})]
```

2. Export it from `src/sentinelx/detection/rules/__init__.py` (import the class,
   append an instance to `BUILTIN_RULES`).
3. Add tests in `tests/test_rules.py` driving it with `FakeCtx` over synthetic
   event sequences, and extend `tests/test_mitre.py` coverage implicitly (it
   iterates `BUILTIN_RULES`).
4. If the signal is a simple single-event pattern, consider a Sigma YAML rule in
   `sigma_rules/` instead — see `docs/04-sigma-guide.md`.

Rule authoring checklist:

- Return `[]` fast for events the rule cannot fire on (cheap pre-filter first).
- Keep per-event work O(1)-ish; never do I/O or network calls.
- Key `ctx` entries by the correlation dimension (`f"my_rule:{event.src_ip}"`).
- Put machine-readable facts in `evidence`; keep `title` short and specific.
- Pick `technique_id` from `sentinelx.common.mitre.TECHNIQUES`.
- Keep `severity`/`base_score` consistent via `score_to_level`.
