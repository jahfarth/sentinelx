"""Compile a supported subset of Sigma detection rules into Event predicates.

Supported Sigma subset
-----------------------
* Rule fields: ``title``, ``id``, ``description``, ``logsource`` (``category`` /
  ``product``), ``detection`` (named selections plus a ``condition`` string) and
  ``level``. Anything else (``status``, ``author``, ``tags``, ``references``,
  ...) is accepted and ignored, except ``tags`` which are scanned for
  ``attack.<technique>`` entries used to attach MITRE metadata.
* Selection values: a mapping of ``field: value`` (AND semantics) or a list of
  such mappings (OR semantics).
* Field modifiers: ``|contains``, ``|contains|all``, ``|startswith``,
  ``|endswith`` and ``|re``. All string matching is case-insensitive (the
  ``|re`` modifier included — a deliberate, documented deviation from upstream
  Sigma, which is case-sensitive there).
* Plain string values support ``*`` wildcards (glob-style, case-insensitive).
  Lists of values mean OR. Numbers compare with numeric equality (a string
  ``"4625"`` in the event matches the integer ``4625`` in the rule).
* Condition grammar: ``and`` / ``or`` / ``not``, parentheses, ``N of <glob>``
  and ``all of <glob>`` over selection names (``1 of sel*``), plus the
  ``1 of them`` / ``all of them`` shorthands.
* Logsource mapping: category ``authentication``/``web``/``process_creation``
  (also ``process`` and ``network``) constrains ``event.event_type``; product
  ``windows``/``apache``/``nginx`` constrains ``event.source``. Unknown
  categories/products impose no constraint. The logsource check runs first;
  the condition is evaluated only when it passes.

Field names are translated through :data:`FIELD_MAP`; ``raw.*`` paths are
resolved inside ``event.raw`` and any other name resolves as a direct
attribute of the :class:`~sentinelx.common.Event`.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sentinelx.common import Event

logger = logging.getLogger(__name__)

#: Sigma field name -> Event attribute path (``raw.*`` is resolved in event.raw).
FIELD_MAP: dict[str, str] = {
    "EventID": "raw.EventID",
    "IpAddress": "src_ip",
    "TargetUserName": "user",
    "TargetDomainName": "raw.TargetDomainName",
    "Image": "process",
    "CommandLine": "raw.CommandLine",
    "ParentImage": "raw.ParentImage",
    "Url": "http_uri",
    "UserAgent": "user_agent",
    "cs-method": "http_method",
    "cs-uri-stem": "http_uri",
    "c-ip": "src_ip",
    "s-ip": "dst_ip",
}

_CATEGORY_MAP: dict[str, str] = {
    "authentication": "authentication",
    "web": "web",
    "process_creation": "process",
    "process": "process",
    "network": "network",
}

_PRODUCT_MAP: dict[str, str] = {
    "windows": "windows",
    "apache": "apache",
    "nginx": "nginx",
}

#: Sigma level -> nominal base score used when raising alerts.
LEVEL_SCORES: dict[str, int] = {
    "informational": 10,
    "low": 30,
    "medium": 55,
    "high": 75,
    "critical": 90,
}

_SINGLE_MODIFIERS = {"contains", "startswith", "endswith", "re"}


@dataclass(frozen=True)
class CompiledSigmaRule:
    """A Sigma rule compiled to a callable predicate plus its metadata."""

    rule_id: str
    name: str
    description: str
    level: str
    match: Callable[[Event], bool]
    tags: tuple[str, ...] = ()


@dataclass
class _FieldMatcher:
    """One ``field|modifier: value`` test inside a selection."""

    path: str
    modifier: str  # "", "contains", "contains_all", "startswith", "endswith", "re"
    patterns: list[Any]

    def matches(self, event: Event) -> bool:
        value = _resolve(event, self.path)
        if self.modifier == "contains_all":
            return value is not None and all(
                str(p).lower() in str(value).lower() for p in self.patterns
            )
        return any(_match_value(p, value, self.modifier) for p in self.patterns)


def _resolve(event: Event, dotted: str) -> Any:
    """Resolve a dotted attribute path against an Event.

    ``raw.EventID`` looks inside ``event.raw``; anything else walks attributes
    (dicts are supported at any level). Missing links yield ``None``.
    """
    current: Any = event
    for part in dotted.split("."):
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
    return current


def _numeric_eq(pattern: int | float, value: Any) -> bool:
    """Numeric equality with graceful coercion of string event values."""
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return value == pattern
    try:
        return float(value) == float(pattern)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return str(value) == str(pattern)


def _wildcard_regex(pattern: str) -> str:
    """Translate a Sigma ``*`` glob into an equivalent regex fragment."""
    return "".join(".*" if ch == "*" else re.escape(ch) for ch in pattern)


def _match_value(pattern: Any, value: Any, modifier: str) -> bool:
    """Match a single rule value against a single event value."""
    if value is None:
        return False
    if modifier == "re":
        return re.search(str(pattern), str(value), re.IGNORECASE) is not None
    if isinstance(pattern, bool):
        return isinstance(value, bool) and value == pattern
    if isinstance(pattern, (int, float)):
        return _numeric_eq(pattern, value)
    pat = str(pattern)
    val = str(value)
    lowered_val, lowered_pat = val.lower(), pat.lower()
    if modifier == "contains":
        return lowered_pat in lowered_val
    if modifier == "startswith":
        return lowered_val.startswith(lowered_pat)
    if modifier == "endswith":
        return lowered_val.endswith(lowered_pat)
    if "*" in pat:
        return re.fullmatch(_wildcard_regex(pat), val, re.IGNORECASE) is not None
    return lowered_val == lowered_pat


def _parse_field_spec(spec: str) -> tuple[str, str]:
    """Split ``Field|modifier|...`` into (resolved path, modifier key)."""
    parts = spec.split("|")
    name = parts[0].strip()
    if not name:
        raise ValueError(f"invalid empty field name in spec {spec!r}")
    modifiers = [p.strip().lower() for p in parts[1:] if p.strip()]
    if not modifiers:
        modifier = ""
    elif modifiers == ["contains", "all"]:
        modifier = "contains_all"
    elif len(modifiers) == 1 and modifiers[0] in _SINGLE_MODIFIERS:
        modifier = modifiers[0]
    else:
        raise ValueError(f"unsupported modifier(s) in field spec {spec!r}")
    return FIELD_MAP.get(name, name), modifier


def _compile_selection(name: str, body: Any) -> Callable[[Event], bool]:
    """Compile one named selection into an Event predicate."""
    if isinstance(body, dict):
        bodies = [body]
    elif isinstance(body, list) and body and all(isinstance(b, dict) for b in body):
        bodies = body
    else:
        raise ValueError(
            f"selection {name!r} must be a mapping or a list of mappings, got {body!r}"
        )
    clauses: list[list[_FieldMatcher]] = []
    for mapping in bodies:
        matchers = []
        for spec, value in mapping.items():
            path, modifier = _parse_field_spec(str(spec))
            patterns = list(value) if isinstance(value, list) else [value]
            if modifier == "contains_all" and not isinstance(value, list):
                raise ValueError(f"selection {name!r}: '|contains|all' requires a list value")
            matchers.append(_FieldMatcher(path=path, modifier=modifier, patterns=patterns))
        clauses.append(matchers)

    def predicate(event: Event) -> bool:
        return any(all(m.matches(event) for m in clause) for clause in clauses)

    return predicate


_TOKEN_RE = re.compile(r"\(|\)|\d+|[A-Za-z_][A-Za-z0-9_\-\*\./]*")


class _ConditionParser:
    """Recursive-descent parser for Sigma condition strings.

    Grammar (keywords case-insensitive)::

        expr    := or_expr
        or_expr := and_expr ("or" and_expr)*
        and_expr:= unary ("and" unary)*
        unary   := "not" unary | of_expr | primary
        of_expr := ("all" | NUMBER) "of" target
        target  := "them" | glob-pattern
        primary := IDENT | "(" expr ")"
    """

    def __init__(self, text: str, selection_names: set[str]) -> None:
        self.tokens = _TOKEN_RE.findall(text)
        self.pos = 0
        self.selection_names = selection_names

    def parse(self) -> Callable[[dict[str, bool]], bool]:
        if not self.tokens:
            raise ValueError("condition must not be empty")
        node = self._parse_or()
        if self.pos != len(self.tokens):
            raise ValueError(f"unexpected token {self.tokens[self.pos]!r} in condition")
        return node

    # -- token helpers -----------------------------------------------------
    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _peek_is(self, keyword: str) -> bool:
        tok = self._peek()
        return tok is not None and tok.lower() == keyword

    def _next(self) -> str:
        tok = self._peek()
        if tok is None:
            raise ValueError("unexpected end of condition")
        self.pos += 1
        return tok

    def _expect(self, keyword: str) -> None:
        if not self._peek_is(keyword):
            raise ValueError(f"expected {keyword!r} in condition, got {self._peek()!r}")
        self.pos += 1

    # -- grammar -----------------------------------------------------------
    def _parse_or(self) -> Callable[[dict[str, bool]], bool]:
        left = self._parse_and()
        while self._peek_is("or"):
            self.pos += 1
            right = self._parse_and()
            left = _combine_or(left, right)
        return left

    def _parse_and(self) -> Callable[[dict[str, bool]], bool]:
        left = self._parse_unary()
        while self._peek_is("and"):
            self.pos += 1
            right = self._parse_unary()
            left = _combine_and(left, right)
        return left

    def _parse_unary(self) -> Callable[[dict[str, bool]], bool]:
        tok = self._peek()
        if tok is None:
            raise ValueError("unexpected end of condition")
        if self._peek_is("not"):
            self.pos += 1
            operand = self._parse_unary()
            return lambda results, op=operand: not op(results)
        if tok.isdigit() or self._peek_is("all"):
            return self._parse_of()
        return self._parse_primary()

    def _parse_of(self) -> Callable[[dict[str, bool]], bool]:
        head = self._next()
        self._expect("of")
        target = self._next()
        names = self._expand_target(target)
        if head.lower() == "all":
            return lambda results, ns=names: all(results[n] for n in ns)
        count = int(head)
        if count < 1:
            raise ValueError("'0 of' is not a valid condition quantifier")
        return lambda results, ns=names, n=count: sum(1 for x in ns if results[x]) >= n

    def _expand_target(self, target: str) -> list[str]:
        if target.lower() == "them":
            names = sorted(self.selection_names)
        else:
            names = sorted(n for n in self.selection_names if fnmatch.fnmatchcase(n, target))
        if not names:
            raise ValueError(f"condition target {target!r} matches no selections")
        return names

    def _parse_primary(self) -> Callable[[dict[str, bool]], bool]:
        tok = self._next()
        if tok == "(":
            node = self._parse_or()
            if self._peek() != ")":
                raise ValueError("unbalanced parenthesis in condition")
            self.pos += 1
            return node
        if tok == ")":
            raise ValueError("unbalanced parenthesis in condition")
        if tok not in self.selection_names:
            raise ValueError(f"condition references unknown selection {tok!r}")
        return lambda results, name=tok: results[name]


def _combine_and(
    left: Callable[[dict[str, bool]], bool], right: Callable[[dict[str, bool]], bool]
) -> Callable[[dict[str, bool]], bool]:
    return lambda results, lhs=left, rhs=right: lhs(results) and rhs(results)


def _combine_or(
    left: Callable[[dict[str, bool]], bool], right: Callable[[dict[str, bool]], bool]
) -> Callable[[dict[str, bool]], bool]:
    return lambda results, lhs=left, rhs=right: lhs(results) or rhs(results)


def _logsource_predicate(logsource: dict[str, Any]) -> Callable[[Event], bool]:
    """Build the logsource pre-filter; unknown categories/products are ignored."""
    checks: list[Callable[[Event], bool]] = []
    category = logsource.get("category")
    if category is not None:
        want = _CATEGORY_MAP.get(str(category).lower())
        if want is not None:
            checks.append(lambda event, w=want: event.event_type == w)
    product = logsource.get("product")
    if product is not None:
        want = _PRODUCT_MAP.get(str(product).lower())
        if want is not None:
            checks.append(lambda event, w=want: event.source == w)
    return lambda event: all(check(event) for check in checks)


@dataclass
class _CompilerState:
    """Scratch state threaded through one compile() call (avoids re-entrancy bugs)."""

    selections: dict[str, Callable[[Event], bool]] = field(default_factory=dict)


class SigmaCompiler:
    """Compile Sigma rule dicts (parsed YAML) into :class:`Event` predicates."""

    def compile(self, rule_dict: dict[str, Any]) -> Callable[[Event], bool]:
        """Compile a rule dict to a predicate; raises :class:`ValueError` if invalid."""
        return self.compile_record(rule_dict).match

    def compile_file(self, path: str | Path) -> Callable[[Event], bool]:
        """Load a Sigma YAML file and compile it; raises :class:`ValueError` if invalid."""
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            raise ValueError(f"Sigma file {path} must contain a YAML mapping")
        return self.compile(data)

    def compile_record(self, rule_dict: dict[str, Any]) -> CompiledSigmaRule:
        """Compile a rule dict to predicate plus metadata record."""
        if not isinstance(rule_dict, dict):
            raise ValueError("Sigma rule must be a mapping")
        title = rule_dict.get("title")
        if not title or not isinstance(title, str):
            raise ValueError("Sigma rule requires a non-empty string 'title'")
        rule_id = rule_dict.get("id")
        if not rule_id or not isinstance(rule_id, str):
            raise ValueError(f"Sigma rule {title!r} requires a non-empty string 'id'")
        description = rule_dict.get("description") or ""
        if not isinstance(description, str):
            raise ValueError(f"Sigma rule {title!r}: 'description' must be a string")
        level = rule_dict.get("level")
        if not isinstance(level, str) or level.lower() not in LEVEL_SCORES:
            raise ValueError(f"Sigma rule {title!r}: 'level' must be one of {sorted(LEVEL_SCORES)}")
        logsource = rule_dict.get("logsource") or {}
        if not isinstance(logsource, dict):
            raise ValueError(f"Sigma rule {title!r}: 'logsource' must be a mapping")
        detection = rule_dict.get("detection")
        if not isinstance(detection, dict):
            raise ValueError(f"Sigma rule {title!r} requires a 'detection' mapping")
        condition = detection.get("condition")
        if not isinstance(condition, str) or not condition.strip():
            raise ValueError(f"Sigma rule {title!r} requires a non-empty 'condition' string")

        state = _CompilerState()
        for name, body in detection.items():
            if name == "condition":
                continue
            if not isinstance(name, str):
                raise ValueError(f"Sigma rule {title!r}: selection names must be strings")
            state.selections[name] = _compile_selection(name, body)
        if not state.selections:
            raise ValueError(f"Sigma rule {title!r}: 'detection' defines no selections")

        condition_fn = _ConditionParser(condition, set(state.selections)).parse()
        logsource_fn = _logsource_predicate(logsource)
        selection_items = list(state.selections.items())
        tags = rule_dict.get("tags") or []
        if not isinstance(tags, list) or any(not isinstance(t, str) for t in tags):
            raise ValueError(f"Sigma rule {title!r}: 'tags' must be a list of strings")

        def match(event: Event) -> bool:
            if not logsource_fn(event):
                return False
            results = {name: predicate(event) for name, predicate in selection_items}
            try:
                return bool(condition_fn(results))
            except Exception:
                logger.exception("Sigma condition evaluation failed for rule %s", rule_id)
                return False

        return CompiledSigmaRule(
            rule_id=rule_id,
            name=title,
            description=description,
            level=level.lower(),
            match=match,
            tags=tuple(tags),
        )
