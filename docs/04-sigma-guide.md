# Sigma Guide

SentinelX compiles a pragmatic subset of [Sigma](https://github.com/SigmaHQ/sigma)
rules to Python predicates via `SigmaCompiler` (`src/sentinelx/detection/sigma.py`).
Drop a `.yml` file in `src/sentinelx/detection/sigma_rules/` (or point
`SENTINELX_SIGMA_DIR` elsewhere) and the engine picks it up automatically.

## Minimal rule

```yaml
title: Windows failed logon (4625)
id: c7681794-6bff-42fe-aeed-4d9f42021b45
description: Detects Windows failed logon events (Security EventID 4625).
logsource:
  category: authentication
  product: windows
detection:
  selection:
    EventID: 4625
  condition: selection
level: medium
tags:
  - attack.t1110.001
```

Required fields: `title`, `id`, `detection` (with a `condition`), `level`.
`description`, `logsource`, `tags`, `status`, `author`, `date` are optional but
recommended. `tags` entries of the form `attack.t1110.001` attach MITRE metadata
to the generated alerts (resolved against `sentinelx.common.mitre.TECHNIQUES`).
Anything invalid raises `ValueError` at compile time — fail fast, not at 3 AM.

## Field map

Sigma field names translate to `Event` attributes before matching:

| Sigma field | Event attribute |
|---|---|
| `EventID` | `raw.EventID` (inside `event.raw`) |
| `IpAddress`, `c-ip` | `src_ip` |
| `s-ip` | `dst_ip` |
| `TargetUserName` | `user` |
| `TargetDomainName` | `raw.TargetDomainName` |
| `Image` | `process` |
| `CommandLine`, `ParentImage` | `raw.CommandLine`, `raw.ParentImage` |
| `Url`, `cs-uri-stem` | `http_uri` |
| `cs-method` | `http_method` |
| `UserAgent` | `user_agent` |

Unlisted names resolve as direct `Event` attributes (`action`, `message`,
`host`, ...); `raw.*` paths resolve inside `event.raw`.

## Selections

A selection is a mapping of `field: value` (AND) or a list of mappings (OR):

```yaml
detection:
  sel_root:
    TargetUserName: root
  sel_failed:
    action:
      - auth_failed     # lists mean OR
      - logon_failed
  sel_either:           # list of mappings means OR
    - TargetUserName: admin
    - TargetUserName: administrator
```

### Value modifiers

| Modifier | Meaning |
|---|---|
| (none) | exact match; `*` wildcards, case-insensitive (`Image: '*sudo*'`) |
| `\|contains` | substring, case-insensitive |
| `\|contains\|all` | *all* listed substrings present (value must be a list) |
| `\|startswith` / `\|endswith` | prefix/suffix, case-insensitive |
| `\|re` | regex search, **case-insensitive** (deviation from upstream Sigma) |

Numbers compare numerically: `EventID: 4625` matches both the int `4625` and
the string `"4625"` in the event.

## Conditions

Full boolean grammar over selection names:

```yaml
condition: sel_a and not sel_b
condition: (sel_a or sel_b) and sel_c
condition: 1 of sel_*          # at least one selection whose name matches sel_*
condition: all of sel_*        # every matching selection
condition: 1 of them           # any selection
condition: all of them         # every selection
```

Keywords are case-insensitive; `N of <glob>` works for any N ≥ 1 with
fnmatch-style globs. Referencing an unknown selection, or a glob that matches
nothing, is a compile-time `ValueError`.

## Logsource mapping

Checked *before* the condition:

| logsource | constraint |
|---|---|
| `category: authentication` | `event_type == "authentication"` |
| `category: web` | `event_type == "web"` |
| `category: process_creation` (or `process`) | `event_type == "process"` |
| `category: network` | `event_type == "network"` |
| `product: windows` | `source == "windows"` |
| `product: apache` | `source == "apache"` |
| `product: nginx` | `source == "nginx"` |

Unknown categories/products (e.g. `product: linux`) impose no constraint —
the rule then matches on field values alone.

## Levels → severity

| Sigma level | base score | alert severity |
|---|---|---|
| `critical` | 90 | critical |
| `high` | 75 | high |
| `medium` | 55 | medium |
| `low` | 30 | low |
| `informational` | 10 | low |

Alert text is `Sigma rule matched: <title>` with evidence
`{"sigma_level": ..., "tags": [...]}`.

## Examples

**Sudo to root shell** (multi-selection condition):

```yaml
detection:
  selection_img:
    Image: '*sudo*'
  selection_shell:
    CommandLine|contains:
      - 'sudo su'
      - 'su -'
      - '-i'
  condition: selection_img and selection_shell
```

**Web SQLi probe** (contains + field map):

```yaml
logsource:
  category: web
  product: apache
detection:
  selection:
    cs-uri-stem|contains:
      - 'union select'
      - "' or '1'='1"
      - 'information_schema'
      - 'benchmark('
  condition: selection
level: high
```

## Supported subset vs. upstream Sigma

Deliberately *not* supported: `|all` on plain values (use `|contains|all`),
`near`/`windash` modifiers, `base64` encodings, aggregation conditions
(`count() > N`), `timeframe`, field-to-field references, and multi-document
rules. Stateful thresholds belong in Python rules (see
`docs/03-detection-engine.md`); Sigma here is for single-event patterns.

Programmatic use:

```python
from sentinelx.detection.sigma import SigmaCompiler

compiler = SigmaCompiler()
match = compiler.compile(rule_dict)        # Callable[[Event], bool]
match = compiler.compile_file("rule.yml")  # same, from disk
record = compiler.compile_record(rule_dict)  # predicate + id/name/level/tags
```
