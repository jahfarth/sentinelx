# Automated Response

How SentinelX reacts to alerts without human intervention: the firewall
blocker, the Slack/Telegram notifiers, and the YAML policy engine that
maps alerts to actions.

## Architecture

```
Alert --> policy.act(alert) --> ["block_ip:1.2.3.4", "slack", ...]
            |
            +-- load policies/policy.yaml (or SENTINELX_POLICY_PATH)
            +-- first matching rule wins per rule; every matching rule's
                actions run in order
            +-- each action guarded: failures log and continue, act() never raises
```

`worker/pipeline.py` calls `policy.act(alert)` for every persisted
alert. `act` returns the names of the actions actually taken.

## Policy file reference

`policies/policy.yaml`:

```yaml
rules:
  - name: block-critical-attackers
    match:
      severity: [critical]   # any of: severity, status, rule_id (lists)
      status: [new]          # every present key must match
    actions:
      - type: block
        duration_s: 7200     # iptables DROP for 2h
      - type: slack          # needs SLACK_WEBHOOK_URL
      - type: telegram       # needs TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID
```

- `match` keys are optional lists; an alert matches a rule when it
  satisfies **every** present key (`severity` ∈ list, `status` ∈ list,
  `rule_id` ∈ list). A rule with an empty `match` matches everything.
- Action types: `block` (drops the alert's **public** `src_ip`; skipped
  for private/missing IPs), `slack`, `telegram`. Unknown types log a
  warning and are skipped.
- Rules are evaluated in order; all matching rules fire.

## Blocker

`response/blocker.py::block_ip(ip, duration_s=3600) -> bool`:

- Validates with the `ipaddress` module (`ValueError` on invalid input).
- Inserts `iptables -I INPUT -s {ip} -j DROP` (`ip6tables` for IPv6)
  via `subprocess.run(check, timeout=15)`; records the expiry in a
  module-level dict. `unblock_ip(ip)` deletes the rule (`-D`).
- **Dry-run by default**: unless `SENTINELX_DRY_RUN=0`, the command is
  only logged and `True` is returned — safe to demo without root or a
  firewall.

## Notifiers

- `response/slack.py::notify(alert, webhook_url) -> bool` — POSTs a
  Block Kit section (with a plain-text fallback) to an incoming
  webhook; `True` on 2xx.
- `response/telegram.py::notify(alert, bot_token, chat_id) -> bool` —
  POSTs a Markdown summary to
  `https://api.telegram.org/bot{token}/sendMessage`; `True` when the
  response JSON has `ok: true`.

Both use `httpx` with a 10-second timeout, log failures, and return
`False` instead of raising. Credentials come from the environment
(`SLACK_WEBHOOK_URL`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`); when
unset, the policy step logs and skips quietly.
