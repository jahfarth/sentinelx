"""Host firewall blocker: drop (and later un-drop) attacker IPs.

``block_ip`` inserts an ``iptables``/``ip6tables`` DROP rule for the given
IP and records its expiry in a module-level dict; ``unblock_ip`` deletes
the rule again. Both are dry-run by default (``SENTINELX_DRY_RUN`` unset or
anything other than ``"0"``): the command is logged and ``True`` returned
without touching the firewall.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
import time

log = logging.getLogger(__name__)

_block_expiry: dict[str, float] = {}


def _dry_run() -> bool:
    return os.environ.get("SENTINELX_DRY_RUN", "1") != "0"


def _validated(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Return the parsed IP or raise ``ValueError`` when invalid."""
    try:
        return ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {ip!r}") from exc


def _firewall_cmd(ip: str, insert: bool) -> list[str]:
    """Build the iptables/ip6tables command for *ip* (insert or delete)."""
    binary = "ip6tables" if ":" in ip else "iptables"
    action = "-I" if insert else "-D"
    return [binary, action, "INPUT", "-s", ip, "-j", "DROP"]


def block_ip(ip: str, duration_s: int = 3600) -> bool:
    """Block *ip* at the host firewall for *duration_s* seconds.

    Returns ``True`` when the rule was installed (or dry-run logged),
    ``False`` when the firewall command failed. Raises ``ValueError``
    for invalid IPs.
    """
    parsed = _validated(ip)
    cmd = _firewall_cmd(str(parsed), insert=True)
    if _dry_run():
        log.info("[dry-run] would run: %s", " ".join(cmd))
        _block_expiry[str(parsed)] = time.time() + duration_s
        return True
    try:
        # Fixed argv, no shell; the IP was validated by ipaddress above.
        subprocess.run(cmd, check=True, timeout=15, capture_output=True)  # noqa: S603
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        log.error("failed to block %s: %s", ip, exc)
        return False
    _block_expiry[str(parsed)] = time.time() + duration_s
    log.info("blocked %s for %ds", ip, duration_s)
    return True


def unblock_ip(ip: str) -> bool:
    """Remove the firewall DROP rule for *ip*.

    Returns ``True`` when the rule was removed (or dry-run logged),
    ``False`` when the command failed. Raises ``ValueError`` for invalid
    IPs.
    """
    parsed = _validated(ip)
    cmd = _firewall_cmd(str(parsed), insert=False)
    if _dry_run():
        log.info("[dry-run] would run: %s", " ".join(cmd))
        _block_expiry.pop(str(parsed), None)
        return True
    try:
        # Fixed argv, no shell; the IP was validated by ipaddress above.
        subprocess.run(cmd, check=True, timeout=15, capture_output=True)  # noqa: S603
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        log.error("failed to unblock %s: %s", ip, exc)
        return False
    _block_expiry.pop(str(parsed), None)
    log.info("unblocked %s", ip)
    return True


def blocked_until(ip: str) -> float | None:
    """Return the epoch expiry of the current block for *ip*, if any."""
    return _block_expiry.get(ip)
