"""Automated response actions for SentinelX alerts.

``block_ip``/``unblock_ip`` manage host firewall drops, ``slack`` and
``telegram`` notify operators, and ``policy`` maps alert severity to the
actions to run.
"""

from sentinelx.response.blocker import block_ip, unblock_ip
from sentinelx.response.policy import act, load_policy

__all__ = ["act", "block_ip", "load_policy", "unblock_ip"]
