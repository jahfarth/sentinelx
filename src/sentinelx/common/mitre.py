"""MITRE ATT&CK technique lookup used when building alerts.

Maps technique_id -> {"tactic": ..., "technique": ...}.
"""

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1110.001": {
        "tactic": "Credential Access",
        "technique": "Brute Force: Password Guessing",
    },
    "T1046": {
        "tactic": "Discovery",
        "technique": "Network Service Discovery",
    },
    "T1190": {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
    },
    "T1068": {
        "tactic": "Privilege Escalation",
        "technique": "Exploitation for Privilege Escalation",
    },
    "T1078": {
        "tactic": "Persistence",
        "technique": "Valid Accounts",
    },
    "T1059": {
        "tactic": "Execution",
        "technique": "Command and Scripting Interpreter",
    },
    "T1133": {
        "tactic": "Initial Access",
        "technique": "External Remote Services",
    },
}


def lookup(technique_id: str) -> dict[str, str]:
    """Return the tactic/technique mapping for *technique_id*.

    Falls back to an "Unknown" mapping when the id is not in the table, so
    callers never have to guard the lookup themselves.
    """
    entry = TECHNIQUES.get(technique_id)
    if entry is None:
        return {"tactic": "Unknown", "technique": "Unknown"}
    return {"tactic": entry["tactic"], "technique": entry["technique"]}
