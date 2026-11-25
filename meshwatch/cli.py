"""Remote CLI: command catalog (autocomplete) and guarded execution."""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

CATALOG = Path(__file__).parent / "data" / "cli_commands.json"


@lru_cache(maxsize=1)
def catalog() -> dict:
    return json.loads(CATALOG.read_text())


def commands_for(node_type: str | None) -> list[dict]:
    kind = {"room": "room", "sensor": "sensor"}.get(node_type or "", "repeater")
    return [c for c in catalog()["commands"] if kind in c.get("node_types", [kind])]


def match(command: str) -> dict | None:
    """Longest catalog entry whose cmd is a word-prefix of command."""
    text = " ".join(command.strip().lower().split())
    best = None
    for c in catalog()["commands"]:
        cmd = c["cmd"].lower()
        if (text == cmd or text.startswith(cmd + " ")) and (best is None or len(cmd) > len(best["cmd"])):
            best = c
    return best


DISRUPTIVE = re.compile(r"^(reboot|poweroff|shutdown|erase|start ota|password|set |tempradio|clear |region (load|remove|denyf|default)|setperm|gps setloc|io)")


def needs_confirm(command: str) -> bool:
    entry = match(command)
    if entry is not None:
        return bool(entry.get("confirm"))
    # Unknown commands: be careful with anything that looks like a change.
    return bool(DISRUPTIVE.match(command.strip().lower()))


def serial_only(command: str) -> bool:
    entry = match(command)
    return bool(entry and entry.get("serial_only"))


SECRET = re.compile(r"^(password\s+|set\s+\S*(?:password|secret|prv\.key)\S*\s+)(.+)$", re.I)
SET = re.compile(r"^set\s+(\S+)\s+\S")


def secret_value(command: str) -> str | None:
    """The secret in commands like `password x` or `set guest.password x` (never logged)."""
    m = SECRET.match(command.strip())
    return m[2] if m else None


def redact(text: str | None, secret: str | None) -> str | None:
    if text is None or not secret:
        return text
    return text.replace(secret, "••••")


def setting_key(command: str) -> str | None:
    """`set tx 22` -> `tx`, for reading the previous value first. None for secrets."""
    m = SET.match(command.strip().lower())
    if not m or secret_value(command):
        return None
    return m[1]
