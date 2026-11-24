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
