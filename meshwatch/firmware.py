"""Firmware versions and settings drift across watched nodes.

Once a day meshwatch asks each node it holds the admin password for for its
firmware version (`ver`) and a few settings (`get ...`), and checks GitHub for
the newest MeshCore release. The fleet view then flags old firmware and
settings that differ between nodes on the same network.
"""
from __future__ import annotations

import json
import logging
import re
import time
from collections import Counter

import httpx

log = logging.getLogger(__name__)

INVENTORY_EVERY_S = 86400
# Settings worth comparing between repeaters on one network. "get freq"/"get radio" must match
# to talk at all, but the full radio line is still useful to see.
SETTINGS = ["radio", "tx", "repeat", "flood.max", "advert.interval", "flood.advert.interval",
            "txdelay", "direct.txdelay", "path.hash.mode"]
REPEATER_ONLY = {"repeat"}
RELEASES_URL = "https://api.github.com/repos/meshcore-dev/MeshCore/releases?per_page=40"
# GitHub release tag prefix -> node type it applies to
TAG_TYPES = {"repeater-v": "repeater", "room-server-v": "room"}
VERSION = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?")


def inventory_commands(node_type: str | None) -> list[str]:
    keys = [k for k in SETTINGS if node_type in (None, "repeater", "unknown") or k not in REPEATER_ONLY]
    return ["ver"] + [f"get {k}" for k in keys]


def clean_reply(text: str | None) -> str | None:
    """`> 22` -> `22`; errors and unknown commands -> None."""
    if text is None:
        return None
    text = text.strip()
    if text.startswith(">"):
        text = text[1:].strip()
    low = text.lower()
    if not text or low.startswith(("??", "error", "unknown", "err:")):
        return None
    return text


def parse_version(text: str | None) -> tuple[int, int, int] | None:
    """MeshCore `ver` replies look like `v1.18.0-abc123 (Build: ...)`. Others (e.g. openHop) -> None."""
    m = VERSION.match((text or "").strip())
    if not m:
        return None
    return int(m[1]), int(m[2]), int(m[3] or 0)


def fmt_version(v) -> str:
    return ".".join(str(x) for x in v) if v else "?"


async def fetch_latest(db) -> dict | None:
    """Newest release per node type from GitHub, stored in settings `fw_latest`."""
    try:
        async with httpx.AsyncClient(timeout=20, headers={"Accept": "application/vnd.github+json",
                                                          "User-Agent": "meshwatch"}) as client:
            r = await client.get(RELEASES_URL)
        r.raise_for_status()
        releases = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("firmware release check failed: %s", exc)
        return None
    latest: dict[str, list[int]] = {}
    for rel in releases:
        if rel.get("prerelease") or rel.get("draft"):
            continue
        tag = rel.get("tag_name", "")
        for prefix, node_type in TAG_TYPES.items():
            if tag.startswith(prefix):
                v = parse_version(tag[len(prefix):])
                if v and (node_type not in latest or v > tuple(latest[node_type])):
                    latest[node_type] = list(v)
    if not latest:
        return None
    value = {"versions": latest, "checked": time.time()}
    db.set_setting("fw_latest", value)
    return value


def latest_for(db, node_type: str | None) -> tuple[int, int, int] | None:
    data = db.get_setting("fw_latest") or {}
    v = (data.get("versions") or {}).get("room" if node_type == "room" else "repeater")
    return tuple(v) if v else None


def outdated(db, node_type: str | None, firmware: str | None) -> tuple[int, int, int] | None:
    """The newer release if this node's MeshCore firmware is behind it."""
    have, newest = parse_version(firmware), latest_for(db, node_type)
    if have and newest and have < newest:
        return newest
    return None


def fleet(db, monitor, radio_names: dict[str, str]) -> list[dict]:
    """Groups of watched nodes per network (companion), each with settings and drift flags."""
    rows = db.q("SELECT w.pubkey, w.label, w.radio_id, w.admin_pw IS NOT NULL AS admin, s.poll_radio,"
                " s.firmware, s.config, s.config_at FROM watched w LEFT JOIN node_state s USING(pubkey)")
    groups: dict[str, list[dict]] = {}
    for r in rows:
        seen = monitor.directory.get(r["pubkey"])
        node_type = seen.node_type if seen else None
        net = r["radio_id"] or r["poll_radio"] or ""
        newer = outdated(db, node_type, r["firmware"])
        groups.setdefault(net, []).append({
            "pubkey": r["pubkey"], "label": r["label"] or (seen.name if seen and seen.name else r["pubkey"][:8]),
            "node_type": node_type, "admin": bool(r["admin"]), "firmware": r["firmware"],
            "version": fmt_version(parse_version(r["firmware"])) if parse_version(r["firmware"]) else None,
            "newer": fmt_version(newer) if newer else None,
            "config": json.loads(r["config"]) if r["config"] else {}, "config_at": r["config_at"]})
    out = []
    for net, nodes in sorted(groups.items(), key=lambda g: radio_names.get(g[0], "~")):
        drift = {}
        for key in SETTINGS:
            values = [n["config"].get(key) for n in nodes if n["config"].get(key) is not None]
            counts = Counter(values)
            if len(counts) > 1:
                top = counts.most_common(2)
                mode = top[0][0] if top[0][1] > top[1][1] else None   # tie -> flag every value
                drift[key] = mode
        for n in nodes:
            n["differs"] = sorted(k for k, mode in drift.items()
                                  if n["config"].get(k) is not None and n["config"][k] != mode)
        out.append({"network": radio_names.get(net, net or "not polled yet"), "nodes": nodes,
                    "drift": sorted(drift)})
    return out
