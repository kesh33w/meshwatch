"""Alert rules and ntfy delivery.

Rules per watched node: silent, battery, signal (SNR drop vs baseline,
fewer observers hearing it, noise floor rise). Each rule fires once and
notifies again when it resolves. A system rule warns when no data source has
delivered anything for 15 minutes (silent alerts are paused meanwhile).

"Silent" is confirmed before it fires: a polled node must also have failed two
polls since it was last heard (meshwatch polls it early to find out), and the
condition must hold for 5 minutes. A daily summary goes out at a set local time.
"""
from __future__ import annotations

import base64
import json
import logging
import statistics
import time
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx

from . import config, firmware

log = logging.getLogger(__name__)
NOISE_RISE_DB = 10
SYSTEM = ""   # pubkey used for system alerts
CONFIRM_S = 300     # a silent condition must hold this long before it fires
VERIFY_GAP_S = 240  # minimum time between early "is it really silent?" polls


def tz(db) -> ZoneInfo:
    name = config.get(db, "general").get("timezone") or "UTC"
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def local(db, ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz(db))


class Notifier:
    def __init__(self, db, box, origin: str):
        self.db, self.box, self.origin = db, box, origin

    async def send(self, title: str, message: str, priority: int = 3, tags: str = "", path: str = "/",
                   actions: list[tuple[str, str]] | None = None) -> str | None:
        cfg = config.get(self.db, "ntfy")
        if not cfg.get("enabled") or not cfg.get("topic"):
            return "ntfy not configured"
        # HTTP headers are latin-1; ntfy reads RFC 2047 encoded-words for anything else (emoji in labels).
        headers = {"Title": header_text(title), "Priority": str(priority), "Click": self.origin + path}
        if tags:
            headers["Tags"] = tags
        if actions:
            # Only "view" actions: links open in the browser, where Cloudflare Access/passkey apply.
            headers["Actions"] = header_text("; ".join(f"view, {label.replace(',', ' ')}, {self.origin}{url}"
                                                       for label, url in actions))
        token = self.box.open(cfg.get("token_enc"))
        if token:
            headers["Authorization"] = f"Bearer {token}"
        url = cfg["server"].rstrip("/") + "/" + cfg["topic"]
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(url, content=message.encode(), headers=headers)
            if r.status_code >= 300:
                return f"ntfy HTTP {r.status_code}"
        except httpx.HTTPError as exc:
            return f"ntfy error: {exc}"
        return None


def header_text(text: str) -> str:
    try:
        text.encode("latin-1")
        return text
    except UnicodeEncodeError:
        return "=?UTF-8?B?" + base64.b64encode(text.encode()).decode() + "?="


def node_label(db, monitor, pubkey: str) -> str:
    row = db.one("SELECT label FROM watched WHERE pubkey=?", (pubkey,))
    if row and row["label"]:
        return row["label"]
    seen = monitor.directory.get(pubkey)
    return (seen.name if seen and seen.name else pubkey[:8])


def fmt_age(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 3600:
        return f"{seconds // 60} min"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / 86400:.1f} days"


class Alerts:
    def __init__(self, db, monitor, notifier, health, kick=None):
        self.db, self.monitor, self.notifier = db, monitor, notifier
        self.health = health            # callable -> last time any data arrived
        self.kick = kick or (lambda: None)   # wakes the poller after an early poll was scheduled
        self._signal_checked = 0.0
        self._pending: dict[str, float] = {}   # pubkey -> when the silent condition was first true

    def open_alert(self, pubkey: str, rule: str):
        return self.db.one("SELECT * FROM alerts WHERE pubkey=? AND rule=? AND resolved IS NULL", (pubkey, rule))

    async def _set(self, pubkey: str, rule: str, firing: bool, message: str, priority=4, tags="warning") -> None:
        current = self.open_alert(pubkey, rule)
        label = node_label(self.db, self.monitor, pubkey) if pubkey else "meshwatch"
        path = f"/nodes/{pubkey}" if pubkey else "/"
        actions = [("Open node", path), ("All alerts", "/alerts")] if pubkey else [("Open meshwatch", "/")]
        if firing and not current:
            self.db.x("INSERT INTO alerts(pubkey,rule,started,message) VALUES(?,?,?,?)",
                      (pubkey, rule, time.time(), message))
            body = "\n".join([message, *self.context(pubkey)])
            err = await self.notifier.send(f"{label}: {message}", body, priority, tags, path, actions)
            if err:
                log.warning("notify: %s", err)
        elif not firing and current:
            self.db.x("UPDATE alerts SET resolved=? WHERE id=?", (time.time(), current["id"]))
            lasted = fmt_age(time.time() - current["started"])
            err = await self.notifier.send(f"{label}: OK", f"Resolved after {lasted}: {current['message']}. {message}",
                                           2, "white_check_mark", path, actions)
            if err:
                log.warning("notify: %s", err)

    async def evaluate(self) -> None:
        now = time.time()
        cfg = config.get(self.db, "alerts")
        last_data = self.health()
        data_ok = last_data is not None and now - last_data < 900
        await self._set(SYSTEM, "no_data", not data_ok,
                        "No data from MQTT sources or the companion radio for 15 minutes" if not data_ok
                        else "Data is arriving again", 4, "rotating_light")
        check_signal = now - self._signal_checked > 600
        if check_signal:
            self._signal_checked = now
        for node in self.db.q("SELECT w.*, s.status, s.status_at, s.poll_fails, s.last_poll_at, s.next_poll_at"
                              " FROM watched w LEFT JOIN node_state s USING(pubkey) WHERE w.alerts_enabled=1"):
            key = node["pubkey"]
            if data_ok:
                await self._silent(node, cfg, now)
            await self._battery(node)
            if check_signal:
                await self._signal(node, cfg, now)
        # alerts for nodes no longer watched or with alerts disabled
        for row in self.db.q("SELECT a.id FROM alerts a LEFT JOIN watched w USING(pubkey)"
                             " WHERE a.resolved IS NULL AND a.pubkey<>'' AND (w.pubkey IS NULL OR w.alerts_enabled=0)"):
            self.db.x("UPDATE alerts SET resolved=? WHERE id=?", (now, row["id"]))

    def silent_threshold_min(self, node, cfg) -> int:
        if node["silent_min"]:
            return node["silent_min"]
        return cfg["polled_silent_min"] if node["poll_enabled"] else cfg["passive_silent_min"]

    async def _silent(self, node, cfg, now) -> None:
        key = node["pubkey"]
        live = self.monitor.live.get(key)
        since = (live.last_heard if live and live.last_heard else None) or node["added_at"]
        limit = self.silent_threshold_min(node, cfg) * 60
        silent = now - since > limit
        if not silent:
            self._pending.pop(key, None)
        elif not self.open_alert(key, "silent"):
            if node["poll_enabled"] and not ((node["poll_fails"] or 0) >= 2 and (node["last_poll_at"] or 0) > since):
                self._verify(node, now)       # ask the node before calling it silent
                return
            first = self._pending.setdefault(key, now)
            if now - first < CONFIRM_S:
                return
        msg = (f"Not heard for {fmt_age(now - since)}" if silent
               else f"Heard again ({live.last_heard_via if live else ''})")
        await self._set(key, "silent", silent, msg, 4, "warning")

    def _verify(self, node, now) -> None:
        """Bring the next poll forward so a silent node is confirmed (or not) quickly."""
        if (node["next_poll_at"] or 0) <= now + 60 or now - (node["last_poll_at"] or 0) < VERIFY_GAP_S:
            return
        self.db.x("INSERT INTO node_state(pubkey,next_poll_at) VALUES(?,?)"
                  " ON CONFLICT(pubkey) DO UPDATE SET next_poll_at=excluded.next_poll_at", (node["pubkey"], now))
        self.kick()

    def context(self, pubkey: str) -> list[str]:
        """Extra lines for a node notification: how it was last heard, battery, polling."""
        if not pubkey:
            return []
        lines = []
        live = self.monitor.live.get(pubkey)
        if live and live.last_heard:
            lines.append(f"Last heard {fmt_age(time.time() - live.last_heard)} ago via {live.last_heard_via}")
        state = self.db.one("SELECT status, poll_fails, last_error, last_poll_ok FROM node_state WHERE pubkey=?",
                            (pubkey,))
        if state and state["status"]:
            bat = json.loads(state["status"]).get("bat") or 0
            if bat > 0:
                lines.append(f"Battery {bat / 1000:.2f} V")
        if state and state["poll_fails"]:
            lines.append(f"Polls failing ×{state['poll_fails']}: {state['last_error']}")
        elif state and state["last_poll_ok"]:
            lines.append(f"Last poll OK {fmt_age(time.time() - state['last_poll_ok'])} ago")
        return lines

    # daily summary -------------------------------------------------------------
    def summary_due(self, now: float) -> bool:
        cfg = config.get(self.db, "ntfy")
        if not cfg.get("summary_enabled"):
            return False
        t = local(self.db, now)
        try:
            hh, mm = (int(x) for x in str(cfg.get("summary_time") or "08:00").split(":"))
        except ValueError:
            hh, mm = 8, 0
        today = t.strftime("%Y-%m-%d")
        return (t.hour, t.minute) >= (hh, mm) and self.db.get_setting("summary_sent") != today

    def summary(self, now: float) -> tuple[str, str, bool]:
        """(title, body, all_ok) for the daily summary."""
        nodes = self.db.q("SELECT w.pubkey, w.poll_enabled, s.status, s.poll_fails, s.last_error, s.firmware"
                          " FROM watched w LEFT JOIN node_state s USING(pubkey)")
        open_alerts = self.db.q("SELECT pubkey, rule, message, started FROM alerts WHERE resolved IS NULL"
                                " ORDER BY started")
        lines = []
        for a in open_alerts:
            label = node_label(self.db, self.monitor, a["pubkey"]) if a["pubkey"] else "meshwatch"
            lines.append(f"⚠ {label}: {a['message']} (for {fmt_age(now - a['started'])})")
        failing = [n for n in nodes if n["poll_enabled"] and (n["poll_fails"] or 0) >= 2]
        for n in failing:
            lines.append(f"Polling failing ×{n['poll_fails']}: {node_label(self.db, self.monitor, n['pubkey'])}"
                         f" ({n['last_error']})")
        batteries = []
        for n in nodes:
            bat = json.loads(n["status"]).get("bat") if n["status"] else None
            if bat and bat > 0:
                batteries.append(f"{node_label(self.db, self.monitor, n['pubkey'])} {bat / 1000:.2f} V")
        if batteries:
            lines.append("Batteries: " + ", ".join(batteries))
        old = []
        for n in nodes:
            seen = self.monitor.directory.get(n["pubkey"])
            newer = firmware.outdated(self.db, seen.node_type if seen else None, n["firmware"])
            if newer:
                old.append(f"{node_label(self.db, self.monitor, n['pubkey'])} "
                           f"{firmware.fmt_version(firmware.parse_version(n['firmware']))}")
        if old:
            lines.append(f"Firmware behind {firmware.fmt_version(firmware.latest_for(self.db, 'repeater'))}: "
                         + ", ".join(old))
        all_ok = not open_alerts and not failing
        if all_ok:
            title = f"meshwatch: all {len(nodes)} nodes OK"
        else:
            keys = {a["pubkey"] for a in open_alerts} | {n["pubkey"] for n in failing}
            title = f"meshwatch: {len(keys)} of {len(nodes)} nodes need attention"
            if "" in keys:
                title = "meshwatch: data sources down" if len(keys) == 1 else title
        return title, "\n".join(lines) or "Nothing to report.", all_ok

    async def maybe_summary(self, now: float | None = None) -> None:
        now = now or time.time()
        if not self.summary_due(now):
            return
        self.db.set_setting("summary_sent", local(self.db, now).strftime("%Y-%m-%d"))
        title, body, all_ok = self.summary(now)
        err = await self.notifier.send(title, body, 2 if all_ok else 3, "clipboard", "/",
                                       [("Open meshwatch", "/"), ("Fleet", "/fleet")])
        if err:
            log.warning("daily summary: %s", err)

    async def _battery(self, node) -> None:
        if not node["status"]:
            return
        bat = json.loads(node["status"]).get("bat") or 0
        if bat <= 0:
            return
        current = self.open_alert(node["pubkey"], "battery")
        threshold = node["battery_mv"]
        low = bat < threshold if not current else bat < threshold + 100
        await self._set(node["pubkey"], "battery", low,
                        f"Battery {bat / 1000:.2f} V (below {threshold / 1000:.2f} V)" if low
                        else f"Battery {bat / 1000:.2f} V", 4, "battery")

    async def _signal(self, node, cfg, now) -> None:
        key = node["pubkey"]
        window = cfg["snr_window_min"] * 60
        recent_start, base_start = now - window, now - cfg["snr_baseline_days"] * 86400
        min_n = cfg["snr_min_samples"]

        def per_observer(t0, t1):
            return {r["observer"]: (r["snr"], r["n"]) for r in self.db.q(
                "SELECT observer, SUM(snr*n)/SUM(n) AS snr, SUM(n) AS n FROM observations"
                " WHERE pubkey=? AND direct=1 AND snr IS NOT NULL AND ts>=? AND ts<? GROUP BY observer",
                (key, t0, t1))}

        recent, base = per_observer(recent_start, now + 1), per_observer(base_start, recent_start)
        common = [o for o in recent if o in base and recent[o][1] >= min_n and base[o][1] >= min_n]
        drop = None
        if common:
            drop = statistics.fmean(recent[o][0] - base[o][0] for o in common)
        current = self.open_alert(key, "snr")
        limit = node["snr_drop_db"]
        firing = drop is not None and (drop <= -limit if not current else drop <= -limit / 2)
        if drop is not None or current:
            await self._set(key, "snr", firing,
                            f"SNR down {abs(drop):.1f} dB vs {cfg['snr_baseline_days']}-day baseline"
                            f" ({len(common)} observers)" if firing else "SNR back to normal", 3, "signal_strength")

        counts = [r["c"] for r in self.db.q(
            "SELECT COUNT(DISTINCT observer) AS c FROM observations WHERE pubkey=? AND direct=1"
            " AND ts>=? AND ts<? GROUP BY CAST(ts/? AS INTEGER)", (key, base_start, recent_start, window))]
        if len(counts) >= 12:
            median = statistics.median(counts)
            heard_by = sum(1 for o in recent if recent[o][1] > 0)
            if median >= 2:
                few = heard_by < median * cfg["observer_drop_ratio"]
                await self._set(key, "observers", few,
                                f"Heard directly by {heard_by} observers (usually {median:g})" if few
                                else f"Heard directly by {heard_by} observers again", 3, "satellite")

        noise = [r["noise_floor"] for r in self.db.q(
            "SELECT noise_floor FROM status_samples WHERE pubkey=? AND ts>=? AND noise_floor IS NOT NULL"
            " AND noise_floor<0 ORDER BY ts", (key, base_start))]
        if len(noise) >= 12:
            baseline, latest = statistics.median(noise[:-3]), statistics.median(noise[-3:])
            rise = latest - baseline
            current = self.open_alert(key, "noise")
            firing = rise >= NOISE_RISE_DB if not current else rise >= NOISE_RISE_DB / 2
            await self._set(key, "noise", firing,
                            f"Noise floor {latest:g} dBm, {rise:+g} dB vs usual {baseline:g}" if firing
                            else f"Noise floor {latest:g} dBm", 3, "loud_sound")
