"""Alert rules and ntfy delivery.

Rules per watched node: silent, battery, signal (SNR drop vs baseline,
fewer observers hearing it, noise floor rise). Each rule fires once and
notifies again when it resolves. A system rule warns when no data source has
delivered anything for 15 minutes (silent alerts are paused meanwhile).
"""
from __future__ import annotations

import json
import logging
import statistics
import time

import httpx

from . import config

log = logging.getLogger(__name__)
NOISE_RISE_DB = 10
SYSTEM = ""   # pubkey used for system alerts


class Notifier:
    def __init__(self, db, box, origin: str):
        self.db, self.box, self.origin = db, box, origin

    async def send(self, title: str, message: str, priority: int = 3, tags: str = "", path: str = "/") -> str | None:
        cfg = config.get(self.db, "ntfy")
        if not cfg.get("enabled") or not cfg.get("topic"):
            return "ntfy not configured"
        headers = {"Title": title.encode("utf-8").decode("latin-1", "replace"), "Priority": str(priority),
                   "Click": self.origin + path}
        if tags:
            headers["Tags"] = tags
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
    def __init__(self, db, monitor, notifier, health):
        self.db, self.monitor, self.notifier = db, monitor, notifier
        self.health = health            # callable -> last time any data arrived
        self._signal_checked = 0.0

    def open_alert(self, pubkey: str, rule: str):
        return self.db.one("SELECT * FROM alerts WHERE pubkey=? AND rule=? AND resolved IS NULL", (pubkey, rule))

    async def _set(self, pubkey: str, rule: str, firing: bool, message: str, priority=4, tags="warning") -> None:
        current = self.open_alert(pubkey, rule)
        label = node_label(self.db, self.monitor, pubkey) if pubkey else "meshwatch"
        path = f"/nodes/{pubkey}" if pubkey else "/"
        if firing and not current:
            self.db.x("INSERT INTO alerts(pubkey,rule,started,message) VALUES(?,?,?,?)",
                      (pubkey, rule, time.time(), message))
            err = await self.notifier.send(f"{label}: {message}", message, priority, tags, path)
            if err:
                log.warning("notify: %s", err)
        elif not firing and current:
            self.db.x("UPDATE alerts SET resolved=? WHERE id=?", (time.time(), current["id"]))
            err = await self.notifier.send(f"{label}: OK", f"Resolved: {current['message']}. {message}",
                                           3, "white_check_mark", path)
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
        for node in self.db.q("SELECT w.*, s.status, s.status_at FROM watched w LEFT JOIN node_state s USING(pubkey)"
                              " WHERE w.alerts_enabled=1"):
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
        live = self.monitor.live.get(node["pubkey"])
        since = (live.last_heard if live and live.last_heard else None) or node["added_at"]
        limit = self.silent_threshold_min(node, cfg) * 60
        silent = now - since > limit
        msg = (f"Not heard for {fmt_age(now - since)}" if silent
               else f"Heard again ({live.last_heard_via if live else ''})")
        await self._set(node["pubkey"], "silent", silent, msg, 4, "warning")

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
