"""Active polling of watched nodes through the companion radio.

Per node: log in (admin password if known, else guest), request status and
telemetry. Adaptive: a due poll is deferred when the node was heard passively
and a recent poll succeeded; failures back off exponentially; a global hourly
budget and a minimum gap between requests cap airtime.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque

from . import config
from .radio import RadioError

log = logging.getLogger(__name__)


class Poller:
    def __init__(self, db, box, radio, monitor):
        self.db, self.box, self.radio, self.monitor = db, box, radio, monitor
        self.sent: deque[float] = deque()
        self.last_request = 0.0
        self.current: str | None = None
        self._kick = asyncio.Event()

    def kick(self) -> None:
        self._kick.set()

    def budget_left(self, settings) -> int:
        cutoff = time.time() - 3600
        while self.sent and self.sent[0] < cutoff:
            self.sent.popleft()
        return settings["budget_per_hour"] - len(self.sent)

    def _spend(self) -> None:
        self.sent.append(time.time())
        self.last_request = time.time()

    async def run(self) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:              # noqa: BLE001
                log.exception("poller tick")
            self._kick.clear()
            try:
                await asyncio.wait_for(self._kick.wait(), 5)
            except asyncio.TimeoutError:
                pass

    def due_nodes(self, now: float):
        return self.db.q(
            "SELECT w.*, s.next_poll_at, s.last_poll_ok, s.last_login_at, s.poll_fails, s.login_role"
            " FROM watched w LEFT JOIN node_state s USING(pubkey)"
            " WHERE w.poll_enabled=1 AND (s.next_poll_at IS NULL OR s.next_poll_at<=?)"
            " ORDER BY COALESCE(s.next_poll_at,0)", (now,))

    async def tick(self) -> None:
        if self.radio.state != "connected":
            return
        settings = config.get(self.db, "polling")
        now = time.time()
        for node in self.due_nodes(now):
            interval = node["poll_interval_min"] * 60
            live = self.monitor.live.get(node["pubkey"])
            heard = live.last_heard if live and live.last_heard_via != "poll" else None
            if (heard and now - heard < interval / 2 and node["last_poll_ok"]
                    and now - node["last_poll_ok"] < 2 * interval):
                self._schedule(node["pubkey"], now + interval / 2)
                continue
            if self.budget_left(settings) <= 0 or now - self.last_request < settings["min_gap_s"]:
                return
            await self.poll(node, settings)
            return  # one node per tick keeps requests spaced

    def _schedule(self, pubkey: str, at: float) -> None:
        self.db.x("INSERT INTO node_state(pubkey,next_poll_at) VALUES(?,?)"
                  " ON CONFLICT(pubkey) DO UPDATE SET next_poll_at=excluded.next_poll_at", (pubkey, at))

    def credentials(self, node) -> tuple[str, str]:
        admin = self.box.open(node["admin_pw"])
        if admin:
            return "admin", admin
        return "guest", self.box.open(node["guest_pw"]) or ""

    async def ensure_login(self, node, contact, settings, force=False) -> str:
        role, password = self.credentials(node)
        fresh = (node["last_login_at"] and time.time() - node["last_login_at"] < settings["login_max_age_min"] * 60
                 and node["login_role"] == role)
        if fresh and not force:
            return role
        self._spend()
        result = await self.radio.login(contact, password, settings["request_timeout_s"])
        role = "admin" if result.get("is_admin") else "guest"
        self.db.x("UPDATE node_state SET last_login_at=?, login_role=? WHERE pubkey=?",
                  (time.time(), role, node["pubkey"]))
        return role

    async def poll(self, node, settings=None) -> dict:
        """Poll one node now. Returns a summary; records results and schedule."""
        settings = settings or config.get(self.db, "polling")
        key, now = node["pubkey"], time.time()
        self.db.x("INSERT INTO node_state(pubkey) VALUES(?) ON CONFLICT DO NOTHING", (key,))
        node = self.db.one(
            "SELECT w.*, s.last_login_at, s.login_role, s.poll_fails FROM watched w"
            " LEFT JOIN node_state s USING(pubkey) WHERE pubkey=?", (key,))
        self.current = key
        result: dict = {"ok": False}
        try:
            async with self.radio.lock:
                contact = await self.radio.contact(key, self.monitor.directory.get(key))
                await self.ensure_login(node, contact, settings)
                self._spend()
                status = await self.radio.status(contact, settings["request_timeout_s"])
                if status is None:
                    # Session may have expired on the node: log in again once.
                    await self.ensure_login(node, contact, settings, force=True)
                    self._spend()
                    status = await self.radio.status(contact, settings["request_timeout_s"])
                if status is None:
                    raise RadioError("no status response")
                self._spend()
                lpp = await self.radio.telemetry(contact, settings["request_timeout_s"])
            self._store(key, status, lpp)
            result = {"ok": True, "status": status, "telemetry": lpp}
        except RadioError as exc:
            result = {"ok": False, "error": str(exc)}
        finally:
            self.current = None
        self._record_outcome(node, result)
        return result

    def _store(self, key: str, status: dict, lpp) -> None:
        now = time.time()
        clean = {k: v for k, v in status.items() if isinstance(v, (int, float, str))}
        self.db.x("INSERT INTO status_samples(pubkey,ts,bat,noise_floor,last_rssi,last_snr,uptime,airtime,"
                  "nb_sent,nb_recv,tx_queue_len,raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                  (key, now, status.get("bat"), status.get("noise_floor"), status.get("last_rssi"),
                   status.get("last_snr"), status.get("uptime"), status.get("airtime"), status.get("nb_sent"),
                   status.get("nb_recv"), status.get("tx_queue_len"), json.dumps(clean)))
        self.db.x("UPDATE node_state SET status=?, status_at=? WHERE pubkey=?", (json.dumps(clean), now, key))
        if lpp:
            self.db.x("INSERT INTO telemetry_samples(pubkey,ts,lpp) VALUES(?,?,?)", (key, now, json.dumps(lpp)))
            self.db.x("UPDATE node_state SET telemetry=?, telemetry_at=? WHERE pubkey=?",
                      (json.dumps(lpp), now, key))
        self.monitor.heard_by_poll(key, now)

    def _record_outcome(self, node, result) -> None:
        now = time.time()
        interval = node["poll_interval_min"] * 60
        settings = config.get(self.db, "polling")
        if result["ok"]:
            self.db.x("UPDATE node_state SET last_poll_at=?, last_poll_ok=?, poll_fails=0, next_poll_at=?,"
                      " last_error=NULL WHERE pubkey=?", (now, now, now + interval, node["pubkey"]))
        else:
            fails = (node["poll_fails"] or 0) + 1
            delay = min(interval * 2 ** (fails - 1), settings["max_backoff_min"] * 60)
            self.db.x("UPDATE node_state SET last_poll_at=?, poll_fails=?, next_poll_at=?, last_error=?"
                      " WHERE pubkey=?", (now, fails, now + delay, result["error"], node["pubkey"]))
            log.info("poll %s failed: %s", node["pubkey"][:8], result["error"])
