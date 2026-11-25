"""Active polling of watched nodes through the companion radio.

Per node: log in (admin password if known, else guest), request status and
telemetry. Adaptive: a due poll is deferred when the node was heard passively
and a recent poll succeeded; failures back off exponentially; an hourly budget
and a minimum gap between requests cap airtime. Budget and gap apply per
companion radio (each is a separate network/frequency), and different radios
poll in parallel.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict, deque

from . import config, firmware
from .radio import RadioError

log = logging.getLogger(__name__)
RETRY_S = (300, 900)    # first and second retry after a failed poll


class Poller:
    def __init__(self, db, box, radios, monitor):
        self.db, self.box, self.radios, self.monitor = db, box, radios, monitor
        self.sent: dict[str, deque[float]] = defaultdict(deque)
        self.last_request: dict[str, float] = defaultdict(float)
        self.current: dict[str, str] = {}      # radio id -> pubkey being polled
        self.running: set[asyncio.Task] = set()
        self._kick = asyncio.Event()

    def kick(self) -> None:
        self._kick.set()

    def budget_left(self, settings, rid: str) -> int:
        sent = self.sent[rid]
        cutoff = time.time() - 3600
        while sent and sent[0] < cutoff:
            sent.popleft()
        return settings["budget_per_hour"] - len(sent)

    def budgets(self, settings) -> dict[str, int]:
        return {r.id: self.budget_left(settings, r.id) for r in self.radios}

    def _spend(self, rid: str) -> None:
        self.sent[rid].append(time.time())
        self.last_request[rid] = time.time()

    def choose(self, node):
        return self.radios.choose(node["pubkey"], node["radio_id"], self.monitor, self.db)

    async def run(self) -> None:
        try:
            await self._loop()
        finally:
            for task in list(self.running):
                task.cancel()

    async def _loop(self) -> None:
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
        settings = config.get(self.db, "polling")
        now = time.time()
        claimed: set[str] = set()   # one new poll per radio per tick keeps requests spaced
        for node in self.due_nodes(now):
            interval = node["poll_interval_min"] * 60
            live = self.monitor.live.get(node["pubkey"])
            heard = live.last_heard if live and live.last_heard_via != "poll" else None
            if (heard and now - heard < interval / 2 and node["last_poll_ok"]
                    and now - node["last_poll_ok"] < 2 * interval):
                self._schedule(node["pubkey"], now + interval / 2)
                continue
            try:
                radio = self.choose(node)
            except RadioError:
                continue
            rid = radio.id
            if (rid in claimed or radio.state != "connected" or radio.lock.locked() or rid in self.current
                    or self.budget_left(settings, rid) <= 0 or now - self.last_request[rid] < settings["min_gap_s"]):
                continue
            claimed.add(rid)
            self.current[rid] = node["pubkey"]   # reserve before the task starts
            task = asyncio.create_task(self.poll(node, settings, radio), name=f"poll-{node['pubkey'][:8]}")
            self.running.add(task)
            task.add_done_callback(self.running.discard)

    def _schedule(self, pubkey: str, at: float) -> None:
        self.db.x("INSERT INTO node_state(pubkey,next_poll_at) VALUES(?,?)"
                  " ON CONFLICT(pubkey) DO UPDATE SET next_poll_at=excluded.next_poll_at", (pubkey, at))

    def credentials(self, node) -> tuple[str, str]:
        admin = self.box.open(node["admin_pw"])
        if admin:
            return "admin", admin
        return "guest", self.box.open(node["guest_pw"]) or ""

    async def ensure_login(self, node, radio, contact, settings, force=False) -> str:
        """Log in unless this companion holds a recent session with the same role."""
        role, password = self.credentials(node)
        fresh = (node["last_login_at"] and time.time() - node["last_login_at"] < settings["login_max_age_min"] * 60
                 and node["login_role"] == role and node["login_radio"] == radio.id)
        if fresh and not force:
            return role
        self._spend(radio.id)
        result = await radio.login(contact, password, settings["request_timeout_s"])
        role = "admin" if result.get("is_admin") else "guest"
        self.db.x("UPDATE node_state SET last_login_at=?, login_role=?, login_radio=? WHERE pubkey=?",
                  (time.time(), role, radio.id, node["pubkey"]))
        return role

    def node_row(self, key: str):
        self.db.x("INSERT INTO node_state(pubkey) VALUES(?) ON CONFLICT DO NOTHING", (key,))
        return self.db.one(
            "SELECT w.*, s.last_login_at, s.login_role, s.login_radio, s.poll_fails FROM watched w"
            " LEFT JOIN node_state s USING(pubkey) WHERE pubkey=?", (key,))

    async def poll(self, node, settings=None, radio=None, inventory: bool | None = None) -> dict:
        """Poll one node now. Returns a summary; records results and schedule.

        With the admin password, the daily inventory (firmware + settings) rides along when due
        (inventory=None), always (True) or never (False)."""
        settings = settings or config.get(self.db, "polling")
        key = node["pubkey"]
        node = self.node_row(key)
        result: dict = {"ok": False}
        rid = radio.id if radio else None
        try:
            radio = radio or self.choose(node)
            rid = radio.id
            self.current[rid] = key
            async with radio.lock:
                contact = await radio.contact(key, self.monitor.directory.get(key))
                role = await self.ensure_login(node, radio, contact, settings)
                self._spend(rid)
                status = await radio.status(contact, settings["request_timeout_s"])
                if status is None:
                    # Session may have expired on the node: log in again once.
                    role = await self.ensure_login(node, radio, contact, settings, force=True)
                    self._spend(rid)
                    status = await radio.status(contact, settings["request_timeout_s"])
                if status is None:
                    raise RadioError("no status response")
                self._spend(rid)
                lpp = await radio.telemetry(contact, settings["request_timeout_s"])
                self._store(key, status, lpp)
                result = {"ok": True, "status": status, "telemetry": lpp}
                if role == "admin" and self._inventory_due(node, settings, rid, inventory):
                    result["inventory"] = await self._inventory(key, radio, contact, settings)
        except RadioError as exc:
            result = {"ok": False, "error": str(exc)}
        finally:
            if rid and self.current.get(rid) == key:
                del self.current[rid]
        result["radio"] = rid
        self._record_outcome(node, result)
        return result

    def _inventory_due(self, node, settings, rid: str, wanted: bool | None) -> bool:
        if wanted is not None:
            return wanted
        state = self.db.one("SELECT config_at FROM node_state WHERE pubkey=?", (node["pubkey"],))
        fresh = state and state["config_at"] and time.time() - state["config_at"] < firmware.INVENTORY_EVERY_S
        # Keep room in the hourly budget for regular polls of other nodes.
        need = len(firmware.inventory_commands(None)) + 4
        return not fresh and self.budget_left(settings, rid) >= need

    async def _inventory(self, key: str, radio, contact, settings) -> dict:
        """Firmware version and settings via CLI `ver` / `get ...` (caller holds the radio lock)."""
        seen = self.monitor.directory.get(key)
        values: dict[str, str] = {}
        timeouts = 0
        for command in firmware.inventory_commands(seen.node_type if seen else None):
            self._spend(radio.id)
            try:
                reply = await radio.cli(contact, command, settings["request_timeout_s"])
            except RadioError:
                timeouts += 1
                if timeouts >= 2:       # node or path went away; try again next time
                    break
                continue
            value = firmware.clean_reply(reply)
            if value is not None:
                values["ver" if command == "ver" else command[4:]] = value
        if values:
            ver = values.pop("ver", None)
            old = self.db.one("SELECT config FROM node_state WHERE pubkey=?", (key,))
            merged = {**(json.loads(old["config"]) if old and old["config"] else {}), **values}
            self.db.x("UPDATE node_state SET config=?, config_at=?, firmware=COALESCE(?, firmware) WHERE pubkey=?",
                      (json.dumps(merged), time.time(), ver, key))
            values["ver"] = ver
        return values

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
                      " last_error=NULL, poll_radio=?, fail_radio=NULL WHERE pubkey=?",
                      (now, now, now + interval, result.get("radio"), node["pubkey"]))
        else:
            fails = (node["poll_fails"] or 0) + 1
            if not node["radio_id"] and fails < len(self.radios.connected()):
                # Automatic: try the next companion soon before backing off.
                delay = settings["min_gap_s"]
            elif fails <= len(RETRY_S):
                # Single lost replies are common on the mesh: retry soon, then back off.
                delay = min(RETRY_S[fails - 1], interval)
            else:
                delay = min(interval * 2 ** (fails - len(RETRY_S) - 1), settings["max_backoff_min"] * 60)
            self.db.x("UPDATE node_state SET last_poll_at=?, poll_fails=?, next_poll_at=?, last_error=?,"
                      " fail_radio=? WHERE pubkey=?",
                      (now, fails, now + delay, result["error"], result.get("radio"), node["pubkey"]))
            log.info("poll %s via %s failed: %s", node["pubkey"][:8], result.get("radio"), result["error"])
