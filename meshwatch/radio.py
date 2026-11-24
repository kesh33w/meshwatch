"""Companion radio connection (TCP or USB serial) used for polling and remote admin.

All mesh operations go through one lock: a companion handles one remote
request at a time and serializing keeps airtime predictable.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import time

from meshcore import EventType, MeshCore

log = logging.getLogger(__name__)

TYPE_CODES = {"chat": 1, "repeater": 2, "room": 3, "sensor": 4}


class RadioError(RuntimeError):
    pass


class Radio:
    def __init__(self, on_rx=None):
        self.config: dict = {"kind": "none"}
        self.mc: MeshCore | None = None
        self.lock = asyncio.Lock()
        self.on_rx = on_rx                 # callback(raw_hex, snr, rssi)
        self.state = "disabled"
        self.error: str | None = None
        self.self_info: dict = {}
        self.connected_at: float | None = None
        self._task: asyncio.Task | None = None
        self._wake = asyncio.Event()

    # lifecycle --------------------------------------------------------------
    def configure(self, config: dict) -> None:
        self.config = dict(config)
        self._wake.set()

    def start(self) -> None:
        self._task = asyncio.create_task(self._supervise(), name="radio")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        await self._close()

    async def _close(self) -> None:
        mc, self.mc = self.mc, None
        if mc:
            with contextlib.suppress(Exception):
                await mc.disconnect()

    async def _supervise(self) -> None:
        delay = 5
        while True:
            cfg = self.config
            self._wake.clear()
            if cfg.get("kind") not in ("tcp", "serial"):
                self.state, self.error = "disabled", None
                await self._wake.wait()
                continue
            self.state = "connecting"
            try:
                if cfg["kind"] == "tcp":
                    mc = await MeshCore.create_tcp(cfg["host"], int(cfg["port"]), only_error=True)
                else:
                    mc = await MeshCore.create_serial(cfg["serial_port"], int(cfg.get("baud") or 115200),
                                                      only_error=True)
                if mc is None:
                    raise RadioError("no response from companion")
                self.mc = mc
                self.self_info = dict(mc.self_info or {})
                lost = asyncio.Event()
                mc.subscribe(EventType.DISCONNECTED, lambda e: lost.set())
                mc.subscribe(EventType.RX_LOG_DATA, self._rx)
                await mc.ensure_contacts()
                await mc.start_auto_message_fetching()
                self.state, self.error, self.connected_at, delay = "connected", None, time.time(), 5
                log.info("companion connected: %s", self.self_info.get("name"))
                wake = asyncio.create_task(self._wake.wait())
                gone = asyncio.create_task(lost.wait())
                await asyncio.wait({wake, gone}, return_when=asyncio.FIRST_COMPLETED)
                wake.cancel(), gone.cancel()
                if lost.is_set():
                    raise RadioError("companion disconnected")
                await self._close()       # reconfigured
            except asyncio.CancelledError:
                raise
            except Exception as exc:     # noqa: BLE001 - keep retrying on any transport error
                await self._close()
                self.state, self.error = "error", str(exc) or type(exc).__name__
                log.warning("companion: %s (retry in %ss)", self.error, delay)
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._wake.wait(), delay)
                delay = min(delay * 2, 300)

    def _rx(self, event) -> None:
        p = event.payload or {}
        raw = p.get("payload")
        if raw and self.on_rx:
            try:
                self.on_rx(raw, p.get("snr"), p.get("rssi"))
            except Exception:            # noqa: BLE001
                log.exception("rx handler")

    # helpers ----------------------------------------------------------------
    def _need(self) -> MeshCore:
        if not self.mc or self.state != "connected":
            raise RadioError("companion radio not connected")
        return self.mc

    async def contact(self, pubkey: str, seen=None) -> dict:
        """Companion contact for pubkey, added from the advert directory if missing."""
        mc = self._need()
        c = mc.get_contact_by_key_prefix(pubkey)
        if c and c.get("public_key", "").lower() == pubkey:
            return c
        if seen is None:
            raise RadioError("node is not in the companion's contacts and no advert has been seen yet")
        c = {"public_key": pubkey, "type": TYPE_CODES.get(seen.node_type, 2), "flags": 0,
             "out_path_len": -1, "out_path": "", "out_path_hash_mode": 0,
             "adv_name": (seen.name or pubkey[:8])[:31], "last_advert": int(seen.advert_ts or 0),
             "adv_lat": seen.lat or 0.0, "adv_lon": seen.lon or 0.0}
        res = await mc.commands.add_contact(c)
        if res.type == EventType.ERROR:
            raise RadioError(f"could not add contact: {res.payload}")
        await mc.ensure_contacts(follow=True)
        return mc.get_contact_by_key_prefix(pubkey) or c

    async def _wait_any(self, types, prefix: str, timeout: float):
        mc = self._need()
        loop = asyncio.get_running_loop()
        fut = loop.create_future()

        def done(event):
            p = event.payload or {}
            if p.get("pubkey_prefix") and not prefix.startswith(p["pubkey_prefix"]):
                return
            if not fut.done():
                fut.set_result(event)

        subs = [mc.subscribe(t, done) for t in types]
        try:
            return fut, subs
        except BaseException:
            for s in subs:
                s.unsubscribe()
            raise

    async def login(self, contact: dict, password: str, timeout: float) -> dict:
        mc = self._need()
        fut, subs = await self._wait_any((EventType.LOGIN_SUCCESS, EventType.LOGIN_FAILED),
                                         contact["public_key"], timeout)
        try:
            sent = await mc.commands._send_login_raw(contact, password)
            if sent is None or sent.type == EventType.ERROR:
                raise RadioError("companion refused login request")
            wait = max(timeout, sent.payload.get("suggested_timeout", 0) / 800)
            event = await asyncio.wait_for(fut, wait)
        except asyncio.TimeoutError:
            raise RadioError("login timed out") from None
        finally:
            for s in subs:
                s.unsubscribe()
        if event.type == EventType.LOGIN_FAILED:
            raise RadioError("login rejected (wrong password?)")
        return event.payload or {}

    async def status(self, contact: dict, timeout: float) -> dict | None:
        return await self._need().commands.req_status_sync(contact, min_timeout=timeout / 2)

    async def telemetry(self, contact: dict, timeout: float):
        return await self._need().commands.req_telemetry_sync(contact, min_timeout=timeout / 2)

    async def cli(self, contact: dict, command: str, timeout: float) -> str:
        """Send a CLI command and wait for its text reply."""
        mc = self._need()
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        prefix = contact["public_key"]

        def reply(event):
            p = event.payload or {}
            if p.get("txt_type") == 1 and prefix.startswith(p.get("pubkey_prefix", "-")) and not fut.done():
                fut.set_result(p.get("text", ""))

        sub = mc.subscribe(EventType.CONTACT_MSG_RECV, reply)
        try:
            sent = await mc.commands.send_cmd(contact, command)
            if sent is None or sent.type == EventType.ERROR:
                raise RadioError("companion refused the command")
            wait = max(timeout, (sent.payload or {}).get("suggested_timeout", 0) / 800)
            return await asyncio.wait_for(fut, wait)
        except asyncio.TimeoutError:
            raise RadioError("no reply (timed out)") from None
        finally:
            sub.unsubscribe()
