"""MQTT sources in the common MeshCore observer format:
topic meshcore/<IATA>/<observer>/packets, JSON body with "raw" (hex), "SNR",
"RSSI" and an ISO "timestamp"."""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import ssl
import time
from datetime import datetime
from urllib.parse import urlparse

import aiomqtt

log = logging.getLogger(__name__)
DEFAULT_TOPICS = ["meshcore/+/+/packets"]


def _num(value):
    try:
        f = float(value)
        return f if f == f else None
    except (TypeError, ValueError):
        return None


def parse_message(topic: str, body: bytes):
    """-> (raw, observer, region, snr, rssi, ts) or None."""
    try:
        data = json.loads(body)
    except ValueError:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("raw"), str):
        return None
    parts = topic.split("/")
    region = parts[1] if len(parts) > 3 else None
    observer = parts[2] if len(parts) > 3 else str(data.get("origin_id") or data.get("origin") or "mqtt")
    ts = None
    stamp = data.get("timestamp")
    if isinstance(stamp, str):
        with contextlib.suppress(ValueError):
            dt = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if dt.tzinfo is not None:   # zoneless stamps are unreliable: use receipt time
                ts = dt.timestamp()
    if ts is not None and abs(ts - time.time()) > 600:
        ts = None
    return (data["raw"], observer.split("@")[0][:64], region,
            _num(data.get("SNR", data.get("snr"))), _num(data.get("RSSI", data.get("rssi"))), ts)


class Source:
    def __init__(self, cfg: dict, password: str | None, monitor):
        self.cfg, self.password, self.monitor = cfg, password, monitor
        self.state, self.error, self.messages, self.last_message = "starting", None, 0, None
        self.task: asyncio.Task | None = None

    def start(self) -> None:
        self.task = asyncio.create_task(self.run(), name=f"mqtt:{self.cfg.get('name')}")

    async def stop(self) -> None:
        if self.task:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.task

    def client(self) -> aiomqtt.Client:
        url = urlparse(self.cfg["url"])
        scheme = url.scheme.lower()
        if scheme not in ("mqtt", "mqtts", "ws", "wss"):
            raise ValueError("URL must start with mqtt://, mqtts://, ws:// or wss://")
        tls = scheme in ("mqtts", "wss")
        port = url.port or {"mqtt": 1883, "mqtts": 8883, "ws": 80, "wss": 443}[scheme]
        kwargs = dict(hostname=url.hostname, port=port, username=self.cfg.get("username") or None,
                      password=self.password or None, keepalive=60,
                      identifier=f"meshwatch-{int(time.time())}")
        if scheme in ("ws", "wss"):
            kwargs.update(transport="websockets", websocket_path=url.path or "/mqtt")
        if tls:
            kwargs["tls_context"] = ssl.create_default_context()
        return aiomqtt.Client(**kwargs)

    async def run(self) -> None:
        delay = 5
        while True:
            try:
                self.state = "connecting"
                async with self.client() as client:
                    for topic in self.cfg.get("topics") or DEFAULT_TOPICS:
                        await client.subscribe(topic, qos=0)
                    self.state, self.error, delay = "connected", None, 5
                    async for message in client.messages:
                        parsed = parse_message(str(message.topic), message.payload)
                        if parsed:
                            self.messages += 1
                            self.last_message = time.time()
                            raw, observer, region, snr, rssi, ts = parsed
                            self.monitor.ingest(raw, observer, region, snr, rssi, ts)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                self.state, self.error = "error", str(exc) or type(exc).__name__
                log.warning("mqtt %s: %s (retry in %ss)", self.cfg.get("name"), self.error, delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 300)


class Sources:
    def __init__(self, monitor, box):
        self.monitor, self.box = monitor, box
        self.sources: dict[str, Source] = {}

    async def apply(self, configs: list[dict]) -> None:
        for s in list(self.sources.values()):
            await s.stop()
        self.sources = {}
        for cfg in configs:
            if cfg.get("enabled", True) and cfg.get("url"):
                s = Source(cfg, self.box.open(cfg.get("password_enc")), self.monitor)
                s.start()
                self.sources[cfg["id"]] = s

    async def stop(self) -> None:
        await self.apply([])
