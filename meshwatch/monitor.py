"""Passive monitoring: turns observed packets into per-node evidence.

Evidence for a watched node:
  * advert  - a signature-valid advert carrying its public key. Zero-hop
              adverts give the observer's SNR/RSSI of the node itself.
  * relay   - the node's hash is the last hop of a flood packet, so the
              observer heard the node transmit (SNR/RSSI are the node's).
              Earlier hops only prove the node is alive. Hop hashes are short
              (1-3 bytes), so relay evidence is used only when no other known
              repeater/room server shares the prefix.

State is kept in memory and flushed to SQLite periodically.
"""
from __future__ import annotations

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from . import packets

log = logging.getLogger(__name__)

BUCKET_S = 300
RELAYING_TYPES = {"repeater", "room"}
DIRECTORY_MAX_AGE_S = 14 * 86400


@dataclass
class SeenNode:
    pubkey: str
    name: str | None
    node_type: str
    lat: float | None
    lon: float | None
    advert_ts: int
    last_seen: float
    dirty: bool = True


@dataclass
class Bucket:
    pubkey: str
    start: float
    kind: str
    observer: str
    region: str | None
    direct: bool
    n: int = 0
    snr_sum: float = 0.0
    snr_n: int = 0
    rssi_sum: float = 0.0
    rssi_n: int = 0
    hops: int | None = None
    path: str | None = None


@dataclass
class Live:
    """In-memory node state mirrored to node_state."""
    last_heard: float | None = None
    last_heard_via: str | None = None
    last_advert: float | None = None
    dirty: bool = False


class Monitor:
    def __init__(self, db):
        self.db = db
        self.directory: dict[str, SeenNode] = {}
        self.watched: set[str] = set()
        self.live: dict[str, Live] = {}
        self.buckets: dict[tuple, Bucket] = {}
        self._dedupe: OrderedDict[tuple, float] = OrderedDict()
        self.stats = {"packets": 0, "decode_errors": 0, "duplicates": 0, "adverts": 0,
                      "bad_signatures": 0, "evidence": 0, "ambiguous_hops": 0}
        self._load()

    # setup ------------------------------------------------------------------
    def _load(self) -> None:
        cutoff = time.time() - DIRECTORY_MAX_AGE_S
        for r in self.db.q("SELECT * FROM seen_nodes WHERE last_seen > ?", (cutoff,)):
            self.directory[r["pubkey"]] = SeenNode(r["pubkey"], r["name"], r["node_type"], r["lat"],
                                                   r["lon"], r["advert_ts"], r["last_seen"], dirty=False)
        self.reload_watched()

    def reload_watched(self) -> None:
        self.watched = {r["pubkey"] for r in self.db.q("SELECT pubkey FROM watched")}
        for key in self.watched:
            if key not in self.live:
                row = self.db.one("SELECT last_heard,last_heard_via,last_advert FROM node_state WHERE pubkey=?", (key,))
                self.live[key] = Live(*(tuple(row) if row else (None, None, None)))
        for key in list(self.live):
            if key not in self.watched:
                del self.live[key]

    # ingest -----------------------------------------------------------------
    def ingest(self, raw: str | bytes, observer: str, region: str | None = None,
               snr: float | None = None, rssi: float | None = None, ts: float | None = None) -> None:
        self.stats["packets"] += 1
        now = time.time()
        ts = min(ts or now, now)
        try:
            pkt = packets.decode(raw)
        except (packets.PacketError, ValueError):
            self.stats["decode_errors"] += 1
            return
        key = (pkt.hash, observer)
        if key in self._dedupe:
            self.stats["duplicates"] += 1
            return
        self._dedupe[key] = now
        if len(self._dedupe) > 50_000:
            self._dedupe.popitem(last=False)

        if pkt.advert:
            self._advert(pkt, observer, region, snr, rssi, ts)
        if pkt.is_flood and pkt.hops:
            self._relays(pkt, observer, region, snr, rssi, ts)

    def _advert(self, pkt, observer, region, snr, rssi, ts) -> None:
        adv = pkt.advert
        self.stats["adverts"] += 1
        if not adv.verified:
            self.stats["bad_signatures"] += 1
            return
        seen = self.directory.get(adv.pubkey)
        if seen is None or adv.timestamp >= seen.advert_ts:
            self.directory[adv.pubkey] = SeenNode(adv.pubkey, adv.name, adv.node_type, adv.lat, adv.lon,
                                                  adv.timestamp, ts)
        else:
            seen.last_seen, seen.dirty = max(seen.last_seen, ts), True
        if adv.pubkey in self.watched:
            live = self.live[adv.pubkey]
            live.last_advert = max(live.last_advert or 0, ts)
            self._heard(adv.pubkey, ts, "advert")
            self._record(adv.pubkey, ts, "advert", observer, region, snr, rssi,
                         direct=not pkt.hops, hops=len(pkt.hops), path=",".join(pkt.hops))

    def _relays(self, pkt, observer, region, snr, rssi, ts) -> None:
        if not self.watched:
            return
        last = len(pkt.hops) - 1
        for i, prefix in enumerate(pkt.hops):
            node = self.resolve_prefix(prefix)
            if node is None or node not in self.watched:
                continue
            self._heard(node, ts, "relay")
            if i == last:
                self._record(node, ts, "relay", observer, region, snr, rssi, direct=True,
                             hops=len(pkt.hops), path=",".join(pkt.hops))

    def resolve_prefix(self, prefix: str) -> str | None:
        """Unique watched relaying node for a hop prefix, else None."""
        candidates = [k for k in self.watched if k.startswith(prefix)]
        if len(candidates) != 1:
            return None
        node = candidates[0]
        cutoff = time.time() - DIRECTORY_MAX_AGE_S
        for other in self.directory.values():
            if (other.pubkey != node and other.pubkey.startswith(prefix)
                    and other.node_type in RELAYING_TYPES and other.last_seen > cutoff):
                self.stats["ambiguous_hops"] += 1
                return None
        seen = self.directory.get(node)
        if seen and seen.node_type not in RELAYING_TYPES:
            return None
        return node

    def _heard(self, pubkey: str, ts: float, via: str) -> None:
        live = self.live[pubkey]
        if live.last_heard is None or ts >= live.last_heard:
            live.last_heard, live.last_heard_via, live.dirty = ts, via, True
        self.stats["evidence"] += 1

    def heard_by_poll(self, pubkey: str, ts: float) -> None:
        if pubkey in self.live:
            self._heard(pubkey, ts, "poll")

    def _record(self, pubkey, ts, kind, observer, region, snr, rssi, direct, hops, path) -> None:
        start = ts - ts % BUCKET_S
        key = (pubkey, start, kind, observer, direct)
        b = self.buckets.get(key)
        if b is None:
            b = self.buckets[key] = Bucket(pubkey, start, kind, observer, region, direct)
        b.n += 1
        if isinstance(snr, (int, float)):
            b.snr_sum, b.snr_n = b.snr_sum + snr, b.snr_n + 1
        if isinstance(rssi, (int, float)):
            b.rssi_sum, b.rssi_n = b.rssi_sum + rssi, b.rssi_n + 1
        b.hops, b.path = hops, path

    # persistence ------------------------------------------------------------
    def flush(self, force: bool = False) -> None:
        now = time.time()
        done = [k for k, b in self.buckets.items() if force or b.start + BUCKET_S <= now]
        rows = []
        for k in done:
            b = self.buckets.pop(k)
            rows.append((b.pubkey, b.start, b.kind, b.observer, b.region,
                         b.snr_sum / b.snr_n if b.snr_n else None,
                         b.rssi_sum / b.rssi_n if b.rssi_n else None,
                         b.n, int(b.direct), b.hops, b.path))
        if rows:
            self.db.many("INSERT INTO observations(pubkey,ts,kind,observer,region,snr,rssi,n,direct,hops,path)"
                         " VALUES(?,?,?,?,?,?,?,?,?,?,?)", rows)
        states = [(k, l.last_heard, l.last_heard_via, l.last_advert)
                  for k, l in self.live.items() if l.dirty]
        if states:
            self.db.many("INSERT INTO node_state(pubkey,last_heard,last_heard_via,last_advert) VALUES(?,?,?,?)"
                         " ON CONFLICT(pubkey) DO UPDATE SET last_heard=excluded.last_heard,"
                         " last_heard_via=excluded.last_heard_via, last_advert=excluded.last_advert", states)
            for l in self.live.values():
                l.dirty = False
        seen = [s for s in self.directory.values() if s.dirty]
        if seen:
            self.db.many("INSERT INTO seen_nodes(pubkey,name,node_type,lat,lon,advert_ts,last_seen)"
                         " VALUES(?,?,?,?,?,?,?) ON CONFLICT(pubkey) DO UPDATE SET name=excluded.name,"
                         " node_type=excluded.node_type, lat=excluded.lat, lon=excluded.lon,"
                         " advert_ts=excluded.advert_ts, last_seen=excluded.last_seen",
                         [(s.pubkey, s.name, s.node_type, s.lat, s.lon, s.advert_ts, s.last_seen) for s in seen])
            for s in seen:
                s.dirty = False

    def search(self, text: str, limit: int = 30) -> list[SeenNode]:
        text = text.strip().lower()
        nodes = sorted(self.directory.values(), key=lambda s: -s.last_seen)
        if text:
            nodes = [s for s in nodes if s.pubkey.startswith(text) or (s.name and text in s.name.lower())]
        return nodes[:limit]
