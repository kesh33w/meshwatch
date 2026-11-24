"""Minimal MeshCore wire-format decoding: header, path hops and adverts.

Only what monitoring needs. Reference: MeshCore docs/packet_format.md and
docs/payloads.md.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROUTE_TRANSPORT_FLOOD, ROUTE_FLOOD, ROUTE_DIRECT, ROUTE_TRANSPORT_DIRECT = 0, 1, 2, 3
PAYLOAD_ADVERT = 4
PAYLOAD_TRACE = 9
NODE_TYPES = {1: "chat", 2: "repeater", 3: "room", 4: "sensor"}


class PacketError(ValueError):
    pass


@dataclass
class Advert:
    pubkey: str          # 64 hex, lowercase
    timestamp: int
    node_type: str
    name: str | None
    lat: float | None
    lon: float | None
    verified: bool


@dataclass
class Packet:
    route: int
    payload_type: int
    hash_size: int                      # bytes per path hop (1-3)
    hops: list[str] = field(default_factory=list)   # lowercase hex per hop
    payload: bytes = b""
    hash: str = ""                      # content hash (same packet across observers)
    advert: Advert | None = None

    @property
    def is_flood(self) -> bool:
        return self.route in (ROUTE_FLOOD, ROUTE_TRANSPORT_FLOOD)


def decode(raw: bytes | str) -> Packet:
    data = bytes.fromhex(raw) if isinstance(raw, str) else bytes(raw)
    if len(data) < 2:
        raise PacketError("too short")
    header = data[0]
    route, payload_type = header & 3, (header >> 2) & 15
    offset = 5 if route in (ROUTE_TRANSPORT_FLOOD, ROUTE_TRANSPORT_DIRECT) else 1
    if len(data) <= offset:
        raise PacketError("truncated")
    path_byte = data[offset]
    size, count = (path_byte >> 6) + 1, path_byte & 63
    if size > 3:
        raise PacketError("reserved path hash size")
    start = offset + 1
    end = start + size * count
    if end > len(data):
        raise PacketError("truncated path")
    payload = data[end:]
    pkt = Packet(route=route, payload_type=payload_type, hash_size=size, payload=payload,
                 hash=hashlib.sha256(bytes([payload_type]) + payload).hexdigest()[:16])
    if payload_type != PAYLOAD_TRACE:  # TRACE paths hold SNR bytes, not hops
        pkt.hops = [data[i:i + size].hex() for i in range(start, end, size)]
    if payload_type == PAYLOAD_ADVERT:
        pkt.advert = decode_advert(payload)
    return pkt


def decode_advert(payload: bytes) -> Advert:
    if len(payload) < 101:
        raise PacketError("advert too short")
    pubkey, ts, sig, app = payload[:32], payload[32:36], payload[36:100], payload[100:]
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(sig, pubkey + ts + app)
        verified = True
    except (InvalidSignature, ValueError):
        verified = False
    flags = app[0] if app else 0
    pos, lat, lon, name = 1, None, None, None
    if flags & 0x10 and len(app) >= pos + 8:
        la, lo = struct.unpack_from("<ii", app, pos)
        lat, lon, pos = la / 1e6, lo / 1e6, pos + 8
    if flags & 0x20:
        pos += 2
    if flags & 0x40:
        pos += 2
    if flags & 0x80 and len(app) > pos:
        name = app[pos:].split(b"\0", 1)[0].decode("utf-8", "replace").strip() or None
    return Advert(pubkey=pubkey.hex(), timestamp=struct.unpack("<I", ts)[0],
                  node_type=NODE_TYPES.get(flags & 0x0F, "unknown"), name=name,
                  lat=lat, lon=lon, verified=verified)
