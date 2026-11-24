import struct
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def keypair(seed: int = 0):
    """Deterministic-ish key; returns (private, pubkey_hex)."""
    while True:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if seed is None or pub[0] == seed:
            return priv, pub.hex()


def advert_packet(priv, node_type=2, name="Test RPT", lat=38.5, lon=-121.4, hops=(), route=1, ts=None,
                  tamper=False, hash_size=1):
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ts = struct.pack("<I", int(ts or time.time()))
    flags = node_type | 0x80 | (0x10 if lat is not None else 0)
    app = bytes([flags])
    if lat is not None:
        app += struct.pack("<ii", int(lat * 1e6), int(lon * 1e6))
    app += name.encode()
    sig = priv.sign(pub + ts + app)
    if tamper:
        app = app[:-1] + b"X"
    payload = pub + ts + sig + app
    return frame(4, payload, hops, route, hash_size)


def frame(payload_type, payload, hops=(), route=1, hash_size=1):
    header = bytes([(payload_type << 2) | route])
    transport = b"\0\0\0\0" if route in (0, 3) else b""
    path = b"".join(bytes.fromhex(h) for h in hops)
    path_byte = ((hash_size - 1) << 6) | len(hops)
    return (header + transport + bytes([path_byte]) + path + payload).hex()
