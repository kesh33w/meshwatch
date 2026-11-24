from meshwatch import packets
from helpers import advert_packet, frame, keypair


def test_advert_decodes_and_verifies():
    priv, pub = keypair(None)
    pkt = packets.decode(advert_packet(priv, name="Hill", hops=["aa", "bb"]))
    assert pkt.advert.pubkey == pub
    assert pkt.advert.verified
    assert pkt.advert.name == "Hill"
    assert pkt.advert.node_type == "repeater"
    assert abs(pkt.advert.lat - 38.5) < 1e-6 and abs(pkt.advert.lon + 121.4) < 1e-6
    assert pkt.hops == ["aa", "bb"] and pkt.is_flood


def test_tampered_advert_fails_signature():
    priv, _ = keypair(None)
    assert not packets.decode(advert_packet(priv, tamper=True)).advert.verified


def test_multibyte_hops_and_transport_codes():
    pkt = packets.decode(frame(5, b"\x01\x02\x03", hops=["a1b2", "c3d4"], route=0, hash_size=2))
    assert pkt.hops == ["a1b2", "c3d4"] and pkt.is_flood and pkt.payload == b"\x01\x02\x03"


def test_same_payload_same_hash_regardless_of_path():
    a = packets.decode(frame(5, b"hello", hops=["aa"]))
    b = packets.decode(frame(5, b"hello", hops=["aa", "bb"]))
    assert a.hash == b.hash


def test_truncated():
    import pytest
    with pytest.raises(packets.PacketError):
        packets.decode("05")
