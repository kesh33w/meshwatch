import time

import pytest

from meshwatch.db import DB
from meshwatch.monitor import Monitor
from helpers import advert_packet, frame, keypair


@pytest.fixture
def mon(tmp_path):
    db = DB(tmp_path / "t.db")
    return Monitor(db)


def watch(mon, pub):
    mon.db.x("INSERT INTO watched(pubkey,added_at) VALUES(?,?)", (pub, time.time()))
    mon.reload_watched()


def test_zero_hop_advert_records_direct_signal(mon):
    priv, pub = keypair(None)
    watch(mon, pub)
    mon.ingest(advert_packet(priv), "obs1", "SMF", -3.5, -101)
    mon.ingest(advert_packet(priv), "obs1", "SMF", -3.5, -101)   # duplicate from 2nd source
    mon.flush(force=True)
    rows = mon.db.q("SELECT * FROM observations")
    assert len(rows) == 1 and rows[0]["direct"] == 1 and rows[0]["snr"] == -3.5 and rows[0]["n"] == 1
    assert mon.live[pub].last_heard_via == "advert"
    assert mon.db.one("SELECT name FROM seen_nodes WHERE pubkey=?", (pub,))["name"] == "Test RPT"


def test_relay_attribution_requires_unique_prefix(mon):
    priv, pub = keypair(0x42)
    other_priv, other_pub = keypair(0x43)
    watch(mon, pub)
    mon.ingest(advert_packet(priv, hops=["99"]), "obsA")             # learn type=repeater
    mon.ingest(frame(5, b"payload-1", hops=["11", "42"]), "obsB", "SMF", 7.25, -90)
    mon.flush(force=True)
    relay = mon.db.q("SELECT * FROM observations WHERE kind='relay'")
    assert len(relay) == 1 and relay[0]["snr"] == 7.25 and relay[0]["direct"] == 1

    # A second known repeater with the same 1-byte prefix makes it ambiguous.
    clash_priv, clash_pub = keypair(0x42)
    mon.ingest(advert_packet(clash_priv, name="Other"), "obsA")
    mon.ingest(frame(5, b"payload-2", hops=["42"]), "obsB", "SMF", 1.0, -95)
    mon.flush(force=True)
    assert len(mon.db.q("SELECT * FROM observations WHERE kind='relay'")) == 1
    assert mon.stats["ambiguous_hops"] >= 1


def test_middle_hop_marks_alive_without_signal(mon):
    priv, pub = keypair(0x55)
    watch(mon, pub)
    mon.ingest(advert_packet(priv, hops=["01"]), "obsA")
    before = mon.live[pub].last_heard
    time.sleep(0.01)
    mon.ingest(frame(5, b"xyz", hops=["55", "66"]), "obsB", "SMF", 2, -80)
    mon.flush(force=True)
    assert mon.live[pub].last_heard > before
    assert not mon.db.q("SELECT * FROM observations WHERE kind='relay'")


def test_search(mon):
    priv, pub = keypair(None)
    mon.ingest(advert_packet(priv, name="Sutro Tower"), "o")
    assert [n.pubkey for n in mon.search("sutro")] == [pub]
    assert [n.pubkey for n in mon.search(pub[:6])] == [pub]
