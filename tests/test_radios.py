import asyncio
import json
import sqlite3
import time

import pytest

from meshwatch import config
from meshwatch.db import DB
from meshwatch.monitor import Monitor
from meshwatch.poller import Poller
from meshwatch.radio import Radios, RadioError
from helpers import advert_packet, keypair


class FakeRadio:
    """Stands in for radio.Radio in choose() and the poller."""

    def __init__(self, rid, key, regions=(), state="connected"):
        self.id, self.name, self.state = rid, rid, state
        self.public_key, self.regions = key, set(regions)
        self.lock = asyncio.Lock()
        self.calls = []

    async def contact(self, pubkey, seen=None):
        return {"public_key": pubkey}

    async def login(self, contact, password, timeout):
        self.calls.append("login")
        return {"is_admin": True}

    async def status(self, contact, timeout):
        self.calls.append("status")
        return {"bat": 4000}

    async def telemetry(self, contact, timeout):
        return None


def make(tmp_path, *radios):
    db = DB(tmp_path / "t.db")
    mon = Monitor(db)
    rs = Radios()
    rs.by_id = {r.id: r for r in radios}
    return db, mon, rs


def watch(db, mon, pub, radio_id=None, admin=None):
    db.x("INSERT INTO watched(pubkey,added_at,radio_id,admin_pw) VALUES(?,?,?,?)",
         (pub, time.time(), radio_id, admin))
    mon.reload_watched()


def test_old_single_radio_setting_is_migrated(tmp_path):
    db = DB(tmp_path / "t.db")
    db.set_setting("radio", {"kind": "tcp", "host": "10.0.0.1", "port": 5053})
    radios = config.radios(db)
    assert radios == [{"kind": "tcp", "host": "10.0.0.1", "port": 5053, "serial_port": "", "baud": 115200,
                       "id": "r1", "name": "Radio 1", "regions": []}]
    assert db.get_setting("radios") == radios
    db2 = DB(tmp_path / "u.db")
    db2.set_setting("radio", {"kind": "none"})
    assert config.radios(db2) == []


def test_db_adds_new_columns_to_old_tables(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE watched (pubkey TEXT PRIMARY KEY, label TEXT, added_at REAL NOT NULL)")
    conn.execute("CREATE TABLE node_state (pubkey TEXT PRIMARY KEY, last_heard REAL)")
    conn.commit()
    conn.close()
    db = DB(path)
    assert "radio_id" in {r["name"] for r in db.q("PRAGMA table_info(watched)")}
    assert {"poll_radio", "login_radio"} <= {r["name"] for r in db.q("PRAGMA table_info(node_state)")}


def test_choose_prefers_explicit_then_own_hearing_then_region(tmp_path):
    r909, r910 = FakeRadio("r1", "aa" * 32, ["SMF"]), FakeRadio("r2", "bb" * 32, ["SJC"])
    db, mon, rs = make(tmp_path, r909, r910)
    priv, pub = keypair(None)
    watch(db, mon, pub)
    # Heard only via MQTT in the Bay region -> the 910 radio.
    mon.ingest(advert_packet(priv), "obs1", "SJC", 3.0, -100)
    assert rs.choose(pub, None, mon, db) is r910
    # Heard by the 909 companion itself -> that wins over region.
    mon.ingest(advert_packet(priv, ts=time.time() + 5), r909.public_key, "radio", 3.0, -100)
    mon.flush(force=True)
    assert rs.choose(pub, None, mon, db) is r909
    # Explicit choice beats everything.
    assert rs.choose(pub, "r2", mon, db) is r910
    with pytest.raises(RadioError):
        rs.choose(pub, "gone", mon, db)


def test_choose_needs_a_connected_radio(tmp_path):
    db, mon, rs = make(tmp_path, FakeRadio("r1", "aa" * 32, state="error"))
    with pytest.raises(RadioError, match="not connected"):
        rs.choose("cc" * 32, None, mon, db)


def test_poll_uses_node_radio_and_per_radio_budget(tmp_path):
    from meshwatch.crypto import Box
    r1, r2 = FakeRadio("r1", "aa" * 32), FakeRadio("r2", "bb" * 32)
    db, mon, rs = make(tmp_path, r1, r2)
    box = Box("x" * 40)
    poller = Poller(db, box, rs, mon)
    pub = "cc" * 32
    watch(db, mon, pub, radio_id="r2", admin=box.seal("pw"))
    row = db.one("SELECT * FROM watched WHERE pubkey=?", (pub,))
    settings = config.get(db, "polling")

    result = asyncio.run(poller.poll(row, settings))
    assert result["ok"] and result["radio"] == "r2"
    assert r2.calls == ["login", "status"] and r1.calls == []
    state = db.one("SELECT * FROM node_state WHERE pubkey=?", (pub,))
    assert state["poll_radio"] == "r2" and state["login_radio"] == "r2"
    assert poller.budget_left(settings, "r2") == settings["budget_per_hour"] - 3
    assert poller.budget_left(settings, "r1") == settings["budget_per_hour"]

    # Switching the node to the other radio forces a fresh login there.
    db.x("UPDATE watched SET radio_id='r1' WHERE pubkey=?", (pub,))
    row = db.one("SELECT * FROM watched WHERE pubkey=?", (pub,))
    assert asyncio.run(poller.poll(row, settings))["radio"] == "r1"
    assert r1.calls == ["login", "status"]


def test_tick_polls_both_radios_in_parallel(tmp_path):
    from meshwatch.crypto import Box
    r1, r2 = FakeRadio("r1", "aa" * 32), FakeRadio("r2", "bb" * 32)
    db, mon, rs = make(tmp_path, r1, r2)
    box = Box("x" * 40)
    poller = Poller(db, box, rs, mon)
    for i, rid in enumerate(["r1", "r1", "r2"]):
        watch(db, mon, f"{i:02x}" * 32, radio_id=rid, admin=box.seal("pw"))

    async def go():
        await poller.tick()
        assert set(poller.current) == {"r1", "r2"}   # one per radio, not two on r1
        await asyncio.gather(*poller.running)

    asyncio.run(go())
    polled = {r["pubkey"]: r["poll_radio"] for r in db.q("SELECT * FROM node_state WHERE last_poll_ok IS NOT NULL")}
    assert sorted(polled.values()) == ["r1", "r2"]
