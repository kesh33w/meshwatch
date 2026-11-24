import json
import time

import pytest

from meshwatch.alerts import Alerts
from meshwatch.db import DB
from meshwatch.monitor import Monitor


class FakeNotifier:
    def __init__(self):
        self.sent = []

    async def send(self, title, message, priority=3, tags="", path="/"):
        self.sent.append(title)


@pytest.fixture
def env(tmp_path):
    db = DB(tmp_path / "a.db")
    mon = Monitor(db)
    n = FakeNotifier()
    al = Alerts(db, mon, n, lambda: time.time())
    return db, mon, n, al


async def test_silent_fires_once_and_resolves(env):
    db, mon, n, al = env
    key = "ab" * 32
    db.x("INSERT INTO watched(pubkey,added_at,poll_enabled,silent_min) VALUES(?,?,0,10)", (key, time.time() - 3600))
    mon.reload_watched()
    await al.evaluate()
    await al.evaluate()
    assert len([t for t in n.sent if "Not heard" in t or key[:8] in t]) == 1
    assert al.open_alert(key, "silent")
    mon.heard_by_poll(key, time.time())
    await al.evaluate()
    assert not al.open_alert(key, "silent")
    assert n.sent[-1].endswith(": OK")


async def test_battery_hysteresis(env):
    db, mon, n, al = env
    key = "cd" * 32
    db.x("INSERT INTO watched(pubkey,added_at,battery_mv) VALUES(?,?,3500)", (key, time.time()))
    mon.reload_watched()
    mon.heard_by_poll(key, time.time())

    async def bat(mv):
        db.x("INSERT INTO node_state(pubkey,status) VALUES(?,?) ON CONFLICT(pubkey) DO UPDATE SET status=excluded.status",
             (key, json.dumps({"bat": mv})))
        await al.evaluate()

    await bat(3450)
    assert al.open_alert(key, "battery")
    await bat(3550)              # inside hysteresis band
    assert al.open_alert(key, "battery")
    await bat(3650)
    assert not al.open_alert(key, "battery")


async def test_no_data_system_alert(tmp_path):
    db = DB(tmp_path / "s.db")
    mon = Monitor(db)
    n = FakeNotifier()
    al = Alerts(db, mon, n, lambda: time.time() - 3600)
    await al.evaluate()
    assert al.open_alert("", "no_data")
