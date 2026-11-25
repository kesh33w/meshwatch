import json
import time

import pytest

from meshwatch.alerts import Alerts
from meshwatch.db import DB
from meshwatch.monitor import Monitor


class FakeNotifier:
    def __init__(self):
        self.sent = []

    async def send(self, title, message, priority=3, tags="", path="/", actions=None):
        self.sent.append(title)
        self.bodies = getattr(self, "bodies", []) + [message]


@pytest.fixture
def env(tmp_path):
    db = DB(tmp_path / "a.db")
    mon = Monitor(db)
    n = FakeNotifier()
    al = Alerts(db, mon, n, lambda: time.time())
    return db, mon, n, al


async def test_silent_fires_once_and_resolves(env, monkeypatch):
    monkeypatch.setattr("meshwatch.alerts.CONFIRM_S", 0)
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


async def test_silent_waits_for_confirmation(env):
    db, mon, n, al = env
    key = "ef" * 32
    db.x("INSERT INTO watched(pubkey,added_at,poll_enabled,silent_min) VALUES(?,?,0,10)", (key, time.time() - 3600))
    mon.reload_watched()
    await al.evaluate()
    assert not al.open_alert(key, "silent")          # condition must hold for 5 minutes
    al._pending[key] -= 301
    await al.evaluate()
    assert al.open_alert(key, "silent")


async def test_polled_node_is_polled_before_it_is_called_silent(env, monkeypatch):
    monkeypatch.setattr("meshwatch.alerts.CONFIRM_S", 0)
    db, mon, n, al = env
    kicks = []
    al.kick = lambda: kicks.append(1)
    key = "12" * 32
    now = time.time()
    db.x("INSERT INTO watched(pubkey,added_at,poll_enabled,silent_min) VALUES(?,?,1,10)", (key, now - 7200))
    db.x("INSERT INTO node_state(pubkey,last_heard,last_poll_at,next_poll_at,poll_fails) VALUES(?,?,?,?,0)",
         (key, now - 3600, now - 1800, now + 1800))
    mon.reload_watched()
    await al.evaluate()
    assert not al.open_alert(key, "silent")
    state = db.one("SELECT next_poll_at FROM node_state WHERE pubkey=?", (key,))
    assert state["next_poll_at"] <= time.time() and kicks          # early poll requested
    # One failed poll is not enough; two failed polls after it was last heard are.
    db.x("UPDATE node_state SET poll_fails=1, last_poll_at=? WHERE pubkey=?", (time.time(), key))
    await al.evaluate()
    assert not al.open_alert(key, "silent")
    db.x("UPDATE node_state SET poll_fails=2, last_poll_at=? WHERE pubkey=?", (time.time(), key))
    await al.evaluate()
    assert al.open_alert(key, "silent")
    assert "Polls failing ×2" in n.bodies[-1]


async def test_daily_summary(env):
    db, mon, n, al = env
    db.set_setting("general", {"timezone": "America/Los_Angeles"})
    db.set_setting("ntfy", {"summary_enabled": True, "summary_time": "00:00"})
    key = "34" * 32
    db.x("INSERT INTO watched(pubkey,label,added_at) VALUES(?,?,?)", (key, "Hill", time.time()))
    db.x("INSERT INTO node_state(pubkey,status,firmware) VALUES(?,?,?)", (key, json.dumps({"bat": 3900}), "v1.17.0-abc"))
    db.set_setting("fw_latest", {"versions": {"repeater": [1, 18, 0]}, "checked": time.time()})
    mon.reload_watched()
    title, body, ok = al.summary(time.time())
    assert ok and title == "meshwatch: all 1 nodes OK"
    assert "Hill 3.90 V" in body and "Firmware behind 1.18.0: Hill 1.17.0" in body
    await al.maybe_summary()
    await al.maybe_summary()
    assert n.sent.count(title) == 1                      # once per day
