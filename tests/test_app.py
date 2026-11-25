import time

import pytest
from fastapi.testclient import TestClient

from meshwatch.app import create_app
from meshwatch.config import Env
from helpers import advert_packet, keypair

ORIGIN = "https://mw.example.test"


@pytest.fixture
def client(tmp_path):
    env = Env(data_dir=tmp_path, secret_key="x" * 40, origin=ORIGIN, rp_id="mw.example.test",
              host="127.0.0.1", port=0, secure_cookies=False)
    app = create_app(env)
    with TestClient(app, base_url=ORIGIN) as c:
        c.svc = app.state.svc
        yield c


def login(c):
    token = c.svc.auth.new_session("test")
    c.cookies.set("mw_session", token)
    return {"Origin": ORIGIN}


def test_requires_auth(client):
    assert client.get("/", follow_redirects=False).status_code == 303
    assert client.get("/api/v1/nodes").status_code == 401
    assert (client.svc.auth.setup_token is not None)


def test_setup_token_required_for_first_passkey(client):
    r = client.post("/auth/register/options", json={"token": "wrong"}, headers={"Origin": ORIGIN})
    assert r.status_code == 403
    r = client.post("/auth/register/options", json={"token": client.svc.auth.setup_token}, headers={"Origin": ORIGIN})
    assert r.status_code == 200 and r.json()["options"]["rp"]["id"] == "mw.example.test"


def test_cross_origin_post_refused(client):
    login(client)
    r = client.post("/nodes", data={"pubkey": "ab" * 32}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_full_flow(client):
    h = login(client)
    priv, pub = keypair(None)
    client.svc.monitor.ingest(advert_packet(priv, name="Hilltop"), "obs1", "SMF", 4.0, -97)
    assert "Hilltop" in client.get("/partials/search?q=hill").text
    r = client.post("/nodes", data={"pubkey": pub, "label": "", "admin_pw": "secret", "guest_pw": ""},
                    headers=h, follow_redirects=False)
    assert r.status_code == 303
    row = client.svc.db.one("SELECT * FROM watched WHERE pubkey=?", (pub,))
    assert row["admin_pw"] and "secret" not in row["admin_pw"] and row["poll_enabled"] == 1
    client.svc.monitor.ingest(advert_packet(priv, name="Hilltop", ts=time.time() + 1), "obs2", "SMF", 6.0, -90)
    client.svc.monitor.flush(force=True)
    for path in ["/", "/partials/nodes", f"/nodes/{pub}", f"/nodes/{pub}?range=7d", f"/nodes/{pub}/console",
                 "/alerts", "/audit", "/settings", "/add"]:
        r = client.get(path)
        assert r.status_code == 200, path
        assert "secret" not in r.text
    assert "Hilltop" in client.get("/").text
    api = client.get(f"/api/v1/nodes/{pub}").json()
    assert api["observers_24h"] == 1 and api["has_admin"] and "admin_pw" not in api
    assert client.get(f"/api/v1/nodes/{pub}/history?metric=snr&range=24h").json()["points"]
    cat = client.get(f"/api/v1/cli/catalog?node={pub}").json()
    assert any(c["cmd"] == "get radio" for c in cat["commands"])
    # Disruptive command needs confirmation; then fails cleanly with no radio.
    r = client.post(f"/api/v1/nodes/{pub}/cli", json={"command": "reboot"}, headers=h)
    assert r.status_code == 409
    r = client.post(f"/api/v1/nodes/{pub}/cli", json={"command": "reboot", "confirm": True}, headers=h)
    assert r.status_code == 200 and r.json()["ok"] is False and "not connected" in r.json()["error"]
    r = client.post(f"/api/v1/nodes/{pub}/cli", json={"command": "get prv.key"}, headers=h)
    assert r.status_code == 400
    assert client.svc.db.one("SELECT COUNT(*) c FROM audit WHERE action='cli'")["c"] == 1
    # Settings: change thresholds, clear password
    r = client.post(f"/nodes/{pub}/settings", data={"label": "Hill", "poll_interval_min": "45", "silent_min": "",
                    "battery_mv": "3400", "snr_drop_db": "5", "notes": "n", "alerts_enabled": "on",
                    "clear_admin_pw": "on"}, headers=h, follow_redirects=False)
    assert r.status_code == 303
    row = client.svc.db.one("SELECT * FROM watched WHERE pubkey=?", (pub,))
    assert row["admin_pw"] is None and row["poll_interval_min"] == 45 and row["poll_enabled"] == 0
    r = client.post(f"/nodes/{pub}/settings", data={"poll_interval_min": "1", "battery_mv": "1", "snr_drop_db": "5"},
                    headers=h)
    assert r.status_code == 400
    # Settings pages
    assert client.post("/settings/ntfy", data={"server": "https://ntfy.sh", "topic": "abc_123", "enabled": "on",
                       "token": "tk"}, headers=h, follow_redirects=False).status_code == 303
    assert "tk" not in client.get("/settings").text
    r = client.post("/settings/mqtt", data={"name": "feed", "url": "ftp://x", "action": "add"}, headers=h)
    assert r.status_code == 400
    # Radios: add two, edit, assign one to the node, remove it again.
    for name, port in (("909", 5053), ("910", 5054)):
        r = client.post("/settings/radio", data={"name": name, "kind": "none", "host": "10.40.0.100",
                        "port": str(port), "regions": "sjc, SFO", "action": "add"}, headers=h, follow_redirects=False)
        assert r.status_code == 303
    radios = client.svc.db.get_setting("radios")
    assert [(x["id"], x["name"], x["port"], x["regions"]) for x in radios] == [
        ("r1", "909", 5053, ["SJC", "SFO"]), ("r2", "910", 5054, ["SJC", "SFO"])]
    assert set(client.svc.radios.by_id) == {"r1", "r2"}
    assert client.post("/settings/radio", data={"name": "x", "kind": "tcp", "port": "99999"},
                       headers=h).status_code == 400
    page = client.get("/settings").text
    assert "910" in page and "5054" in page
    assert len(client.get("/api/v1/status").json()["radios"]) == 2
    r = client.post(f"/nodes/{pub}/settings", data={"poll_interval_min": "45", "battery_mv": "3400",
                    "snr_drop_db": "5", "radio_id": "r2"}, headers=h, follow_redirects=False)
    assert r.status_code == 303 and client.get(f"/api/v1/nodes/{pub}").json()["radio_id"] == "r2"
    assert 'value="r2" selected' in client.get(f"/nodes/{pub}").text
    assert client.post(f"/nodes/{pub}/settings", data={"poll_interval_min": "45", "battery_mv": "3400",
                       "snr_drop_db": "5", "radio_id": "nope"}, headers=h).status_code == 400
    r = client.post("/settings/radio", data={"id": "r2", "action": "delete"}, headers=h, follow_redirects=False)
    assert r.status_code == 303 and set(client.svc.radios.by_id) == {"r1"}
    assert client.get(f"/api/v1/nodes/{pub}").json()["radio_id"] is None
    r = client.post("/settings/tokens", data={"label": "phone"}, headers=h, follow_redirects=False)
    token = r.cookies.get("mw_new_token")
    assert token and token.startswith("mw_")
    client.cookies.clear()
    assert client.get("/api/v1/nodes", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert client.get("/api/v1/nodes", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_new_pages_bulk_add_snippets_and_settings(client):
    h = login(client)
    keys = []
    for name, lat in (("Alpha", 38.6), ("Bravo", 38.7)):
        priv, pub = keypair(None)
        client.svc.monitor.ingest(advert_packet(priv, name=name, lat=lat, lon=-121.4), "obs1", "SMF", 4.0, -97)
        keys.append(pub)
    r = client.post("/nodes/bulk", data={"pubkey": keys, "guest_pw": "g"}, headers=h, follow_redirects=False)
    assert r.status_code == 303
    rows = client.svc.db.q("SELECT pubkey, poll_enabled, guest_pw FROM watched ORDER BY pubkey")
    assert sorted(r["pubkey"] for r in rows) == sorted(keys) and all(r["poll_enabled"] and r["guest_pw"] for r in rows)
    assert client.post("/nodes/bulk", data={"pubkey": ["xyz"]}, headers=h).status_code == 400
    client.svc.monitor.flush(force=True)
    for path in ["/", "/map", "/fleet", "/console", "/settings", f"/nodes/{keys[0]}"]:
        r = client.get(path)
        assert r.status_code == 200, path
    assert "tile.openstreetmap.org" in client.get("/map").headers["content-security-policy"]
    assert "tile.openstreetmap.org" not in client.get("/").headers["content-security-policy"]
    m = client.get("/api/v1/map").json()
    assert {n["label"] for n in m["nodes"]} == {"Alpha", "Bravo"} and all(n["pos"] for n in m["nodes"])
    # Snippets
    assert client.post("/api/v1/snippets", json={"name": "x", "commands": ["password hunter2"]},
                       headers=h).status_code == 400
    r = client.post("/api/v1/snippets", json={"name": "Std", "commands": ["get tx", " set flood.max  8 ", ""]},
                    headers=h)
    assert r.status_code == 200
    snips = client.get("/api/v1/snippets").json()["snippets"]
    assert snips == [{"id": r.json()["id"], "name": "Std", "commands": ["get tx", "set flood.max 8"]}]
    assert client.post(f"/api/v1/snippets/{snips[0]['id']}/delete", headers=h).json()["ok"]
    # Secrets never reach the audit log or history, even when the command fails.
    client.svc.db.x("UPDATE watched SET admin_pw=? WHERE pubkey=?", (client.svc.box.seal("a"), keys[0]))
    r = client.post(f"/api/v1/nodes/{keys[0]}/cli", json={"command": "password hunter2", "confirm": True}, headers=h)
    assert r.status_code == 200 and "hunter2" not in r.text
    assert client.svc.db.one("SELECT COUNT(*) c FROM audit WHERE detail LIKE '%hunter2%'")["c"] == 0
    assert client.svc.db.one("SELECT COUNT(*) c FROM cli_history WHERE command LIKE '%hunter2%'")["c"] == 0
    # General settings
    assert client.post("/settings/general", data={"timezone": "Mars/Base", "map_tiles": ""},
                       headers=h).status_code == 400
    assert client.post("/settings/general", data={"timezone": "America/Los_Angeles", "map_tiles": "",
                       "check_releases": "on"}, headers=h, follow_redirects=False).status_code == 303
    assert client.svc.db.get_setting("general")["timezone"] == "America/Los_Angeles"
    assert client.post("/settings/ntfy", data={"server": "https://ntfy.sh", "topic": "t", "summary_time": "25:00"},
                       headers=h).status_code == 400
