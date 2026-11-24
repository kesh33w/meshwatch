import json

from meshwatch import cli
from meshwatch.ingest import parse_message


def test_catalog_loads_and_flags():
    cmds = cli.catalog()["commands"]
    assert len(cmds) > 50
    assert cli.match("set tx 22")["cmd"] == "set tx"
    assert cli.needs_confirm("reboot")
    assert cli.needs_confirm("set tx 20")
    assert not cli.needs_confirm("get radio")
    assert cli.needs_confirm("set something.unknown 1")     # unknown setters are guarded
    assert cli.serial_only("get prv.key")


def test_parse_mqtt_message():
    body = json.dumps({"raw": "1500", "SNR": "5.5", "RSSI": -99, "timestamp": "2026-01-01T00:00:00Z"}).encode()
    raw, obs, region, snr, rssi, ts = parse_message("meshcore/SMF/ABCDEF@g39/packets", body)
    assert (raw, obs, region, snr, rssi) == ("1500", "ABCDEF", "SMF", 5.5, -99)
    assert ts is None   # far from now -> receipt time
    assert parse_message("meshcore/SMF/x/packets", b"not json") is None
    zoneless = json.dumps({"raw": "1500", "timestamp": "2026-11-24T10:00:00"}).encode()
    assert parse_message("meshcore/SMF/x/packets", zoneless)[5] is None
