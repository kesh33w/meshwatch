"""Hourly rollups and retention: raw data 30 days, rollups 1 year."""
from __future__ import annotations

import time

RAW_DAYS = 30
ROLLUP_DAYS = 365

# metric -> SQL returning (pubkey, hour, n, vmin, vmax, vsum) for one hour [?, ?)
ROLLUP_SQL = {
    "snr": "SELECT pubkey, SUM(n), MIN(snr), MAX(snr), SUM(snr*n) FROM observations"
           " WHERE direct=1 AND snr IS NOT NULL AND ts>=? AND ts<? GROUP BY pubkey",
    "rssi": "SELECT pubkey, SUM(n), MIN(rssi), MAX(rssi), SUM(rssi*n) FROM observations"
            " WHERE direct=1 AND rssi IS NOT NULL AND ts>=? AND ts<? GROUP BY pubkey",
    "observers": "SELECT pubkey, 1, COUNT(DISTINCT observer), COUNT(DISTINCT observer), COUNT(DISTINCT observer)"
                 " FROM observations WHERE direct=1 AND ts>=? AND ts<? GROUP BY pubkey",
    "heard": "SELECT pubkey, 1, SUM(n), SUM(n), SUM(n) FROM observations WHERE ts>=? AND ts<? GROUP BY pubkey",
    "bat": "SELECT pubkey, COUNT(*), MIN(bat), MAX(bat), SUM(bat) FROM status_samples"
           " WHERE bat>0 AND ts>=? AND ts<? GROUP BY pubkey",
    "noise_floor": "SELECT pubkey, COUNT(*), MIN(noise_floor), MAX(noise_floor), SUM(noise_floor)"
                   " FROM status_samples WHERE noise_floor<0 AND ts>=? AND ts<? GROUP BY pubkey",
}


def rollup(db, now: float | None = None) -> int:
    now = now or time.time()
    last_full_hour = int(now // 3600) - 1
    done = db.get_setting("rollup_until")
    start = done + 1 if done is not None else last_full_hour - 24 * RAW_DAYS
    rows = 0
    for hour in range(max(start, last_full_hour - 24 * RAW_DAYS), last_full_hour + 1):
        t0, t1 = hour * 3600, (hour + 1) * 3600
        batch = []
        for metric, sql in ROLLUP_SQL.items():
            for r in db.q(sql, (t0, t1)):
                batch.append((r[0], hour, metric, r[1], r[2], r[3], r[4]))
        if batch:
            db.many("INSERT OR REPLACE INTO rollups(pubkey,hour,metric,n,vmin,vmax,vsum) VALUES(?,?,?,?,?,?,?)", batch)
            rows += len(batch)
    db.set_setting("rollup_until", last_full_hour)
    return rows


def prune(db, now: float | None = None) -> None:
    now = now or time.time()
    raw_cut, roll_cut = now - RAW_DAYS * 86400, now - ROLLUP_DAYS * 86400
    with db.conn:
        for table in ("observations", "status_samples", "telemetry_samples"):
            db.conn.execute(f"DELETE FROM {table} WHERE ts<?", (raw_cut,))
        db.conn.execute("DELETE FROM rollups WHERE hour<?", (int(roll_cut // 3600),))
        db.conn.execute("DELETE FROM alerts WHERE resolved IS NOT NULL AND resolved<?", (roll_cut,))
        db.conn.execute("DELETE FROM audit WHERE ts<?", (roll_cut,))
        db.conn.execute("DELETE FROM sessions WHERE expires<?", (now,))
        db.conn.execute("DELETE FROM seen_nodes WHERE last_seen<?", (now - 90 * 86400,))
