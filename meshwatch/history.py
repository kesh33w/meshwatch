"""Time series for charts and the API, plus small server-rendered SVG charts."""
from __future__ import annotations

import html
import time
from datetime import datetime

RANGES = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "1y": 365 * 86400}
METRICS = {
    "snr": ("SNR heard by observers", "dB"),
    "rssi": ("RSSI heard by observers", "dBm"),
    "observers": ("Observers hearing it directly", ""),
    "bat": ("Battery", "V"),
    "noise_floor": ("Noise floor", "dBm"),
}

RAW_SQL = {
    "snr": "SELECT CAST(ts/? AS INTEGER)*? AS t, SUM(snr*n)/SUM(n) FROM observations"
           " WHERE pubkey=? AND direct=1 AND snr IS NOT NULL AND ts>=? GROUP BY t ORDER BY t",
    "rssi": "SELECT CAST(ts/? AS INTEGER)*? AS t, SUM(rssi*n)/SUM(n) FROM observations"
            " WHERE pubkey=? AND direct=1 AND rssi IS NOT NULL AND ts>=? GROUP BY t ORDER BY t",
    "observers": "SELECT CAST(ts/? AS INTEGER)*? AS t, COUNT(DISTINCT observer) FROM observations"
                 " WHERE pubkey=? AND direct=1 AND ts>=? GROUP BY t ORDER BY t",
    "bat": "SELECT CAST(ts/? AS INTEGER)*? AS t, AVG(bat)/1000.0 FROM status_samples"
           " WHERE pubkey=? AND bat>0 AND ts>=? GROUP BY t ORDER BY t",
    "noise_floor": "SELECT CAST(ts/? AS INTEGER)*? AS t, AVG(noise_floor) FROM status_samples"
                   " WHERE pubkey=? AND noise_floor<0 AND ts>=? GROUP BY t ORDER BY t",
}


def series(db, pubkey: str, metric: str, range_key: str = "24h") -> list[tuple[float, float]]:
    if metric not in METRICS or range_key not in RANGES:
        raise ValueError("unknown metric or range")
    span = RANGES[range_key]
    since = time.time() - span
    if range_key == "24h":
        step = 900 if metric in ("snr", "rssi", "observers") else 60
        return [(r[0], r[1]) for r in db.q(RAW_SQL[metric], (step, step, pubkey, since)) if r[1] is not None]
    hours = 1 if range_key == "7d" else (3 if range_key == "30d" else 24)
    if metric == "observers":
        sql = ("SELECT CAST(hour/? AS INTEGER)*?*3600 AS t, MAX(vmax) FROM rollups"
               " WHERE pubkey=? AND metric=? AND hour>=? GROUP BY t ORDER BY t")
    else:
        sql = ("SELECT CAST(hour/? AS INTEGER)*?*3600 AS t, SUM(vsum)/SUM(n) FROM rollups"
               " WHERE pubkey=? AND metric=? AND hour>=? GROUP BY t ORDER BY t")
    rows = db.q(sql, (hours, hours, pubkey, metric, int(since // 3600)))
    scale = 1000.0 if metric == "bat" else 1.0
    return [(r[0], r[1] / scale) for r in rows if r[1] is not None]


def svg_chart(points: list[tuple[float, float]], span: float, unit: str = "", width=640, height=150) -> str:
    """Line chart; gaps where samples are missing. Colors come from CSS."""
    if not points:
        return '<p class="muted">No data in this range yet.</p>'
    now = time.time()
    t0 = now - span
    pad_l, pad_r, pad_t, pad_b = 46, 8, 8, 20
    w, h = width - pad_l - pad_r, height - pad_t - pad_b
    values = [v for _, v in points]
    lo, hi = min(values), max(values)
    if hi - lo < 1e-9:
        lo, hi = lo - 1, hi + 1
    margin = (hi - lo) * 0.1
    lo, hi = lo - margin, hi + margin

    def x(t):
        return pad_l + (t - t0) / span * w

    def y(v):
        return pad_t + (hi - v) / (hi - lo) * h

    gaps = sorted(b[0] - a[0] for a, b in zip(points, points[1:]))
    typical = gaps[len(gaps) // 2] if gaps else span
    segments, current, prev = [], [], None
    for t, v in points:
        if prev is not None and t - prev > max(typical * 3, span / 100):
            segments.append(current)
            current = []
        current.append(f"{x(t):.1f},{y(v):.1f}")
        prev = t
    segments.append(current)
    lines = "".join(
        f'<polyline class="line" points="{" ".join(seg)}"/>' if len(seg) > 1 else
        f'<circle class="dot" cx="{seg[0].split(",")[0]}" cy="{seg[0].split(",")[1]}" r="2"/>'
        for seg in segments if seg)
    fmt = (lambda v: f"{v:.2f}") if hi - lo < 5 else (lambda v: f"{v:.0f}")
    ticks = ""
    for frac in (0, 0.5, 1):
        v = hi - frac * (hi - lo)
        ty = pad_t + frac * h
        ticks += (f'<line class="grid" x1="{pad_l}" x2="{width - pad_r}" y1="{ty:.1f}" y2="{ty:.1f}"/>'
                  f'<text class="axis" x="{pad_l - 4}" y="{ty + 4:.1f}" text-anchor="end">{fmt(v)}</text>')
    label_fmt = "%H:%M" if span <= 86400 else "%b %d"
    for frac in (0, 0.5, 1):
        t = t0 + frac * span
        anchor = "start" if frac == 0 else ("end" if frac == 1 else "middle")
        ticks += (f'<text class="axis" x="{x(t):.1f}" y="{height - 4}" text-anchor="{anchor}">'
                  f'{datetime.fromtimestamp(t).strftime(label_fmt)}</text>')
    latest = points[-1][1]
    title = html.escape(f"latest {fmt(latest)} {unit}".strip())
    return (f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{title}">'
            f"<title>{title}</title>{ticks}{lines}</svg>")


def sparkline(points: list[tuple[float, float]], span: float, width=120, height=28) -> str:
    """Tiny axis-less line for dashboard cards; empty string without data."""
    if len(points) < 2:
        return ""
    t0 = time.time() - span
    values = [v for _, v in points]
    lo, hi = min(values), max(values)
    if hi - lo < 1e-9:
        lo, hi = lo - 1, hi + 1
    pts = " ".join(f"{(t - t0) / span * width:.1f},{2 + (hi - v) / (hi - lo) * (height - 4):.1f}" for t, v in points)
    title = html.escape(f"{values[-1]:.2f}" if hi - lo < 5 else f"{values[-1]:.0f}")
    return (f'<svg class="spark" viewBox="0 0 {width} {height}" preserveAspectRatio="none" role="img"'
            f' aria-label="24 hour trend, latest {title}"><polyline class="line" points="{pts}"/></svg>')
