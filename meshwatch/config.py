"""Process configuration (environment) and runtime settings (database)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class Env:
    data_dir: Path
    secret_key: str
    origin: str          # public origin, e.g. https://meshwatch.example.org
    rp_id: str           # WebAuthn relying party id (host of origin)
    host: str
    port: int
    secure_cookies: bool

    @classmethod
    def load(cls) -> "Env":
        secret = os.environ.get("MW_SECRET_KEY", "")
        if len(secret) < 32:
            raise SystemExit("MW_SECRET_KEY must be set (at least 32 characters). "
                             "Generate one with: python -c 'import secrets;print(secrets.token_urlsafe(48))'")
        origin = os.environ.get("MW_ORIGIN", "http://localhost:8790").rstrip("/")
        parsed = urlparse(origin)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise SystemExit("MW_ORIGIN must look like https://meshwatch.example.org")
        return cls(
            data_dir=Path(os.environ.get("MW_DATA_DIR", "./data")),
            secret_key=secret,
            origin=origin,
            rp_id=os.environ.get("MW_RP_ID", parsed.hostname),
            host=os.environ.get("MW_HOST", "127.0.0.1"),
            port=int(os.environ.get("MW_PORT", "8790")),
            secure_cookies=parsed.scheme == "https",
        )


# Runtime settings, editable on the Settings page. Secrets inside are sealed
# with crypto.Box and stored as "<name>_enc".
DEFAULTS = {
    "mqtt_sources": [],   # [{id,name,url,username,password_enc,topics:[...],enabled}]
    # [{id,name,kind,host,port,serial_port,baud,regions:[...]}]; one per network/frequency
    "radios": [],
    "radio": {"kind": "none", "host": "", "port": 5000, "serial_port": "", "baud": 115200},  # pre-0.2, migrated
    "ntfy": {"server": "https://ntfy.sh", "topic": "", "token_enc": None, "enabled": False,
             "summary_enabled": True, "summary_time": "08:00"},
    # timezone: IANA name used for times on pages and the daily summary
    "general": {"timezone": os.environ.get("TZ") or "UTC",
                "map_tiles": "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
                "check_releases": True},
    "polling": {"budget_per_hour": 20, "min_gap_s": 15, "max_backoff_min": 360,
                "login_max_age_min": 180, "request_timeout_s": 30},
    "alerts": {"passive_silent_min": 1500, "polled_silent_min": 90,
               "snr_window_min": 120, "snr_baseline_days": 7, "snr_min_samples": 5,
               "observer_drop_ratio": 0.5},
}


def radios(db) -> list[dict]:
    """Configured companions; converts the single pre-0.2 "radio" setting on first use."""
    value = db.get_setting("radios")
    if value is None:
        old = db.get_setting("radio") or {}
        value = []
        if old.get("kind") in ("tcp", "serial"):
            value = [{**DEFAULTS["radio"], **old, "id": "r1", "name": "Radio 1", "regions": []}]
        db.set_setting("radios", value)
    return value


def get(db, key: str):
    value = db.get_setting(key)
    default = DEFAULTS[key]
    if isinstance(default, dict):
        return {**default, **(value or {})}
    return value if value is not None else default
