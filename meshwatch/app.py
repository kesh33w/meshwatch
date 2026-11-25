"""FastAPI application: wiring, background jobs, HTML pages and JSON API."""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from urllib.parse import urlparse

from . import __version__, cli, config, firmware, history, maintenance
from .alerts import Alerts, Notifier, fmt_age, local, node_label
from .auth import SESSION_COOKIE, SESSION_DAYS, Auth
from .crypto import Box
from .db import DB
from .ingest import DEFAULT_TOPICS, Sources
from .monitor import Monitor
from .poller import Poller
from .radio import Radios, RadioError

log = logging.getLogger("meshwatch")
HERE = Path(__file__).parent
PUBKEY = re.compile(r"^[0-9a-f]{64}$")
PUBLIC_PATHS = {"/login", "/setup", "/auth/login/options", "/auth/login", "/auth/register/options",
                "/auth/register", "/healthz", "/manifest.webmanifest"}


class Services:
    """Everything the routes need, created in the lifespan."""

    def __init__(self, env):
        self.env = env
        self.started = time.time()
        self.db = DB(env.data_dir / "meshwatch.db")
        self.box = Box(env.secret_key)
        self.auth = Auth(self.db, env)
        self.monitor = Monitor(self.db)
        self.radios = Radios(on_rx=self._radio_rx)
        self.sources = Sources(self.monitor, self.box)
        self.poller = Poller(self.db, self.box, self.radios, self.monitor)
        self.notifier = Notifier(self.db, self.box, env.origin)
        self.alerts = Alerts(self.db, self.monitor, self.notifier, self.last_data, kick=self.poller.kick)
        self.tasks: list[asyncio.Task] = []

    def _radio_rx(self, radio, raw, snr, rssi) -> None:
        # The companion's public key is the observer, so "heard by" lists it like any MQTT observer
        # and automatic radio choice can tell which companion hears a node.
        self.monitor.ingest(raw, radio.public_key or f"companion-{radio.id}", "radio", snr, rssi)

    def last_data(self) -> float | None:
        times = [s.last_message for s in self.sources.sources.values() if s.last_message]
        if self.radios.last_rx:
            times.append(self.radios.last_rx)
        # Grace period after start before "no data" can fire.
        return max(times) if times else self.started

    async def start(self) -> None:
        await self.sources.apply(config.get(self.db, "mqtt_sources"))
        self.radios.apply(config.radios(self.db))
        self.radios.start()
        self.tasks = [asyncio.create_task(self.poller.run(), name="poller"),
                      asyncio.create_task(self._every(60, self._minute), name="minute"),
                      asyncio.create_task(self._every(3600, self._hourly, first=30), name="hourly")]

    async def stop(self) -> None:
        for t in self.tasks:
            t.cancel()
        for t in self.tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await t
        await self.sources.stop()
        await self.radios.stop()
        self.monitor.flush(force=True)

    async def _every(self, seconds, fn, first=None) -> None:
        await asyncio.sleep(seconds if first is None else first)
        while True:
            try:
                await fn()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("%s failed", fn.__name__)
            await asyncio.sleep(seconds)

    async def _minute(self) -> None:
        self.monitor.flush()
        await self.alerts.evaluate()
        await self.alerts.maybe_summary()

    async def _hourly(self) -> None:
        maintenance.rollup(self.db)
        maintenance.prune(self.db)
        if config.get(self.db, "general").get("check_releases"):
            checked = (self.db.get_setting("fw_latest") or {}).get("checked") or 0
            if time.time() - checked > 86400:
                await firmware.fetch_latest(self.db)

    def tile_origin(self) -> str:
        """Origin of the map tile server, for the page's Content-Security-Policy."""
        url = urlparse(config.get(self.db, "general").get("map_tiles") or "")
        host = (url.hostname or "").replace("{s}", "*")
        return f"https://{host}" if url.scheme == "https" and host else ""


def create_app(env=None) -> FastAPI:
    env = env or config.Env.load()

    @asynccontextmanager
    async def lifespan(app):
        svc = Services(env)
        app.state.svc = svc
        templates.env.globals["dt_db"] = svc.db     # page times in the configured timezone
        await svc.start()
        try:
            yield
        finally:
            await svc.stop()

    app = FastAPI(title="meshwatch", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None,
                  openapi_url="/api/v1/openapi.json")
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals.update(version=__version__, fmt_age=fmt_age)
    templates.env.filters["age"] = lambda ts: "never" if not ts else fmt_age(max(0, time.time() - ts)) + " ago"
    templates.env.globals["dt_db"] = None

    def dt(ts, fmt="%Y-%m-%d %H:%M"):
        db = templates.env.globals["dt_db"]
        if not ts:
            return "—"
        return local(db, ts).strftime(fmt) if db else time.strftime(fmt, time.localtime(ts))

    templates.env.filters["dt"] = dt

    def svc(request: Request) -> Services:
        return request.app.state.svc

    # --- auth middleware ----------------------------------------------------
    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        s: Services = request.app.state.svc
        if path.startswith("/static/") or path in PUBLIC_PATHS:
            who = None
        else:
            who = s.auth.identify(request)
            if who is None:
                if path.startswith("/api/") or request.method != "GET":
                    return JSONResponse({"error": "authentication required"}, status_code=401)
                return RedirectResponse("/login?next=" + path, status_code=303)
        if request.method not in ("GET", "HEAD", "OPTIONS") and who != "token" and not s.auth.same_origin(request):
            return JSONResponse({"error": "cross-origin request refused"}, status_code=403)
        request.state.who = who
        response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            f"default-src 'self'; img-src 'self' data: {s.tile_origin() if path == '/map' else ''}; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        if request.url.path.startswith(("/api/", "/auth/")) or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
        return templates.TemplateResponse(request, "error.html", {"status": exc.status_code, "detail": exc.detail},
                                          status_code=exc.status_code)

    def client_desc(request: Request) -> str:
        ip = request.headers.get("cf-connecting-ip") or (request.client.host if request.client else "?")
        return f"{ip} {request.headers.get('user-agent', '')[:120]}"

    def page(request, name, **ctx):
        s = svc(request)
        open_alerts = s.db.one("SELECT COUNT(*) AS c FROM alerts WHERE resolved IS NULL")["c"]
        return templates.TemplateResponse(request, name, {"open_alerts": open_alerts, "radio": s.radios, **ctx})

    # --- login / setup ------------------------------------------------------
    @app.get("/healthz")
    async def healthz():
        return {"ok": True}

    @app.get("/manifest.webmanifest")
    async def manifest():
        return JSONResponse({"name": "meshwatch", "short_name": "meshwatch", "start_url": "/",
                             "display": "standalone", "background_color": "#0f1115", "theme_color": "#0f1115",
                             "icons": [{"src": "/static/icon.svg", "sizes": "any", "type": "image/svg+xml"}]},
                            media_type="application/manifest+json")

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, next: str = "/"):
        s = svc(request)
        if not s.auth.has_credentials():
            return templates.TemplateResponse(request, "setup.html", {"token": "", "needs_token": True})
        return templates.TemplateResponse(request, "login.html", {"next": next if next.startswith("/") else "/"})

    @app.get("/setup", response_class=HTMLResponse)
    async def setup_page(request: Request, token: str = ""):
        s = svc(request)
        if s.auth.has_credentials():
            return RedirectResponse("/login", status_code=303)
        return templates.TemplateResponse(request, "setup.html", {"token": token, "needs_token": True})

    def allowed_to_register(request: Request, token: str | None) -> bool:
        s = svc(request)
        return s.auth.identify(request) == "session" or (not s.auth.has_credentials()
                                                          and s.auth.check_setup_token(token))

    @app.post("/auth/register/options")
    async def register_options(request: Request):
        body = await request.json()
        if not allowed_to_register(request, body.get("token")):
            raise HTTPException(403, "Setup token required")
        cid, options = svc(request).auth.registration_options()
        return Response(json.dumps({"cid": cid, "options": json.loads(options)}), media_type="application/json")

    @app.post("/auth/register")
    async def register(request: Request):
        body = await request.json()
        s = svc(request)
        first = not s.auth.has_credentials()
        if not allowed_to_register(request, body.get("token")):
            raise HTTPException(403, "Setup token required")
        s.auth.register(body.get("cid"), body.get("credential") or {}, str(body.get("label") or "passkey"))
        s.db.audit("passkey_added", detail=str(body.get("label") or ""), ok=True, client=client_desc(request))
        response = JSONResponse({"ok": True})
        if first:
            set_session(response, s.auth.new_session(client_desc(request)))
        return response

    @app.post("/auth/login/options")
    async def login_options(request: Request):
        cid, options = svc(request).auth.authentication_options()
        return Response(json.dumps({"cid": cid, "options": json.loads(options)}), media_type="application/json")

    def set_session(response, token):
        response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_DAYS * 86400, httponly=True,
                            secure=env.secure_cookies, samesite="lax", path="/")

    @app.post("/auth/login")
    async def login(request: Request):
        body = await request.json()
        s = svc(request)
        try:
            s.auth.authenticate(body.get("cid"), body.get("credential") or {})
        except HTTPException:
            s.db.audit("login", ok=False, client=client_desc(request))
            raise
        s.db.audit("login", ok=True, client=client_desc(request))
        response = JSONResponse({"ok": True})
        set_session(response, s.auth.new_session(client_desc(request)))
        return response

    @app.post("/logout")
    async def logout(request: Request):
        svc(request).auth.end_session(request.cookies.get(SESSION_COOKIE))
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    # --- data helpers -------------------------------------------------------
    def node_view(s: Services, row) -> dict:
        key = row["pubkey"]
        seen = s.monitor.directory.get(key)
        live = s.monitor.live.get(key)
        state = s.db.one("SELECT * FROM node_state WHERE pubkey=?", (key,))
        status = json.loads(state["status"]) if state and state["status"] else {}
        telemetry = json.loads(state["telemetry"]) if state and state["telemetry"] else None
        alerts = [dict(a) for a in s.db.q("SELECT rule,message,started FROM alerts WHERE pubkey=? AND resolved IS NULL",
                                          (key,))]
        recent = s.db.one("SELECT COUNT(DISTINCT observer) AS obs, SUM(snr*n)/SUM(n) AS snr, MAX(snr) AS best"
                          " FROM observations WHERE pubkey=? AND direct=1 AND ts>?", (key, time.time() - 86400))
        cfg = config.get(s.db, "alerts")
        return {
            "pubkey": key, "label": row["label"] or (seen.name if seen and seen.name else key[:8]),
            "name": seen.name if seen else None, "node_type": seen.node_type if seen else "unknown",
            "lat": seen.lat if seen else None, "lon": seen.lon if seen else None,
            "last_heard": live.last_heard if live else None, "last_heard_via": live.last_heard_via if live else None,
            "last_advert": live.last_advert if live else None,
            "status": status, "status_at": state["status_at"] if state else None, "telemetry": telemetry,
            "last_poll_at": state["last_poll_at"] if state else None,
            "last_poll_ok": state["last_poll_ok"] if state else None,
            "poll_fails": state["poll_fails"] if state else 0, "last_error": state["last_error"] if state else None,
            "next_poll_at": state["next_poll_at"] if state else None,
            "login_role": state["login_role"] if state else None,
            "radio_id": row["radio_id"], "poll_radio": state["poll_radio"] if state else None,
            "auto_radio": auto_radio(s, row),
            "has_admin": bool(row["admin_pw"]), "has_guest": bool(row["guest_pw"]),
            "poll_enabled": bool(row["poll_enabled"]), "poll_interval_min": row["poll_interval_min"],
            "alerts_enabled": bool(row["alerts_enabled"]), "silent_min": row["silent_min"],
            "silent_effective_min": s.alerts.silent_threshold_min(row, cfg),
            "battery_mv": row["battery_mv"], "snr_drop_db": row["snr_drop_db"], "notes": row["notes"],
            "alerts": alerts, "observers_24h": recent["obs"] or 0,
            "snr_24h": round(recent["snr"], 1) if recent["snr"] is not None else None,
            "best_snr_24h": recent["best"], "added_at": row["added_at"],
            "firmware": state["firmware"] if state else None,
            "fw_newer": fmt_v(firmware.outdated(s.db, seen.node_type if seen else None,
                                                state["firmware"] if state else None)),
            "config": json.loads(state["config"]) if state and state["config"] else {},
            "config_at": state["config_at"] if state else None,
            "problem": bool(alerts) or (bool(row["poll_enabled"]) and (state["poll_fails"] if state else 0) >= 2),
        }

    def fmt_v(v):
        return firmware.fmt_version(v) if v else None

    def auto_radio(s: Services, row) -> str | None:
        """Name of the companion Automatic would use now (None when pinned or none is connected)."""
        if row["radio_id"]:
            return None
        try:
            return s.radios.choose(row["pubkey"], None, s.monitor, s.db).name
        except RadioError:
            return None

    def watched_row(s: Services, key: str):
        row = s.db.one("SELECT * FROM watched WHERE pubkey=?", (key,))
        if not row:
            raise HTTPException(404, "Node is not on your watchlist")
        return row

    def all_nodes(s: Services) -> list[dict]:
        nodes = [node_view(s, r) for r in s.db.q("SELECT * FROM watched")]
        return sorted(nodes, key=lambda n: (not n["alerts"], not n["problem"], n["label"].lower()))

    def with_sparks(s: Services, nodes: list[dict]) -> list[dict]:
        """Adds 24 h sparklines (SNR heard by observers, battery) for the dashboard cards."""
        span = history.RANGES["24h"]
        for n in nodes:
            n["spark_snr"] = history.sparkline(history.series(s.db, n["pubkey"], "snr", "24h"), span)
            n["spark_bat"] = history.sparkline(history.series(s.db, n["pubkey"], "bat", "24h"), span)
        return nodes

    def system_status(s: Services) -> dict:
        return {
            "radio": {"state": s.radios.state, "error": s.radios.error},
            "radios": [r.view() for r in s.radios],
            "mqtt": [{"name": src.cfg.get("name"), "state": src.state, "error": src.error,
                      "messages": src.messages, "last_message": src.last_message}
                     for src in s.sources.sources.values()],
            "monitor": dict(s.monitor.stats, directory=len(s.monitor.directory)),
            "poller": {"budget_left": s.poller.budgets(config.get(s.db, "polling")),
                       "current": dict(s.poller.current)},
        }

    # --- pages ----------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        s = svc(request)
        system_alerts = s.db.q("SELECT * FROM alerts WHERE pubkey='' AND resolved IS NULL")
        return page(request, "dashboard.html", nodes=with_sparks(s, all_nodes(s)), system=system_status(s),
                    system_alerts=system_alerts, radio_names=radio_names(s))

    @app.get("/partials/nodes", response_class=HTMLResponse)
    async def nodes_partial(request: Request):
        s = svc(request)
        return templates.TemplateResponse(request, "_nodes.html", {"nodes": with_sparks(s, all_nodes(s)),
                                                                   "radio_names": radio_names(s)})

    def radio_names(s: Services) -> dict[str, str]:
        return {r["id"]: r.get("name") or r["id"] for r in config.radios(s.db)}

    @app.get("/add", response_class=HTMLResponse)
    async def add_page(request: Request, q: str = ""):
        s = svc(request)
        return page(request, "add.html", q=q, results=s.monitor.search(q), watched=s.monitor.watched)

    @app.get("/partials/search", response_class=HTMLResponse)
    async def search_partial(request: Request, q: str = ""):
        s = svc(request)
        return templates.TemplateResponse(request, "_search.html",
                                          {"results": s.monitor.search(q), "watched": s.monitor.watched})

    @app.post("/nodes")
    async def add_node(request: Request, pubkey: str = Form(...), label: str = Form(""),
                       admin_pw: str = Form(""), guest_pw: str = Form("")):
        s = svc(request)
        key = pubkey.strip().lower()
        if not PUBKEY.match(key):
            raise HTTPException(400, "Public key must be 64 hex characters")
        poll = 1 if (admin_pw or guest_pw) else 0
        s.db.x("INSERT INTO watched(pubkey,label,added_at,admin_pw,guest_pw,poll_enabled) VALUES(?,?,?,?,?,?)"
               " ON CONFLICT(pubkey) DO NOTHING",
               (key, label.strip()[:40] or None, time.time(), s.box.seal(admin_pw), s.box.seal(guest_pw), poll))
        s.db.audit("watch_add", key, label or None, True, client=client_desc(request))
        s.monitor.reload_watched()
        s.poller.kick()
        return RedirectResponse(f"/nodes/{key}", status_code=303)

    @app.post("/nodes/bulk")
    async def add_nodes(request: Request):
        """Watch several nodes picked from search at once, optionally with shared passwords."""
        s = svc(request)
        form = await request.form()
        keys = sorted({str(k).strip().lower() for k in form.getlist("pubkey")})
        if not keys or any(not PUBKEY.match(k) for k in keys):
            raise HTTPException(400, "Pick at least one node")
        if len(keys) > 100:
            raise HTTPException(400, "At most 100 nodes at once")
        admin_pw, guest_pw = str(form.get("admin_pw") or ""), str(form.get("guest_pw") or "")
        poll = 1 if (admin_pw or guest_pw) else 0
        added = 0
        for key in keys:
            cur = s.db.x("INSERT INTO watched(pubkey,added_at,admin_pw,guest_pw,poll_enabled) VALUES(?,?,?,?,?)"
                         " ON CONFLICT(pubkey) DO NOTHING",
                         (key, time.time(), s.box.seal(admin_pw), s.box.seal(guest_pw), poll))
            if cur.rowcount:
                added += 1
                s.db.audit("watch_add", key, "bulk", True, client=client_desc(request))
        s.monitor.reload_watched()
        s.poller.kick()
        return RedirectResponse("/", status_code=303)

    @app.get("/nodes/{key}", response_class=HTMLResponse)
    async def node_page(request: Request, key: str, range: str = "24h"):
        s = svc(request)
        row = watched_row(s, key)
        if range not in history.RANGES:
            range = "24h"
        span = history.RANGES[range]
        charts = []
        for metric, (title, unit) in history.METRICS.items():
            pts = history.series(s.db, key, metric, range)
            charts.append({"title": title, "unit": unit, "svg": history.svg_chart(pts, span, unit),
                           "latest": pts[-1][1] if pts else None})
        observers = s.db.q(
            "SELECT observer, MAX(region) AS region, SUM(n) AS n, SUM(snr*n)/SUM(n) AS snr,"
            " SUM(rssi*n)/SUM(n) AS rssi, MAX(ts) AS last FROM observations"
            " WHERE pubkey=? AND direct=1 AND ts>? GROUP BY observer ORDER BY last DESC LIMIT 40",
            (key, time.time() - 7 * 86400))
        # MQTT observer ids are often upper-case hex; the advert directory is lower-case.
        observer_names = {o["observer"]: (s.monitor.directory[o["observer"].lower()].name
                                          if o["observer"].lower() in s.monitor.directory else None)
                          for o in observers}
        paths = s.db.q("SELECT ts, kind, observer, hops, path, snr FROM observations WHERE pubkey=?"
                       " ORDER BY ts DESC LIMIT 25", (key,))
        alert_log = s.db.q("SELECT * FROM alerts WHERE pubkey=? ORDER BY started DESC LIMIT 20", (key,))
        for r in s.radios:
            if r.public_key:
                observer_names[r.public_key] = f"meshwatch companion ({r.name})"
        return page(request, "node.html", n=node_view(s, row), charts=charts, range=range, radios=list(s.radios),
                    ranges=list(history.RANGES), observers=observers, observer_names=observer_names,
                    paths=paths, alert_log=alert_log)

    @app.post("/nodes/{key}/settings")
    async def node_settings(request: Request, key: str):
        s = svc(request)
        watched_row(s, key)
        form = await request.form()

        def num(name, lo, hi, cast=int, allow_empty=False):
            raw = str(form.get(name, "")).strip()
            if raw == "" and allow_empty:
                return None
            try:
                value = cast(raw)
            except ValueError:
                raise HTTPException(400, f"{name}: not a number") from None
            if not lo <= value <= hi:
                raise HTTPException(400, f"{name}: must be between {lo} and {hi}")
            return value

        updates = {
            "label": str(form.get("label", "")).strip()[:40] or None,
            "poll_enabled": 1 if form.get("poll_enabled") else 0,
            "poll_interval_min": num("poll_interval_min", 5, 1440),
            "alerts_enabled": 1 if form.get("alerts_enabled") else 0,
            "silent_min": num("silent_min", 5, 100000, allow_empty=True),
            "battery_mv": num("battery_mv", 0, 20000),
            "snr_drop_db": num("snr_drop_db", 1, 40, float),
            "notes": str(form.get("notes", ""))[:2000],
        }
        if "radio_id" in form:
            rid = str(form.get("radio_id") or "").strip() or None
            if rid and s.radios.get(rid) is None:
                raise HTTPException(400, "Unknown radio")
            updates["radio_id"] = rid
        for field in ("admin_pw", "guest_pw"):
            if form.get(f"clear_{field}"):
                updates[field] = None
            elif form.get(field):
                updates[field] = s.box.seal(str(form.get(field)))
        sets = ", ".join(f"{k}=?" for k in updates)
        s.db.x(f"UPDATE watched SET {sets} WHERE pubkey=?", (*updates.values(), key))
        if "admin_pw" in updates or "guest_pw" in updates or "radio_id" in updates:
            s.db.x("UPDATE node_state SET last_login_at=NULL, next_poll_at=NULL WHERE pubkey=?", (key,))
        changed = sorted(k for k in updates if k not in ("notes",))
        s.db.audit("watch_settings", key, ", ".join(changed), True, client=client_desc(request))
        s.poller.kick()
        return RedirectResponse(f"/nodes/{key}", status_code=303)

    @app.post("/nodes/{key}/delete")
    async def node_delete(request: Request, key: str):
        s = svc(request)
        watched_row(s, key)
        with s.db.conn:
            for table in ("watched", "node_state", "observations", "status_samples", "telemetry_samples",
                          "rollups"):
                s.db.conn.execute(f"DELETE FROM {table} WHERE pubkey=?", (key,))
            s.db.conn.execute("UPDATE alerts SET resolved=? WHERE pubkey=? AND resolved IS NULL", (time.time(), key))
        s.db.audit("watch_remove", key, None, True, client=client_desc(request))
        s.monitor.reload_watched()
        return RedirectResponse("/", status_code=303)

    @app.post("/nodes/{key}/poll")
    async def node_poll(request: Request, key: str):
        s = svc(request)
        row = watched_row(s, key)
        try:
            radio = s.poller.choose(row)
        except RadioError as exc:
            raise HTTPException(503, str(exc)) from None
        if not s.poller.budget_left(config.get(s.db, "polling"), radio.id) > 0:
            raise HTTPException(429, f"Hourly polling budget used up on {radio.name}")
        result = await s.poller.poll(row, radio=radio)
        s.db.audit("poll", key, None, result["ok"], result.get("error"), client_desc(request))
        if request.headers.get("hx-request") or request.headers.get("accept", "").startswith("application/json"):
            return JSONResponse({"ok": result["ok"], "error": result.get("error")})
        return RedirectResponse(f"/nodes/{key}", status_code=303)

    @app.get("/nodes/{key}/console", response_class=HTMLResponse)
    async def console_page(request: Request, key: str):
        s = svc(request)
        row = watched_row(s, key)
        log_rows = s.db.q("SELECT * FROM audit WHERE pubkey=? AND action='cli' ORDER BY ts DESC LIMIT 50", (key,))
        return page(request, "console.html", n=node_view(s, row), log=list(reversed(log_rows)))

    @app.post("/nodes/{key}/inventory")
    async def node_inventory(request: Request, key: str):
        """Poll now and read firmware + settings (admin password needed)."""
        s = svc(request)
        row = watched_row(s, key)
        if not row["admin_pw"]:
            raise HTTPException(400, "Reading settings needs the node's admin password")
        try:
            radio = s.poller.choose(row)
        except RadioError as exc:
            raise HTTPException(503, str(exc)) from None
        result = await s.poller.poll(row, radio=radio, inventory=True)
        s.db.audit("inventory", key, None, result["ok"], result.get("error"), client_desc(request))
        if request.headers.get("hx-request") or request.headers.get("accept", "").startswith("application/json"):
            return JSONResponse({"ok": result["ok"], "error": result.get("error"),
                                 "values": result.get("inventory")})
        return RedirectResponse(f"/nodes/{key}", status_code=303)

    @app.get("/map", response_class=HTMLResponse)
    async def map_page(request: Request):
        s = svc(request)
        return page(request, "map.html", tiles=config.get(s.db, "general").get("map_tiles") or "")

    def located(seen) -> tuple[float, float] | None:
        if seen and seen.lat is not None and seen.lon is not None and (abs(seen.lat) > 0.01 or abs(seen.lon) > 0.01):
            return seen.lat, seen.lon
        return None

    @app.get("/api/v1/map")
    async def api_map(request: Request, days: int = 7):
        """Watched nodes with positions, and the observers that heard each one directly."""
        s = svc(request)
        days = max(1, min(days, 30))
        companions = {r.public_key: r.name for r in s.radios if r.public_key}
        nodes, links, observers = [], [], {}
        for n in all_nodes(s):
            pos = located(s.monitor.directory.get(n["pubkey"]))
            nodes.append({"pubkey": n["pubkey"], "label": n["label"], "pos": pos,
                          "state": "alert" if n["alerts"] else ("problem" if n["problem"] else
                                                                ("ok" if n["last_heard"] else "waiting")),
                          "alerts": [a["message"] for a in n["alerts"]], "last_heard": n["last_heard"],
                          "bat": n["status"].get("bat"), "snr_24h": n["snr_24h"], "observers_24h": n["observers_24h"]})
            for o in s.db.q("SELECT observer, SUM(n) AS n, SUM(snr*n)/SUM(n) AS snr, MAX(ts) AS last"
                            " FROM observations WHERE pubkey=? AND direct=1 AND ts>? GROUP BY observer",
                            (n["pubkey"], time.time() - days * 86400)):
                okey = o["observer"].lower()
                seen = s.monitor.directory.get(okey)
                opos = located(seen)
                if opos is None:
                    continue
                observers[o["observer"]] = {"pubkey": o["observer"], "pos": opos,
                                            "name": companions.get(okey) or (seen.name if seen else None)}
                links.append({"node": n["pubkey"], "observer": o["observer"], "n": o["n"],
                              "snr": round(o["snr"], 1) if o["snr"] is not None else None, "last": o["last"]})
        return {"nodes": nodes, "observers": list(observers.values()), "links": links, "days": days}

    @app.get("/fleet", response_class=HTMLResponse)
    async def fleet_page(request: Request):
        s = svc(request)
        latest = s.db.get_setting("fw_latest") or {}
        return page(request, "fleet.html", groups=firmware.fleet(s.db, s.monitor, radio_names(s)),
                    settings_keys=firmware.SETTINGS, latest=latest,
                    check_releases=config.get(s.db, "general").get("check_releases"))

    @app.post("/fleet/releases")
    async def fleet_releases(request: Request):
        s = svc(request)
        if await firmware.fetch_latest(s.db) is None:
            raise HTTPException(502, "Could not read MeshCore releases from GitHub")
        return RedirectResponse("/fleet", status_code=303)

    @app.get("/console", response_class=HTMLResponse)
    async def multi_console_page(request: Request):
        s = svc(request)
        nodes = [n for n in all_nodes(s) if n["has_admin"]]
        names = radio_names(s)
        for n in nodes:
            n["network"] = names.get(n["radio_id"] or "") or n["auto_radio"] or names.get(n["poll_radio"] or "") or "?"
        nodes.sort(key=lambda n: (n["network"], n["label"].lower()))
        log_rows = s.db.q("SELECT * FROM audit WHERE action='cli' ORDER BY ts DESC LIMIT 40")
        labels = {r["pubkey"]: node_label(s.db, s.monitor, r["pubkey"]) for r in log_rows if r["pubkey"]}
        return page(request, "multi_console.html", nodes=nodes, log=list(reversed(log_rows)), labels=labels)

    @app.get("/api/v1/snippets")
    async def api_snippets(request: Request):
        s = svc(request)
        return {"snippets": [{"id": r["id"], "name": r["name"], "commands": r["commands"].split("\n")}
                             for r in s.db.q("SELECT * FROM cli_snippets ORDER BY name")]}

    @app.post("/api/v1/snippets")
    async def api_snippet_save(request: Request):
        s = svc(request)
        body = await request.json()
        name = " ".join(str(body.get("name", "")).split())[:60]
        commands = [" ".join(str(c).split())[:160] for c in body.get("commands") or [] if str(c).strip()]
        if not name or not commands:
            raise HTTPException(400, "A snippet needs a name and at least one command")
        if len(commands) > 20:
            raise HTTPException(400, "At most 20 commands per snippet")
        if any(cli.secret_value(c) for c in commands):
            raise HTTPException(400, "Snippets cannot contain passwords or secrets")
        sid = body.get("id")
        if sid:
            s.db.x("UPDATE cli_snippets SET name=?, commands=? WHERE id=?", (name, "\n".join(commands), int(sid)))
        else:
            sid = s.db.x("INSERT INTO cli_snippets(name,commands,created) VALUES(?,?,?)",
                         (name, "\n".join(commands), time.time())).lastrowid
        s.db.audit("snippet_saved", None, name, True, client=client_desc(request))
        return {"ok": True, "id": sid}

    @app.post("/api/v1/snippets/{sid}/delete")
    async def api_snippet_delete(request: Request, sid: int):
        s = svc(request)
        s.db.x("DELETE FROM cli_snippets WHERE id=?", (sid,))
        s.db.audit("snippet_removed", None, str(sid), True, client=client_desc(request))
        return {"ok": True}

    @app.get("/alerts", response_class=HTMLResponse)
    async def alerts_page(request: Request):
        s = svc(request)
        rows = s.db.q("SELECT * FROM alerts ORDER BY resolved IS NOT NULL, started DESC LIMIT 200")
        labels = {r["pubkey"]: node_label(s.db, s.monitor, r["pubkey"]) if r["pubkey"] else "meshwatch"
                  for r in rows}
        return page(request, "alerts.html", rows=rows, labels=labels)

    @app.get("/audit", response_class=HTMLResponse)
    async def audit_page(request: Request):
        s = svc(request)
        rows = s.db.q("SELECT * FROM audit ORDER BY ts DESC LIMIT 300")
        labels = {r["pubkey"]: node_label(s.db, s.monitor, r["pubkey"]) for r in rows if r["pubkey"]}
        return page(request, "audit.html", rows=rows, labels=labels)

    # --- settings -------------------------------------------------------------
    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request, new_token: str = ""):
        s = svc(request)
        response = page(request, "settings.html",
                    mqtt=config.get(s.db, "mqtt_sources"), radios_cfg=config.radios(s.db),
                    ntfy=config.get(s.db, "ntfy"), polling=config.get(s.db, "polling"),
                    general=config.get(s.db, "general"),
                    alerts_cfg=config.get(s.db, "alerts"), system=system_status(s),
                    passkeys=s.db.q("SELECT * FROM credentials ORDER BY created"),
                    tokens=s.db.q("SELECT * FROM api_tokens ORDER BY created"),
                    new_token=request.cookies.get("mw_new_token", ""), default_topics=", ".join(DEFAULT_TOPICS))
        response.delete_cookie("mw_new_token", path="/settings")
        return response

    def back(anchor: str):
        return RedirectResponse(f"/settings#{anchor}", status_code=303)

    @app.post("/settings/mqtt")
    async def settings_mqtt(request: Request):
        s = svc(request)
        form = await request.form()
        sources = config.get(s.db, "mqtt_sources")
        action, sid = form.get("action"), form.get("id")
        if action == "delete":
            sources = [x for x in sources if x["id"] != sid]
        else:
            url = str(form.get("url", "")).strip()
            if not re.match(r"^(mqtts?|wss?)://[^\s/]+", url):
                raise HTTPException(400, "URL must start with mqtt://, mqtts://, ws:// or wss://")
            topics = [t.strip() for t in str(form.get("topics", "")).split(",") if t.strip()] or DEFAULT_TOPICS
            entry = next((x for x in sources if x["id"] == sid), None)
            if entry is None:
                entry = {"id": uuid.uuid4().hex[:8]}
                sources.append(entry)
            entry.update(name=str(form.get("name", "")).strip()[:40] or url, url=url,
                         username=str(form.get("username", "")).strip(), topics=topics,
                         enabled=bool(form.get("enabled")))
            if form.get("password"):
                entry["password_enc"] = s.box.seal(str(form.get("password")))
            elif form.get("clear_password"):
                entry["password_enc"] = None
        s.db.set_setting("mqtt_sources", sources)
        s.db.audit("settings_mqtt", None, f"{action or 'save'} {sid or ''}".strip(), True, client=client_desc(request))
        await s.sources.apply(sources)
        return back("mqtt")

    @app.post("/settings/radio")
    async def settings_radio(request: Request):
        s = svc(request)
        form = await request.form()
        radios = config.radios(s.db)
        action, rid = form.get("action"), form.get("id")
        if action == "delete":
            radios = [r for r in radios if r["id"] != rid]
            s.db.x("UPDATE watched SET radio_id=NULL WHERE radio_id=?", (rid,))
            detail = f"delete {rid}"
        else:
            kind = str(form.get("kind", "none"))
            if kind not in ("none", "tcp", "serial"):
                raise HTTPException(400, "Unknown connection type")
            try:
                port, baud = int(form.get("port") or 5000), int(form.get("baud") or 115200)
            except ValueError:
                raise HTTPException(400, "Port and baud must be numbers") from None
            if not 1 <= port <= 65535:
                raise HTTPException(400, "Port must be between 1 and 65535")
            regions = [x.strip().upper() for x in str(form.get("regions", "")).split(",") if x.strip()]
            if any(not re.match(r"^[A-Z0-9_.|-]{1,32}$", x) for x in regions):
                raise HTTPException(400, "Regions: letters, digits, '.', '-', '_' and '|' only")
            entry = next((r for r in radios if r["id"] == rid), None)
            if entry is None:
                used = {r["id"] for r in radios}
                entry = {"id": next(f"r{i}" for i in range(1, 100) if f"r{i}" not in used)}
                radios.append(entry)
            entry.update(name=str(form.get("name", "")).strip()[:40] or f"Radio {entry['id'][1:]}", kind=kind,
                         host=str(form.get("host", "")).strip(), port=port,
                         serial_port=str(form.get("serial_port", "")).strip(), baud=baud, regions=regions)
            detail = f"{entry['id']} {entry['name']}: {kind} {entry['host'] or entry['serial_port']}:{port}"
        s.db.set_setting("radios", radios)
        s.db.audit("settings_radio", None, detail, True, client=client_desc(request))
        s.radios.apply(radios)
        return back("radio")

    @app.post("/settings/ntfy")
    async def settings_ntfy(request: Request):
        s = svc(request)
        form = await request.form()
        cfg = config.get(s.db, "ntfy")
        server = str(form.get("server", "")).strip().rstrip("/") or "https://ntfy.sh"
        if not re.match(r"^https?://", server):
            raise HTTPException(400, "Server must be an http(s) URL")
        topic = str(form.get("topic", "")).strip()
        if topic and not re.match(r"^[A-Za-z0-9_-]{1,64}$", topic):
            raise HTTPException(400, "Topic may contain letters, digits, - and _ only")
        summary_time = str(form.get("summary_time") or "08:00").strip()
        if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", summary_time):
            raise HTTPException(400, "Summary time must be HH:MM (24 h)")
        cfg.update(server=server, topic=topic, enabled=bool(form.get("enabled")),
                   summary_enabled=bool(form.get("summary_enabled")), summary_time=summary_time)
        if form.get("token"):
            cfg["token_enc"] = s.box.seal(str(form.get("token")))
        elif form.get("clear_token"):
            cfg["token_enc"] = None
        s.db.set_setting("ntfy", cfg)
        s.db.audit("settings_ntfy", None, f"{server} enabled={cfg['enabled']}", True, client=client_desc(request))
        if form.get("action") == "test":
            err = await s.notifier.send("meshwatch test", "Notifications are working.", 3, "test_tube")
            s.db.audit("ntfy_test", None, None, err is None, err, client_desc(request))
            if err:
                raise HTTPException(502, err)
        elif form.get("action") == "summary":
            title, body, all_ok = s.alerts.summary(time.time())
            err = await s.notifier.send(title, body, 2 if all_ok else 3, "clipboard", "/",
                                        [("Open meshwatch", "/"), ("Fleet", "/fleet")])
            if err:
                raise HTTPException(502, err)
        return back("ntfy")

    @app.post("/settings/general")
    async def settings_general(request: Request):
        s = svc(request)
        form = await request.form()
        cfg = config.get(s.db, "general")
        name = str(form.get("timezone") or "UTC").strip()
        try:
            from zoneinfo import ZoneInfo
            ZoneInfo(name)
        except Exception:  # noqa: BLE001 - any invalid name
            raise HTTPException(400, f"Unknown timezone {name!r} (use a name like America/Los_Angeles)") from None
        tiles = str(form.get("map_tiles") or "").strip()
        if tiles and not (tiles.startswith("https://") and "{z}" in tiles and "{x}" in tiles and "{y}" in tiles):
            raise HTTPException(400, "Map tiles must be an https URL with {z}, {x} and {y}")
        cfg.update(timezone=name, map_tiles=tiles or config.DEFAULTS["general"]["map_tiles"],
                   check_releases=bool(form.get("check_releases")))
        s.db.set_setting("general", cfg)
        s.db.audit("settings_general", None, json.dumps(cfg)[:300], True, client=client_desc(request))
        return back("general")

    @app.post("/settings/polling")
    async def settings_polling(request: Request):
        s = svc(request)
        form = await request.form()
        polling, alerts_cfg = config.get(s.db, "polling"), config.get(s.db, "alerts")
        try:
            polling.update(budget_per_hour=max(1, min(600, int(form["budget_per_hour"]))),
                           min_gap_s=max(5, min(600, int(form["min_gap_s"]))))
            alerts_cfg.update(passive_silent_min=max(10, int(form["passive_silent_min"])),
                              polled_silent_min=max(10, int(form["polled_silent_min"])))
        except (KeyError, ValueError):
            raise HTTPException(400, "Numbers required") from None
        s.db.set_setting("polling", polling)
        s.db.set_setting("alerts", alerts_cfg)
        s.db.audit("settings_polling", None, json.dumps({**polling, **alerts_cfg})[:500], True,
                   client=client_desc(request))
        return back("polling")

    @app.post("/settings/tokens")
    async def settings_tokens(request: Request, label: str = Form("iPhone")):
        s = svc(request)
        token = s.auth.new_api_token(label)
        s.db.audit("api_token_added", None, label, True, client=client_desc(request))
        response = back("tokens")
        # Shown once on the next page view, then gone.
        response.set_cookie("mw_new_token", token, max_age=60, httponly=True, secure=env.secure_cookies,
                            samesite="strict", path="/settings")
        return response

    @app.post("/settings/tokens/{tid}/delete")
    async def token_delete(request: Request, tid: int):
        s = svc(request)
        s.db.x("DELETE FROM api_tokens WHERE id=?", (tid,))
        s.db.audit("api_token_removed", None, str(tid), True, client=client_desc(request))
        return back("tokens")

    @app.post("/settings/passkeys/{pid}/delete")
    async def passkey_delete(request: Request, pid: str):
        s = svc(request)
        if s.db.one("SELECT COUNT(*) AS c FROM credentials")["c"] <= 1:
            raise HTTPException(400, "Cannot remove the last passkey")
        s.db.x("DELETE FROM credentials WHERE id=?", (pid,))
        s.db.audit("passkey_removed", None, pid[:16], True, client=client_desc(request))
        return back("passkeys")

    # --- JSON API (web UI + future iPhone app) --------------------------------------
    @app.get("/api/v1/status")
    async def api_status(request: Request):
        s = svc(request)
        return {"version": __version__, **system_status(s),
                "alerts": [dict(a) for a in s.db.q("SELECT * FROM alerts WHERE resolved IS NULL")]}

    @app.get("/api/v1/nodes")
    async def api_nodes(request: Request):
        return {"nodes": all_nodes(svc(request))}

    @app.get("/api/v1/nodes/{key}")
    async def api_node(request: Request, key: str):
        s = svc(request)
        return node_view(s, watched_row(s, key))

    @app.get("/api/v1/nodes/{key}/history")
    async def api_history(request: Request, key: str, metric: str = "snr", range: str = "24h"):
        s = svc(request)
        watched_row(s, key)
        try:
            pts = history.series(s.db, key, metric, range)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        return {"metric": metric, "range": range, "unit": history.METRICS[metric][1], "points": pts}

    @app.get("/api/v1/alerts")
    async def api_alerts(request: Request, open_only: bool = False):
        s = svc(request)
        sql = "SELECT * FROM alerts" + (" WHERE resolved IS NULL" if open_only else "") + " ORDER BY started DESC LIMIT 200"
        return {"alerts": [dict(a) for a in s.db.q(sql)]}

    @app.get("/api/v1/search")
    async def api_search(request: Request, q: str = ""):
        s = svc(request)
        return {"nodes": [{"pubkey": n.pubkey, "name": n.name, "type": n.node_type, "last_seen": n.last_seen,
                           "watched": n.pubkey in s.monitor.watched} for n in s.monitor.search(q)]}

    @app.post("/api/v1/nodes/{key}/poll")
    async def api_poll(request: Request, key: str):
        return await node_poll(request, key)

    @app.get("/api/v1/cli/catalog")
    async def api_catalog(request: Request, node: str = ""):
        s = svc(request)
        seen = s.monitor.directory.get(node)
        hist = [r["command"] for r in s.db.q("SELECT command FROM cli_history ORDER BY ts DESC LIMIT 200")]
        return {"source": cli.catalog().get("source"), "commands": cli.commands_for(seen.node_type if seen else None),
                "history": hist}

    @app.post("/api/v1/nodes/{key}/cli")
    async def api_cli(request: Request, key: str):
        s = svc(request)
        row = watched_row(s, key)
        body = await request.json()
        command = " ".join(str(body.get("command", "")).split())[:160]
        if not command:
            raise HTTPException(400, "Empty command")
        if cli.serial_only(command):
            raise HTTPException(400, "This command only works over the node's USB serial port, not remotely")
        if cli.needs_confirm(command) and not body.get("confirm"):
            return JSONResponse({"needs_confirm": True, "command": command}, status_code=409)
        if not row["admin_pw"]:
            raise HTTPException(400, "Remote CLI needs the node's admin password (Settings on the node page)")
        settings = config.get(s.db, "polling")
        node = s.poller.node_row(key)
        started = time.time()
        secret = cli.secret_value(command)
        setting = cli.setting_key(command)
        previous = None
        try:
            radio = s.poller.choose(node)
            async with radio.lock:
                contact = await radio.contact(key, s.monitor.directory.get(key))
                role = await s.poller.ensure_login(node, radio, contact, settings)
                if role != "admin":
                    raise RadioError("logged in without admin rights; check the admin password")
                if setting and body.get("previous", True):
                    # Read the current value first so the console and audit log show what changed.
                    s.poller._spend(radio.id)
                    with contextlib.suppress(RadioError):
                        previous = firmware.clean_reply(
                            await radio.cli(contact, f"get {setting}", settings["request_timeout_s"]))
                s.poller._spend(radio.id)
                reply = await radio.cli(contact, command, settings["request_timeout_s"])
            ok, error = True, None
        except RadioError as exc:
            reply, ok, error = "", False, str(exc)
        reply = cli.redact(reply, secret)
        logged = cli.redact(command, secret)
        if previous is not None:
            logged += f"  (was {previous})"
        s.db.audit("cli", key, logged, ok, reply if ok else error, client_desc(request))
        if not secret:
            s.db.x("INSERT INTO cli_history(ts,command) VALUES(?,?)"
                   " ON CONFLICT(command) DO UPDATE SET ts=excluded.ts", (time.time(), command))
        if ok:
            s.monitor.heard_by_poll(key, time.time())
            if setting and (reply or "").strip().upper().startswith("OK"):
                remember_setting(s, key, setting, command.split(None, 2)[2])
        return {"ok": ok, "command": cli.redact(command, secret), "reply": reply, "error": error,
                "previous": previous, "elapsed_s": round(time.time() - started, 1)}

    def remember_setting(s: Services, key: str, setting: str, value: str) -> None:
        """Keep the fleet view current after a successful `set` from the console."""
        if setting not in firmware.SETTINGS:
            return
        row = s.db.one("SELECT config FROM node_state WHERE pubkey=?", (key,))
        cfg = json.loads(row["config"]) if row and row["config"] else {}
        cfg[setting] = value.strip()
        s.db.x("UPDATE node_state SET config=? WHERE pubkey=?", (json.dumps(cfg), key))

    return app
