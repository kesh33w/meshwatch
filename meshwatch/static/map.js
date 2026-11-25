"use strict";
// Map page: watched nodes and the observers that hear them directly (Leaflet, tiles from Settings).

(function () {
  const el = document.getElementById("map");
  if (!el || typeof L === "undefined") return;
  const map = L.map(el, { worldCopyJump: true });
  L.tileLayer(el.dataset.tiles, {
    maxZoom: 18,
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
  }).addTo(map);
  map.setView([38.58, -121.49], 9);
  const layer = L.layerGroup().addTo(map);
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const age = (ts) => {
    if (!ts) return "never";
    const s = Date.now() / 1000 - ts;
    return s < 3600 ? `${Math.round(s / 60)} min ago` : s < 172800 ? `${(s / 3600).toFixed(1)} h ago` : `${(s / 86400).toFixed(1)} days ago`;
  };
  const snrColor = (snr) => snr == null ? css("--muted") : snr >= 5 ? css("--ok") : snr >= -5 ? css("--warn") : css("--bad");
  const stateColor = { ok: "--ok", alert: "--bad", problem: "--warn", waiting: "--muted" };
  let fitted = false;

  async function load(days) {
    const r = await fetch(`/api/v1/map?days=${days}`, { credentials: "same-origin" });
    const d = await r.json();
    layer.clearLayers();
    const nodes = new Map(d.nodes.map((n) => [n.pubkey, n]));
    const obs = new Map(d.observers.map((o) => [o.pubkey, o]));
    const bounds = [];
    for (const l of d.links) {
      const n = nodes.get(l.node), o = obs.get(l.observer);
      if (!n || !n.pos || !o) continue;
      L.polyline([n.pos, o.pos], { color: snrColor(l.snr), weight: 2, opacity: 0.75 })
        .bindTooltip(`${esc(n.label)} → ${esc(o.name || o.pubkey.slice(0, 8))}<br>SNR ${l.snr ?? "?"} dB · ${l.n} packets · ${age(l.last)}`)
        .addTo(layer);
    }
    for (const o of obs.values()) {
      if (nodes.has(o.pubkey)) continue;
      L.circleMarker(o.pos, { radius: 4, color: css("--muted"), weight: 1, fillOpacity: 0.6 })
        .bindTooltip(`Observer ${esc(o.name || o.pubkey.slice(0, 8))}`).addTo(layer);
      bounds.push(o.pos);
    }
    const missing = [];
    for (const n of nodes.values()) {
      if (!n.pos) { missing.push(n.label); continue; }
      bounds.push(n.pos);
      const color = css(stateColor[n.state] || "--muted");
      const bat = n.bat ? `${(n.bat / 1000).toFixed(2)} V` : "—";
      L.circleMarker(n.pos, { radius: 8, color, weight: 2, fillColor: color, fillOpacity: 0.85 })
        .bindPopup(`<b><a href="/nodes/${n.pubkey}">${esc(n.label)}</a></b><br>` +
          (n.alerts.length ? `<span style="color:${css("--bad")}">${n.alerts.map(esc).join("<br>")}</span><br>` : "") +
          `Heard ${age(n.last_heard)}<br>Battery ${bat}<br>SNR 24 h ${n.snr_24h ?? "—"} dB · ${n.observers_24h} observers`)
        .addTo(layer);
    }
    if (bounds.length && !fitted) { map.fitBounds(bounds, { padding: [30, 30], maxZoom: 13 }); fitted = true; }
    document.getElementById("maplist").textContent = missing.length ? `No location: ${missing.join(", ")}` : "";
  }

  document.getElementById("mapdays").addEventListener("click", (e) => {
    const a = e.target.closest("a[data-days]");
    if (!a) return;
    e.preventDefault();
    document.querySelectorAll("#mapdays a").forEach((x) => x.classList.toggle("on", x === a));
    load(a.dataset.days);
  });
  load(7);
})();
