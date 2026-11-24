"use strict";
// meshwatch front-end: passkeys, small form helpers, CLI console with autocomplete.

const $ = (sel, root = document) => root.querySelector(sel);

// ---------- base64url <-> ArrayBuffer ----------
const b64uToBuf = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)).buffer;
};
const bufToB64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify(body || {}),
  });
  let data = {};
  try { data = await r.json(); } catch (e) { /* empty body */ }
  return { status: r.status, ok: r.ok, data };
}

const errText = (res) => (res.data && (res.data.error || res.data.detail)) || `HTTP ${res.status}`;

// ---------- passkeys ----------
async function passkeyLogin(btn) {
  const msg = $("#msg");
  msg.textContent = "";
  btn.disabled = true;
  try {
    const opt = await postJSON("/auth/login/options");
    if (!opt.ok) throw new Error(errText(opt));
    const o = opt.data.options;
    o.challenge = b64uToBuf(o.challenge);
    (o.allowCredentials || []).forEach((c) => { c.id = b64uToBuf(c.id); });
    const cred = await navigator.credentials.get({ publicKey: o });
    const res = await postJSON("/auth/login", { cid: opt.data.cid, credential: {
      id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        authenticatorData: bufToB64u(cred.response.authenticatorData),
        signature: bufToB64u(cred.response.signature),
        userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null,
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    }});
    if (!res.ok) throw new Error(errText(res));
    location.href = btn.dataset.next || "/";
  } catch (e) {
    msg.textContent = e.message || String(e);
  } finally {
    btn.disabled = false;
  }
}

async function passkeyRegister(btn) {
  const msg = $("#msg");
  msg.textContent = "";
  btn.disabled = true;
  const token = $("#token") ? $("#token").value.trim() : null;
  const label = ($("#plabel") && $("#plabel").value.trim()) || "passkey";
  try {
    const opt = await postJSON("/auth/register/options", { token });
    if (!opt.ok) throw new Error(errText(opt));
    const o = opt.data.options;
    o.challenge = b64uToBuf(o.challenge);
    o.user.id = b64uToBuf(o.user.id);
    (o.excludeCredentials || []).forEach((c) => { c.id = b64uToBuf(c.id); });
    const cred = await navigator.credentials.create({ publicKey: o });
    const res = await postJSON("/auth/register", { cid: opt.data.cid, token, label, credential: {
      id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        attestationObject: bufToB64u(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : [],
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    }});
    if (!res.ok) throw new Error(errText(res));
    location.href = btn.dataset.first ? "/" : "/settings#passkeys";
  } catch (e) {
    msg.textContent = e.message || String(e);
  } finally {
    btn.disabled = false;
  }
}

// ---------- page helpers ----------
document.addEventListener("click", (ev) => {
  const t = ev.target.closest("button, a");
  if (!t) return;
  if (t.id === "login") { ev.preventDefault(); passkeyLogin(t); }
  else if (t.id === "register") { ev.preventDefault(); passkeyRegister(t); }
  else if (t.dataset.back !== undefined && history.length > 1) { ev.preventDefault(); history.back(); }
  else if (t.dataset.pick) {
    $("#pubkey").value = t.dataset.pick;
    if (t.dataset.name && $("#label") && !$("#label").value) $("#label").value = t.dataset.name;
    $("#addform").scrollIntoView({ behavior: "smooth" });
  } else if (t.dataset.confirmClick && !confirm(t.dataset.confirmClick)) {
    ev.preventDefault();
  } else if (t.dataset.poll) {
    ev.preventDefault();
    pollNow(t);
  }
});

document.addEventListener("submit", (ev) => {
  const f = ev.target;
  if (f.dataset.confirm && !confirm(f.dataset.confirm)) ev.preventDefault();
});

async function pollNow(btn) {
  const msg = $("#pollmsg");
  btn.disabled = true;
  if (msg) msg.textContent = "Polling over the mesh…";
  const res = await postJSON(`/nodes/${btn.dataset.poll}/poll`);
  btn.disabled = false;
  if (res.ok && res.data.ok) location.reload();
  else if (msg) msg.textContent = "Poll failed: " + (res.data.error || errText(res));
}

// ---------- console ----------
function initConsole() {
  const box = $("#console");
  const input = $("#cmd");
  if (!box || !input) return;
  const node = box.dataset.node;
  const list = $("#suggest");
  const hint = $("#hint");
  let commands = [];
  let historyCmds = [];
  let items = [];
  let sel = -1;
  let histPos = -1;
  box.scrollTop = box.scrollHeight;

  fetch(`/api/v1/cli/catalog?node=${node}`, { credentials: "same-origin" })
    .then((r) => r.json()).then((d) => {
      commands = (d.commands || []).sort((a, b) => a.cmd.localeCompare(b.cmd));
      historyCmds = d.history || [];
    });

  const norm = (s) => s.replace(/\s+/g, " ").replace(/^ /, "").toLowerCase();

  function entryFor(text) {
    let best = null;
    for (const c of commands) {
      if ((text === c.cmd || text.startsWith(c.cmd + " ")) && (!best || c.cmd.length > best.cmd.length)) best = c;
    }
    return best;
  }

  function compute() {
    const text = norm(input.value);
    const out = [];
    const seen = new Set();
    const entry = entryFor(text);
    if (entry && entry.values && text.startsWith(entry.cmd + " ")) {
      const part = text.slice(entry.cmd.length + 1);
      for (const v of entry.values) {
        if (v.toLowerCase().startsWith(part) && v.toLowerCase() !== part) {
          out.push({ value: `${entry.cmd} ${v}`, label: `${entry.cmd} ${v}`, args: "", desc: "value", entry });
        }
      }
    }
    if (text) {
      for (const h of historyCmds) {
        if (h.toLowerCase().startsWith(text) && h.toLowerCase() !== text && !seen.has(h)) {
          seen.add(h);
          out.push({ value: h, label: h, args: "", desc: "history", entry: entryFor(h.toLowerCase()), history: true });
          if (out.length >= 4) break;
        }
      }
    }
    for (const c of commands) {
      if (out.length >= 14) break;
      if (c.cmd.startsWith(text) && c.cmd !== text && !seen.has(c.cmd)) {
        seen.add(c.cmd);
        out.push({ value: c.cmd + (c.args ? " " : ""), label: c.cmd, args: c.args || "", desc: c.desc || "", entry: c });
      }
    }
    return { out, entry };
  }

  function render() {
    const { out, entry } = compute();
    items = out;
    if (sel >= items.length) sel = items.length - 1;
    list.innerHTML = "";
    items.forEach((it, i) => {
      const row = document.createElement("div");
      row.className = i === sel ? "on" : "";
      row.setAttribute("role", "option");
      const c = document.createElement("span"); c.className = "c"; c.textContent = it.label;
      const a = document.createElement("span"); a.className = "a"; a.textContent = it.args;
      const d = document.createElement("span"); d.className = "d"; d.textContent = it.desc;
      row.append(c, a);
      if (it.entry && it.entry.confirm) { const h = document.createElement("span"); h.className = "h"; h.textContent = "⚠ changes node"; row.append(h); }
      row.append(d);
      row.addEventListener("mousedown", (e) => { e.preventDefault(); accept(i); });
      list.append(row);
    });
    list.hidden = items.length === 0 || !input.value.trim() && document.activeElement !== input;
    if (entry) {
      let h = `${entry.cmd}${entry.args ? " " + entry.args : ""} — ${entry.desc || ""}`;
      if (entry.values) h += `  [${entry.values.join(" | ")}]`;
      if (entry.confirm) h += "  ⚠ asks for confirmation";
      if (entry.serial_only) h += "  ✕ USB serial only, not available remotely";
      if (entry.min_fw) h += `  (firmware ≥ ${entry.min_fw})`;
      hint.textContent = h;
    } else {
      hint.textContent = "";
    }
  }

  function accept(i) {
    const it = items[i];
    if (!it) return;
    input.value = it.value;
    sel = -1;
    render();
    input.focus();
  }

  function commonPrefix() {
    if (!items.length) return null;
    let p = items[0].value;
    for (const it of items) { while (!it.value.startsWith(p)) p = p.slice(0, -1); }
    return p;
  }

  function line(cls, text) {
    const d = document.createElement("div");
    d.className = cls;
    d.textContent = text;
    box.append(d);
    box.scrollTop = box.scrollHeight;
    return d;
  }

  async function send(command, confirmed) {
    input.disabled = true;
    if (!confirmed) line("cmd", "> " + command);
    const pending = line("meta", "sending over the mesh…");
    try {
      const res = await postJSON(`/api/v1/nodes/${node}/cli`, { command, confirm: !!confirmed });
      pending.remove();
      if (res.status === 409 && res.data.needs_confirm) {
        if (confirm(`“${command}” changes the node (it may reboot, change radio settings or cut it off). Send it?`)) {
          return send(command, true);
        }
        line("err", "cancelled");
      } else if (!res.ok) {
        line("err", errText(res));
      } else if (res.data.ok) {
        line("reply", res.data.reply || "(empty reply)");
        line("meta", `${res.data.elapsed_s}s`);
      } else {
        line("err", res.data.error || "failed");
      }
      if (!historyCmds.includes(command)) historyCmds.unshift(command);
    } catch (e) {
      pending.remove();
      line("err", e.message || String(e));
    } finally {
      input.disabled = false;
      input.focus();
    }
  }

  input.addEventListener("input", () => { sel = -1; histPos = -1; render(); });
  input.addEventListener("focus", render);
  input.addEventListener("blur", () => { setTimeout(() => { list.hidden = true; }, 100); });
  input.addEventListener("keydown", (e) => {
    const open = !list.hidden && items.length > 0;
    if (e.key === "Tab") {
      if (!items.length) return;
      e.preventDefault();
      if (sel >= 0) return accept(sel);
      const p = commonPrefix();
      if (items.length === 1 || !p || p.length <= input.value.length) accept(0);
      else { input.value = p; render(); }
    } else if (e.key === "ArrowDown" && open) {
      e.preventDefault(); sel = (sel + 1) % items.length; render();
    } else if (e.key === "ArrowUp" && open && sel >= 0) {
      e.preventDefault(); sel -= 1; render();
    } else if ((e.key === "ArrowUp" || e.key === "ArrowDown") && !open) {
      if (!historyCmds.length) return;
      e.preventDefault();
      histPos = e.key === "ArrowUp" ? Math.min(histPos + 1, historyCmds.length - 1) : Math.max(histPos - 1, -1);
      input.value = histPos >= 0 ? historyCmds[histPos] : "";
    } else if (e.key === "Escape") {
      list.hidden = true; sel = -1;
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (open && sel >= 0) return accept(sel);
      const command = input.value.trim().replace(/\s+/g, " ");
      if (!command) return;
      input.value = ""; sel = -1; histPos = -1; list.hidden = true; hint.textContent = "";
      send(command, false);
    }
  });
}

document.addEventListener("DOMContentLoaded", initConsole);
