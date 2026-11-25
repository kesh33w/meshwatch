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
  } else if (t.dataset.inventory) {
    ev.preventDefault();
    readSettings(t);
  } else if (t.id === "bulkclear") {
    bulk.clear();
    syncBulk();
  }
});

async function readSettings(btn) {
  const msg = $("#invmsg");
  btn.disabled = true;
  if (msg) msg.textContent = "Reading firmware and settings over the mesh (about 10 requests)…";
  const res = await postJSON(`/nodes/${btn.dataset.inventory}/inventory`);
  btn.disabled = false;
  if (res.ok && res.data.ok) location.reload();
  else if (msg) msg.textContent = "Failed: " + (res.data.error || errText(res));
}

// ---------- bulk add (add page) ----------
const bulk = new Map();   // pubkey -> name, kept across searches

function syncBulk() {
  const panel = $("#bulkpanel");
  if (!panel) return;
  document.querySelectorAll("input.bulk").forEach((cb) => { cb.checked = bulk.has(cb.value); });
  panel.hidden = bulk.size === 0;
  $("#bulkcount").textContent = bulk.size;
  const list = $("#bulklist");
  const keys = $("#bulkkeys");
  list.replaceChildren();
  keys.replaceChildren();
  for (const [key, name] of bulk) {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = name;
    list.append(chip);
    const input = document.createElement("input");
    input.type = "hidden"; input.name = "pubkey"; input.value = key;
    keys.append(input);
  }
}

document.addEventListener("change", (ev) => {
  const t = ev.target;
  if (t.classList && t.classList.contains("bulk")) {
    if (t.checked) bulk.set(t.value, t.dataset.name); else bulk.delete(t.value);
    syncBulk();
  } else if (t.classList && t.classList.contains("pick-net")) {
    document.querySelectorAll(`input.target[data-net="${CSS.escape(t.dataset.net)}"]`)
      .forEach((cb) => { cb.checked = t.checked; });
  }
});
document.addEventListener("htmx:afterSwap", syncBulk);

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
  const multi = !!box.dataset.multi;
  const list = $("#suggest");
  const hint = $("#hint");
  let commands = [];
  let historyCmds = [];
  let items = [];
  let sel = -1;
  let histPos = -1;
  box.scrollTop = box.scrollHeight;

  fetch(`/api/v1/cli/catalog?node=${node || ""}`, { credentials: "same-origin" })
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

  function targets() {
    if (!multi) return [{ key: node, label: box.dataset.label || "", net: "" }];
    return [...document.querySelectorAll("input.target:checked")]
      .map((cb) => ({ key: cb.value, label: cb.dataset.label, net: cb.dataset.net }));
  }

  function show(t, res) {
    if (multi) line("meta", t.label);
    if (!res.ok) { line("err", errText(res)); return; }
    if (res.data.ok) {
      line("reply", res.data.reply || "(empty reply)");
      line("meta", (res.data.previous != null ? `was: ${res.data.previous} · ` : "") + `${res.data.elapsed_s}s`);
    } else {
      line("err", res.data.error || "failed");
    }
  }

  const exec = (t, command, confirmed) =>
    postJSON(`/api/v1/nodes/${t.key}/cli`, { command, confirm: !!confirmed });

  // Runs one command on every target. run.confirmed carries the user's "yes" across a snippet.
  async function runCommand(command, run) {
    const list = targets();
    if (!list.length) { line("err", "Tick at least one node above."); return false; }
    line("cmd", "> " + command + (multi ? `   (${list.length} node${list.length > 1 ? "s" : ""})` : ""));
    const pending = line("meta", "sending over the mesh…");
    const first = list[0];
    let res = await exec(first, command, run.confirmed);
    if (res.status === 409 && res.data.needs_confirm) {
      const what = run.snippet ? `the snippet “${run.snippet}”` : `“${command}”`;
      const where = list.length > 1 ? ` on ${list.length} nodes` : "";
      if (!confirm(`${what} changes nodes${where} (may reboot, change radio settings or cut a node off). Send it?`)) {
        pending.remove(); line("err", "cancelled"); return false;
      }
      run.confirmed = true;
      res = await exec(first, command, true);
    }
    show(first, res);
    // The rest: sequential per network/radio, networks in parallel.
    const groups = new Map();
    for (const t of list.slice(1)) { if (!groups.has(t.net)) groups.set(t.net, []); groups.get(t.net).push(t); }
    await Promise.all([...groups.values()].map(async (g) => {
      for (const t of g) show(t, await exec(t, command, run.confirmed));
    }));
    pending.remove();
    if (!historyCmds.includes(command)) historyCmds.unshift(command);
    return true;
  }

  async function send(command, run) {
    input.disabled = true;
    try {
      await runCommand(command, run || { confirmed: false });
    } catch (e) {
      line("err", e.message || String(e));
    } finally {
      input.disabled = false;
      input.focus();
    }
  }

  // ---------- snippets ----------
  const snippetList = $("#snippetlist");
  const snippetForm = $("#snippetform");
  const F = () => snippetForm.elements;
  async function loadSnippets() {
    if (!snippetList) return;
    const d = await fetch("/api/v1/snippets", { credentials: "same-origin" }).then((r) => r.json());
    snippetList.replaceChildren();
    for (const sn of d.snippets || []) {
      const run = document.createElement("button");
      run.type = "button"; run.className = "secondary"; run.textContent = "▶ " + sn.name;
      run.title = sn.commands.join("\n");
      run.addEventListener("click", async () => {
        input.disabled = true;
        const state = { confirmed: false, snippet: sn.name };
        try {
          for (const c of sn.commands) { if (!(await runCommand(c, state))) break; }
        } finally { input.disabled = false; }
      });
      const edit = document.createElement("button");
      edit.type = "button"; edit.className = "secondary small"; edit.textContent = "edit";
      edit.addEventListener("click", () => {
        F().sid.value = sn.id; F().sname.value = sn.name;
        F().scmds.value = sn.commands.join("\n");
      });
      const del = document.createElement("button");
      del.type = "button"; del.className = "secondary small"; del.textContent = "✕";
      del.setAttribute("aria-label", "Delete snippet " + sn.name);
      del.addEventListener("click", async () => {
        if (!confirm(`Delete snippet “${sn.name}”?`)) return;
        await postJSON(`/api/v1/snippets/${sn.id}/delete`);
        loadSnippets();
      });
      const wrap = document.createElement("span");
      wrap.className = "snippet";
      wrap.append(run, edit, del);
      snippetList.append(wrap);
    }
  }
  if (snippetForm) {
    snippetForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const res = await postJSON("/api/v1/snippets", {
        id: F().sid.value || null, name: F().sname.value,
        commands: F().scmds.value.split("\n"),
      });
      if (!res.ok) { alert(errText(res)); return; }
      snippetForm.reset(); F().sid.value = "";
      loadSnippets();
    });
    loadSnippets();
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
      send(command);
    }
  });
}

document.addEventListener("DOMContentLoaded", initConsole);
