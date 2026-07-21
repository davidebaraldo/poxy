"use strict";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

async function api(method, path, body) {
  const opt = { method, credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(path, opt);
  if (res.status === 401) { showLogin(); throw new Error("non autenticato"); }
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  const ct = res.headers.get("Content-Type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

function humanBytes(n) {
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + " " + u[i];
}
function fmtTime(iso) { return new Date(iso).toLocaleTimeString(); }
function stCls(code, blocked) {
  if (blocked) return "st-blocked";
  return "st-" + Math.floor(code / 100);
}

// --- auth ---
function showLogin() { $("#app").classList.add("hidden"); $("#login").classList.remove("hidden"); }
function showApp() { $("#login").classList.add("hidden"); $("#app").classList.remove("hidden"); }

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#login-error").textContent = "";
  try {
    await api("POST", "/api/login", { password: $("#login-password").value });
    $("#login-password").value = "";
    showApp();
    boot();
  } catch (err) { $("#login-error").textContent = err.message; }
});

$("#logout").addEventListener("click", async () => {
  try { await api("POST", "/api/logout"); } catch (_) {}
  if (sse) { sse.close(); sse = null; }
  showLogin();
});

// --- tabs ---
$$("nav button").forEach((b) => b.addEventListener("click", () => {
  $$("nav button").forEach((x) => x.classList.remove("active"));
  b.classList.add("active");
  $$(".tab").forEach((el) => el.classList.add("hidden"));
  $("#tab-" + b.dataset.tab).classList.remove("hidden");
  if (b.dataset.tab === "domini") loadDomains();
  if (b.dataset.tab === "uscita") loadEgress();
  if (b.dataset.tab === "client") loadClients();
}));

// --- dashboard ---
let sse = null;
let statsTimer = null;

function bootDashboard() {
  loadStats();
  if (statsTimer) clearInterval(statsTimer);
  statsTimer = setInterval(loadStats, 3000);

  api("GET", "/api/traffic?limit=200").then((rows) => {
    (rows || []).forEach((e) => addRow(e, false));
  }).catch(() => {});

  api("GET", "/api/config").then((c) => {
    const el = $("#hdr-fp");
    if (el) el.textContent = c.fingerprint;
  }).catch(() => {});

  startSSE();
}

async function loadStats() {
  try {
    const s = await api("GET", "/api/stats");
    $("#s-total").textContent = s.total;
    $("#s-blocked").textContent = s.blocked;
    $("#s-errors").textContent = s.errors;
    $("#s-connected").textContent = s.connected;
    $("#s-in").textContent = humanBytes(s.bytesIn);
    $("#s-out").textContent = humanBytes(s.bytesOut);
    const hc = $("#hdr-clients");
    if (hc) hc.textContent = s.connected;
  } catch (_) {}
}

function startSSE() {
  if (sse) sse.close();
  sse = new EventSource("/api/traffic/live");
  sse.onopen = () => { $("#live-dot").classList.add("on"); const s = $("#hdr-state"); if (s) s.textContent = t("status.active"); };
  sse.onerror = () => { $("#live-dot").classList.remove("on"); const s = $("#hdr-state"); if (s) s.textContent = t("status.reconnect"); };
  sse.onmessage = (ev) => {
    try { addRow(JSON.parse(ev.data), true); } catch (_) {}
  };
}

function addRow(e, prepend) {
  const tb = $("#traffic tbody");
  const tr = document.createElement("tr");
  tr.className = "req-row" + (prepend ? " flash" : "");
  tr.innerHTML = `
    <td>${fmtTime(e.time)}</td>
    <td>${esc(e.clientId)}</td>
    <td><span class="method m-${esc(e.method)}">${esc(e.method)}</span></td>
    <td>${esc(e.scheme)}://${esc(e.host)}</td>
    <td title="${esc(e.path)}">${esc(e.path)}</td>
    <td><span class="pill ${stCls(e.status, e.blocked)}">${e.blocked ? "BLOCK" : e.status}</span></td>
    <td class="fpchip">${esc(e.fingerprint)}</td>
    <td>${esc(e.matchedRule || "")}</td>
    <td class="up">${humanBytes(e.reqBytes)}</td>
    <td class="down">${humanBytes(e.respBytes)}</td>
    <td>${e.durationMs}</td>`;
  const detail = document.createElement("tr");
  detail.className = "detail-row hidden";
  detail.innerHTML = `<td colspan="11">${renderDetail(e)}</td>`;
  tr.addEventListener("click", () => detail.classList.toggle("hidden"));
  if (prepend) {
    tb.insertBefore(detail, tb.firstChild);
    tb.insertBefore(tr, tb.firstChild);
  } else {
    tb.appendChild(tr);
    tb.appendChild(detail);
  }
  while (tb.children.length > 1000) tb.removeChild(tb.lastChild);
}

function renderDetail(e) {
  const fields = [
    ["d.id", e.id],
    ["d.time", new Date(e.time).toLocaleString()],
    ["d.clientId", e.clientId],
    ["d.clientAddr", e.clientAddr],
    ["d.method", e.method],
    ["d.url", `${e.scheme}://${e.host}${e.path}`],
    ["d.status", e.blocked ? "BLOCK " + e.status : e.status],
    ["d.fp", e.fingerprint],
    ["d.rule", e.matchedRule || "-"],
    ["d.ua", e.userAgent || "-"],
    ["d.reqBytes", e.reqBytes],
    ["d.respBytes", e.respBytes],
    ["d.duration", e.durationMs + " ms"],
    ["d.blocked", e.blocked],
    ["d.error", e.error || "-"],
  ];
  const kv = fields
    .map(([k, v]) => `<div class="kv"><span>${esc(t(k))}</span><code>${esc(v)}</code></div>`)
    .join("");
  const bodies = (e.reqBody || e.respBody)
    ? `<div class="hdrs">
        <div><h4>${esc(t("detail.reqBody"))}</h4>${renderBody(e.reqBody, e.reqBodyTruncated)}</div>
        <div><h4>${esc(t("detail.respBody"))}</h4>${renderBody(e.respBody, e.respBodyTruncated)}</div>
      </div>`
    : "";
  return `<div class="detail">
    <div class="kvgrid">${kv}</div>
    <div class="hdrs">
      <div><h4>${esc(t("detail.reqHeaders"))}</h4>${renderHeaders(e.reqHeaders)}</div>
      <div><h4>${esc(t("detail.respHeaders"))}</h4>${renderHeaders(e.respHeaders)}</div>
    </div>
    ${bodies}
  </div>`;
}

function renderBody(b64, trunc) {
  if (!b64) return `<div class="muted small">${esc(t("body.empty"))}</div>`;
  let bytes;
  try {
    const bin = atob(b64);
    bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  } catch (_) { return '<div class="muted small">—</div>'; }
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  let ctrl = 0;
  for (const ch of text) {
    const c = ch.codePointAt(0);
    if (c < 9 || (c > 13 && c < 32) || c === 0xfffd) ctrl++;
  }
  if (ctrl > text.length * 0.02) {
    return `<div class="muted small">${esc(t("body.binary", { n: bytes.length }))}</div>`;
  }
  let out = text;
  try { out = JSON.stringify(JSON.parse(text), null, 2); } catch (_) {}
  const note = trunc ? `<div class="muted small">${esc(t("body.truncated"))}</div>` : "";
  return `<pre class="body">${esc(out)}</pre>${note}`;
}

function renderHeaders(h) {
  const keys = h ? Object.keys(h).sort() : [];
  if (!keys.length) return `<div class="muted small">${esc(t("body.none"))}</div>`;
  const rows = keys
    .map((k) => h[k].map((v) => `<tr><td>${esc(k)}</td><td class="hval" title="${esc(t("hval.expand"))}">${esc(v)}</td></tr>`).join(""))
    .join("");
  return `<table class="hdr">${rows}</table>`;
}

$("#clear-traffic").addEventListener("click", () => { $("#traffic tbody").innerHTML = ""; });

// Espandi/collassa i valori header lunghi (es. Authorization) al click.
$("#traffic").addEventListener("click", (e) => {
  const cell = e.target.closest(".hval");
  if (cell) { cell.classList.toggle("expanded"); e.stopPropagation(); }
});

// --- egress / uscita ---
async function loadEgress() {
  const [cfg, fps] = await Promise.all([
    api("GET", "/api/config"),
    api("GET", "/api/fingerprints"),
  ]);
  const sel = $("#e-fingerprint");
  sel.innerHTML = "";
  (fps || []).forEach((f) => {
    const o = document.createElement("option");
    o.value = f; o.textContent = f;
    if (f === cfg.fingerprint) o.selected = true;
    sel.appendChild(o);
  });
  $("#e-ua").value = cfg.userAgent || "";
  $("#e-default").value = cfg.defaultAction || "allow";
  $("#e-allowprivate").checked = !!cfg.allowPrivate;
  $("#e-normalize").checked = !!cfg.normalizeFingerprint;
  $("#e-capture").checked = !!cfg.captureBodies;
  $("#e-set").value = formatHeaders(cfg.setHeaders);
  $("#e-strip").value = (cfg.stripHeaders || []).join("\n");
}

$("#save-egress").addEventListener("click", async () => {
  const body = {
    fingerprint: $("#e-fingerprint").value,
    userAgent: $("#e-ua").value.trim(),
    defaultAction: $("#e-default").value,
    allowPrivate: $("#e-allowprivate").checked,
    normalizeFingerprint: $("#e-normalize").checked,
    captureBodies: $("#e-capture").checked,
    setHeaders: parseHeaders($("#e-set").value),
    stripHeaders: parseLines($("#e-strip").value),
  };
  try {
    await api("PUT", "/api/config", body);
    flash("#egress-status", t("msg.saved"));
  } catch (err) { flash("#egress-status", err.message, true); }
});

// --- domini ---
async function loadDomains() {
  const rules = await api("GET", "/api/domains");
  const tb = $("#domains tbody");
  tb.innerHTML = "";
  (rules || []).forEach(addDomainRow);
}

function addDomainRow(r = {}) {
  const tb = $("#domains tbody");
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td><input class="d-pattern" value="${esc(r.pattern || "")}" placeholder="*.example.com"></td>
    <td><select class="d-action">
      <option value=""${!r.action ? " selected" : ""}>eredita</option>
      <option value="allow"${r.action === "allow" ? " selected" : ""}>allow</option>
      <option value="block"${r.action === "block" ? " selected" : ""}>block</option>
    </select></td>
    <td><input class="d-ua" value="${esc(r.userAgent || "")}"></td>
    <td><textarea class="d-set" rows="2" placeholder="Nome: valore">${esc(formatHeaders(r.setHeaders))}</textarea></td>
    <td><textarea class="d-strip" rows="2">${esc((r.stripHeaders || []).join("\n"))}</textarea></td>
    <td><input class="d-note" value="${esc(r.note || "")}"></td>
    <td><button class="ghost d-del">✕</button></td>`;
  tr.querySelector(".d-del").addEventListener("click", () => tr.remove());
  tb.appendChild(tr);
}

$("#add-domain").addEventListener("click", () => addDomainRow());

$("#save-domains").addEventListener("click", async () => {
  const rules = $$("#domains tbody tr").map((tr) => ({
    pattern: $(".d-pattern", tr).value.trim(),
    action: $(".d-action", tr).value,
    userAgent: $(".d-ua", tr).value.trim(),
    setHeaders: parseHeaders($(".d-set", tr).value),
    stripHeaders: parseLines($(".d-strip", tr).value),
    note: $(".d-note", tr).value.trim(),
  })).filter((r) => r.pattern !== "");
  try {
    await api("PUT", "/api/domains", rules);
    flash("#domini-status", t("msg.saved"));
  } catch (err) { flash("#domini-status", err.message, true); }
});

// --- client ---
async function loadClients() {
  const list = await api("GET", "/api/clients");
  const tb = $("#clients tbody");
  tb.innerHTML = "";
  (list || []).forEach((c) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(c.id)}</td><td>${esc(c.addr)}</td>
      <td>${fmtTime(c.since)}</td><td>${c.streams}</td><td>${c.requests}</td>`;
    tb.appendChild(tr);
  });
}

$("#gen-bundle").addEventListener("click", () => {
  const name = encodeURIComponent($("#bundle-name").value.trim() || "client");
  window.location = "/api/bundle?name=" + name;
});

$("#gen-setup").addEventListener("click", () => {
  const name = encodeURIComponent($("#setup-name").value.trim() || "client");
  const os = $("#setup-os").value;
  window.location = "/api/setup?os=" + os + "&name=" + name;
});

$("#gen-uninstall").addEventListener("click", (e) => {
  e.preventDefault();
  window.location = "/api/uninstall?os=" + $("#setup-os").value;
});

// --- impostazioni ---
$("#save-pw").addEventListener("click", async () => {
  try {
    await api("POST", "/api/password", { old: $("#pw-old").value, new: $("#pw-new").value });
    $("#pw-old").value = ""; $("#pw-new").value = "";
    flash("#pw-status", t("msg.pwUpdated"));
  } catch (err) { flash("#pw-status", err.message, true); }
});

// --- helpers ---
function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
function parseLines(text) {
  return text.split("\n").map((l) => l.trim()).filter(Boolean);
}
function parseHeaders(text) {
  const out = {};
  parseLines(text).forEach((l) => {
    const i = l.indexOf(":");
    if (i > 0) out[l.slice(0, i).trim()] = l.slice(i + 1).trim();
  });
  return out;
}
function formatHeaders(obj) {
  if (!obj) return "";
  return Object.entries(obj).map(([k, v]) => `${k}: ${v}`).join("\n");
}
function flash(sel, msg, isErr) {
  const el = $(sel);
  el.textContent = msg;
  el.style.color = isErr ? "var(--err)" : "var(--ok)";
  setTimeout(() => { el.textContent = ""; }, 4000);
}

// --- boot ---
function boot() { bootDashboard(); }

(async function init() {
  applyI18n();
  initLangSelector();
  try {
    const s = await api("GET", "/api/session");
    if (s.authenticated) { showApp(); boot(); }
    else showLogin();
  } catch (_) { showLogin(); }
})();
