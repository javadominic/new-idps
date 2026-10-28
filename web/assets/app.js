"use strict";
/* IDPS dashboard. No frameworks, no CDN: works in an isolated lab.
   Every piece of text that can come from an attacker (log lines, signatures, addresses)
   goes through esc() before it touches the page. */
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const S = { me: null, ov: null, events: new Map(), page: "overview", sse: null, worldShapes: null, filters: {}, agentCount: null };

async function api(path, body, method) {
  const o = { credentials: "same-origin", headers: { "X-IDPS": "1" } };
  if (body !== undefined) { o.method = method || "POST"; o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(body); }
  else if (method) o.method = method;
  const r = await fetch(path, o);
  if (r.status === 401 && !path.includes("/login")) { location.href = "/login"; return {}; }
  let j = {};
  try { j = await r.json(); } catch (e) { /* empty body */ }
  if (j && typeof j === "object" && !Array.isArray(j)) j._s = r.status;
  return j;
}

/* ---------- formatting ---------- */
const pad = n => String(n).padStart(2, "0");
function clock(t) { const d = new Date(t * 1000); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; }
function when(t) {
  if (!t) return "never";
  const s = Date.now() / 1000 - t;
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago";
  return new Date(t * 1000).toLocaleDateString() + " " + clock(t).slice(0, 5);
}
function until(t) { const s = t - Date.now() / 1000; if (s <= 0) return "ending"; return s < 3600 ? Math.ceil(s / 60) + " min" : (s / 3600).toFixed(1) + " h"; }
const sev = s => `<span class="sev ${esc(s)}">${esc({ high: "Urgent", medium: "Suspicious", low: "Heads-up" }[s] || s)}</span>`;
const simTag = e => e.simulated ? '<span class="sim">demo</span>' : "";
const ipLink = ip => ip ? `<a href="#" class="ip" data-act="open-ip" data-ip="${esc(ip)}">${esc(ip)}</a>` : '<span class="dim">no address</span>';
const cmdBox = (id, text) => `<div class="cmd"><pre id="${id}">${esc(text)}</pre><button class="btn sm" data-act="copy" data-target="${id}">Copy</button></div>`;

function toast(msg, cls) {
  const t = document.createElement("div"); t.className = "toast " + (cls || ""); t.innerHTML = msg; document.body.appendChild(t);
  setTimeout(() => t.remove(), 6000);
}
function beep() {
  try { const c = new (window.AudioContext || window.webkitAudioContext)(), o = c.createOscillator(); o.frequency.value = 740; o.connect(c.destination); o.start(); o.stop(c.currentTime + .1); } catch (e) { /* no audio */ }
}

/* ---------- drawer ---------- */
function drawer(html) { $("#drawer").innerHTML = html; $("#drawer").classList.add("open"); $("#scrim").classList.add("open"); }
function closeDrawer() { $("#drawer").classList.remove("open"); $("#scrim").classList.remove("open"); }

function eventDrawer(e) {
  drawer(`<div class="bar"><button class="btn sm" data-act="close">Close</button></div>
  <h3>${esc(e.title)} ${simTag(e)}</h3><div>${sev(e.severity)} <span class="dim small">${esc(clock(e.ingested))}${e.count > 1 ? " · seen " + e.count + " times" : ""}</span></div>
  <p>${esc(e.explain)}</p>
  <h2>What the system did</h2><p>${esc(e.decision_text)}</p>
  <h2>What you should do</h2><p>${esc(e.advice)}</p>
  <dl class="kv"><dt>Source</dt><dd>${ipLink(e.src_ip)} ${e.country ? "(" + esc(e.country) + ")" : ""}</dd>
  <dt>Detected by</dt><dd>${esc(e.engine)}${e.agent ? " on " + esc(e.agent) : ""}</dd>
  ${e.dst_port ? `<dt>Port</dt><dd class="mono">${esc(e.dst_port)}</dd>` : ""}
  <dt>Rule</dt><dd>${esc(e.signature)}</dd>
  ${e.mitre ? `<dt>MITRE ATT&amp;CK</dt><dd>${esc(e.mitre)} ${esc(e.mitre_name)}</dd>` : ""}
  ${e.intel && e.intel.length ? `<dt>Threat lists</dt><dd>${esc(e.intel.join(", "))}</dd>` : ""}</dl>
  <h2>Raw record</h2><pre>${esc(e.raw)}</pre>`);
}

async function ipDrawer(ip) {
  const d = await api("/api/ip/" + encodeURIComponent(ip));
  if (!d.ip) return;
  drawer(`<div class="bar"><button class="btn sm" data-act="close">Close</button></div>
  <h3 class="mono">${esc(d.ip)}</h3>
  <div>${d.worst ? sev(d.worst) : ""} ${d.blocked ? '<span class="pill live">blocked now</span>' : ""} ${d.protected ? '<span class="pill">protected</span>' : ""}</div>
  <dl class="kv"><dt>Alerts</dt><dd class="mono">${d.total}</dd><dt>First seen</dt><dd>${when(d.first)}</dd><dt>Last seen</dt><dd>${when(d.last)}</dd>
  <dt>Country</dt><dd>${esc(d.country || "unknown (lab or private address)")}</dd>
  ${d.intel.length ? `<dt>Threat lists</dt><dd>${esc(d.intel.join(", "))}</dd>` : ""}
  ${d.protected ? `<dt>Protected</dt><dd>${esc(d.protected)}</dd>` : ""}</dl>
  <div class="bar">${d.blocked ? `<button class="btn" data-act="unblock" data-ip="${esc(d.ip)}">Unblock</button>` :
    (d.protected ? "" : `<button class="btn bad" data-act="block-ip" data-ip="${esc(d.ip)}">Block for 30 minutes</button>`)}
  ${d.protected ? "" : `<button class="btn" data-act="protect-ip" data-ip="${esc(d.ip)}">Never block this address</button>`}</div>
  <h2>What this address did</h2>
  ${d.events.length ? `<table>${d.events.slice(0, 60).map(e => { S.events.set(e.id, e); return `<tr class="click" data-act="open-event" data-id="${e.id}"><td class="mono dim">${clock(e.ingested)}</td><td>${sev(e.severity)}</td><td>${esc(e.title)}</td></tr>`; }).join("")}</table>` : '<p class="dim">Nothing recorded.</p>'}`);
}

/* ---------- overview ---------- */
const STAGES = [
  ["Capture", "Sensors, agents and decoys watch your network and websites."],
  ["Understand", "Each alert is explained in plain words and tagged."],
  ["Decide", "Shadow or Live, protected list, safety limits."],
  ["Act", "Attackers are blocked in the firewall, then released on time."],
  ["Notify", "You are told on the dashboard, Telegram or email."],
];
function pipeHTML(f) {
  const c = f.capture, d = f.decide;
  const src = [["Suricata", c.suricata], ["Snort", c.snort], ["Agents", c.agents > 0], ["Decoys", c.honeypot]]
    .map(([n, on]) => `<span class="dim small"><i class="dot ${on ? "on" : ""}"></i>${n}</span>`).join(" ");
  const nums = [c.alerts_seen, f.understand.events, d.alert_only + d.would_block + d.blocked + d.protected + d.other,
    f.act.active_blocks, f.notify.sent];
  const subs = [src, "", `${d.would_block} would block · ${d.blocked} blocked · ${d.protected} protected`, "blocked right now", "in the last hour"];
  return `<div class="track" id="track"></div><div class="row">${STAGES.map((s, i) =>
    `<div class="st"><h4>${s[0]}</h4><div class="n">${nums[i]}</div><p>${i === 0 || i === 2 ? subs[i] || s[1] : s[1]}</p></div>`).join("")}</div>`;
}
function fireDot(severity) {
  const tr = $("#track"); if (!tr) return;
  const i = document.createElement("i"); i.className = severity; tr.appendChild(i); setTimeout(() => i.remove(), 1500);
}

function modeSwitch(mode) {
  return `<div class="switch"><button data-act="set-mode" data-mode="shadow" class="${mode === "shadow" ? "on" : ""}">Shadow</button><button data-act="set-mode" data-mode="live" class="live ${mode === "live" ? "on" : ""}">Live</button></div>`;
}
async function setMode(m) {
  if (m === "live" && !confirm("Switch to LIVE mode?\n\nAttackers detected as urgent will really be blocked in the firewall.\nMake sure your own address is on the protected list first (Settings).")) return;
  const r = await api("/api/settings", { mode: m });
  (r.warnings || []).forEach(w => toast(esc(w)));
  toast(m === "live" ? "Live mode on. Urgent attackers will be blocked." : "Shadow mode on. Nothing will be blocked.");
  loadOverview(true); route();
}

function feedRow(e, isNew) {
  S.events.set(e.id, e);
  return `<tr class="click ${isNew ? "new" : ""}" data-act="open-event" data-id="${e.id}"><td class="mono dim" style="white-space:nowrap">${clock(e.ingested)}</td>
  <td>${sev(e.severity)}</td><td><b>${esc(e.title)}</b>${simTag(e)}<div class="dim small">${esc(e.explain)}</div></td><td class="dim small">${esc(e.decision_text)}</td></tr>`;
}

async function pageOverview() {
  const [ov, al] = await Promise.all([api("/api/overview"), api("/api/alerts?limit=14")]);
  S.ov = ov; navBadges();
  const c = ov.counts;
  const unprot = S.me && !S.me.protected;
  $("#view").innerHTML = `
  ${unprot ? `<div class="banner"><div class="grow"><b>Protect your own computer.</b> Your address is <span class="mono">${esc(S.me.ip)}</span>. If it ever looked like an attacker you could lock yourself out.</div><button class="btn pri" data-act="add-mine">Protect my address</button></div>` : ""}
  <div class="hero ${esc(ov.status)}"><div class="light"></div><div><div class="t">${esc(ov.headline)}</div>
  <div class="m">${ov.mode === "shadow" ? "Shadow mode: the system watches and explains, but never blocks. Safe for testing." : "Live mode: urgent attackers are blocked automatically."}</div></div>
  <div class="modebar">${modeSwitch(ov.mode)}</div></div>
  <div class="figs"><div class="fig"><b>${c.alerts}</b><span>alerts in 24 h</span></div><div class="fig"><b>${c.high}</b><span>urgent</span></div>
  <div class="fig"><b>${c.blocked}</b><span>blocked now</span></div><div class="fig"><b>${c.would_block}</b><span>would-have-blocked</span></div>
  <div class="fig"><b>${c.agents_online}</b><span>agents online</span></div></div>
  <div class="pipe" id="pipe">${pipeHTML(ov.flow)}</div>
  <div class="cols"><div>
    <h2>Alerts per minute, last hour</h2><canvas id="chart" height="150"></canvas>
    <div class="legend"><span><i style="background:#5bd18a"></i>Heads-up</span><span><i style="background:#f2b84b"></i>Suspicious</span><span><i style="background:#f0645b"></i>Urgent</span></div>
    <h2>Live feed</h2><table id="feed"><tbody>${al.length ? al.map(e => feedRow(e)).join("") : '<tr><td class="dim">Nothing yet. Open Simulator to try a safe demo attack.</td></tr>'}</tbody></table>
  </div><div>
    <h2>Most active sources (24 h)</h2>
    ${ov.top.length ? `<table>${ov.top.map(t => `<tr class="click" data-act="open-ip" data-ip="${esc(t.ip)}"><td class="mono">${esc(t.ip)}</td><td>${sev(t.sev)}</td><td class="right mono">${t.n}</td><td>${t.blocked ? '<span class="pill live">blocked</span>' : ""}</td></tr>`).join("")}</table>` : '<p class="dim">No sources yet.</p>'}
    <h2>What kinds of attack</h2>
    ${ov.kinds.length ? `<table>${ov.kinds.map(k => `<tr><td>${esc(k.title)}</td><td class="dim mono small">${esc(k.mitre)}</td><td class="right mono">${k.n}</td></tr>`).join("")}</table>` : '<p class="dim">None yet.</p>'}
    <h2>Where attackers come from</h2><canvas id="map" height="150"></canvas>
  </div></div>`;
  drawChart(ov.series); drawMap(ov.map);
}

function drawChart(series) {
  const cv = $("#chart"); if (!cv) return;
  const dpr = window.devicePixelRatio || 1, w = cv.clientWidth, h = 150;
  cv.width = w * dpr; cv.height = h * dpr; const g = cv.getContext("2d"); if (!g) return; g.scale(dpr, dpr);
  const max = Math.max(3, ...series.map(s => s.low + s.medium + s.high)), bw = (w - 30) / series.length;
  g.strokeStyle = "#26314b"; g.fillStyle = "#8c98b1"; g.font = "11px IBM Plex Mono, monospace";
  [0, .5, 1].forEach(f => { const y = 8 + (h - 30) * (1 - f); g.beginPath(); g.moveTo(26, y); g.lineTo(w, y); g.stroke(); g.fillText(Math.round(max * f), 0, y + 4); });
  series.forEach((s, i) => {
    let y = h - 22;
    [["low", "#5bd18a"], ["medium", "#f2b84b"], ["high", "#f0645b"]].forEach(([k, col]) => {
      const bh = (s[k] / max) * (h - 30); if (!bh) return; g.fillStyle = col; g.fillRect(28 + i * bw, y - bh, Math.max(bw - 1.5, 1), bh); y -= bh;
    });
  });
  g.fillStyle = "#8c98b1"; g.fillText("60 min ago", 28, h - 6); g.fillText("now", w - 24, h - 6);
}

async function drawMap(points) {
  const cv = $("#map"); if (!cv) return;
  if (!S.worldShapes) { try { S.worldShapes = await (await fetch("/assets/world.json")).json(); } catch (e) { S.worldShapes = []; } }
  const dpr = window.devicePixelRatio || 1, w = cv.clientWidth, h = Math.round(w / 2);
  cv.style.height = h + "px"; cv.width = w * dpr; cv.height = h * dpr;
  const g = cv.getContext("2d"); if (!g) return; g.scale(dpr, dpr);
  const X = lon => (lon + 180) / 360 * w, Y = lat => (90 - lat) / 180 * h;
  g.fillStyle = "#1c2845";
  S.worldShapes.forEach(r => { g.beginPath(); for (let i = 0; i < r.length; i += 2) i ? g.lineTo(X(r[i]), Y(r[i + 1])) : g.moveTo(X(r[i]), Y(r[i + 1])); g.closePath(); g.fill(); });
  points.forEach(p => {
    const col = { 3: "#f0645b", 2: "#f2b84b", 1: "#5bd18a" }[p.r]; g.fillStyle = col + "55"; g.beginPath(); g.arc(X(p.lon), Y(p.lat), 5 + Math.min(Math.sqrt(p.n) * 2, 14), 0, 7); g.fill();
    g.fillStyle = col; g.beginPath(); g.arc(X(p.lon), Y(p.lat), 3, 0, 7); g.fill();
  });
  if (!points.length) { g.fillStyle = "#8c98b1"; g.font = "13px IBM Plex Sans, sans-serif"; g.textAlign = "center";
    g.fillText("Pins appear for public addresses once the location database is installed.", w / 2, h / 2); }
}

/* ---------- alerts ---------- */
async function pageAlerts() {
  const f = S.filters;
  $("#view").innerHTML = `<h1>Alerts</h1><p class="sub">Everything the system noticed. Click a row for the full explanation.</p>
  <div class="bar"><input type="text" id="f-q" placeholder="Search address, rule or machine" value="${esc(f.q || "")}" style="width:260px">
  <select id="f-sev"><option value="">All severities</option><option value="high">Urgent</option><option value="medium">Suspicious</option><option value="low">Heads-up</option></select>
  <select id="f-eng"><option value="">All sources</option><option>suricata</option><option>snort</option><option>weblog</option><option>fim</option><option>honeypot</option><option>simulator</option></select>
  <label style="margin:0;display:flex;gap:6px;align-items:center"><input type="checkbox" id="f-sim" ${f.nosim ? "checked" : ""}> Hide demo alerts</label>
  <a href="/api/export/events.csv" class="btn sm">Download CSV</a></div>
  <table><thead><tr><th>Time</th><th>Level</th><th>What happened</th><th>What we did</th></tr></thead><tbody id="alist"></tbody></table>
  <div class="bar"><button class="btn" id="more" data-act="load-more" style="display:none">Load older</button></div>`;
  $("#f-sev").value = f.severity || ""; $("#f-eng").value = f.engine || "";
  ["f-q", "f-sev", "f-eng", "f-sim"].forEach(id => $("#" + id).addEventListener("input", () => { S.filters = { q: $("#f-q").value, severity: $("#f-sev").value, engine: $("#f-eng").value, nosim: $("#f-sim").checked }; clearTimeout(S._ft); S._ft = setTimeout(() => loadAlerts(true), 250); }));
  loadAlerts(true);
}
async function loadAlerts(reset) {
  const f = S.filters, tb = $("#alist"); if (!tb) return;
  const p = new URLSearchParams({ limit: 60 });
  if (f.q) p.set("q", f.q); if (f.severity) p.set("severity", f.severity); if (f.engine) p.set("engine", f.engine); if (f.nosim) p.set("sim", "0");
  if (!reset && S.lastId) p.set("before", S.lastId);
  const rows = await api("/api/alerts?" + p);
  if (reset) tb.innerHTML = "";
  tb.insertAdjacentHTML("beforeend", rows.map(e => {
    S.events.set(e.id, e);
    return `<tr class="click" data-act="open-event" data-id="${e.id}"><td class="mono dim" style="white-space:nowrap">${when(e.ingested)}</td><td>${sev(e.severity)}</td>
    <td><b>${esc(e.title)}</b>${simTag(e)}${e.count > 1 ? ` <span class="dim mono small">×${e.count}</span>` : ""}<div class="dim small">${esc(e.explain)}</div></td><td class="dim small">${esc(e.decision_text)}</td></tr>`;
  }).join(""));
  if (rows.length) S.lastId = rows[rows.length - 1].id;
  if (reset && !rows.length) tb.innerHTML = '<tr><td colspan="4" class="dim">No alerts match.</td></tr>';
  $("#more").style.display = rows.length >= 60 ? "" : "none";
}

/* ---------- blocked ---------- */
async function pageBlocked() {
  const d = await api("/api/blocks");
  const rec = a => ({ would_block: `Shadow mode: would have blocked <b class="mono">${esc(a.src_ip)}</b>`, skip_protected: `Refused to block <b class="mono">${esc(a.src_ip)}</b>: ${esc(a.reason)}`,
    unblock: `Released <b class="mono">${esc(a.src_ip)}</b> (${esc(a.reason)})`, block_failed: `Could not block <b class="mono">${esc(a.src_ip)}</b>: ${esc(a.reason)}`,
    rate_limited: `Safety limit reached; did not block <b class="mono">${esc(a.src_ip)}</b>` }[a.action] || esc(a.action));
  $("#view").innerHTML = `<h1>Blocked addresses</h1><p class="sub">Addresses currently stopped at the firewall. Every block ends by itself, and repeat offenders are blocked for longer.</p>
  ${d.firewall.available ? "" : `<div class="banner"><div class="grow"><b>The firewall is not available:</b> ${esc(d.firewall.detail)}</div></div>`}
  ${d.active.length ? `<table><thead><tr><th>Address</th><th>Why</th><th>Since</th><th>Ends in</th><th></th></tr></thead>${d.active.map(a => `<tr><td>${ipLink(a.src_ip)} <span class="dim small">${esc(a.country || "")}</span></td><td>${esc(a.reason)}</td><td class="dim">${when(a.ts_epoch)}</td><td class="mono">${until(a.expires_epoch)}</td><td class="right"><button class="btn sm" data-act="unblock" data-ip="${esc(a.src_ip)}">Unblock</button></td></tr>`).join("")}</table>` : '<p class="dim">Nothing is blocked right now.</p>'}
  <div class="bar" style="margin-top:20px"><input type="text" id="blk-ip" placeholder="Block an address by hand, e.g. 203.0.113.5" style="width:300px"><button class="btn" data-act="block-manual">Block for 30 minutes</button>
  <span class="sp" style="flex:1"></span><button class="btn bad" data-act="panic">Unblock everyone now</button></div>
  <h2>Recent decisions</h2>${d.recent.length ? `<div class="list">${d.recent.map(a => `<div class="item"><div class="ic"></div><div>${rec(a)}<div class="dim small">${when(a.ts_epoch)}</div></div></div>`).join("")}</div>` : '<p class="dim">No decisions yet.</p>'}`;
}

/* ---------- agents ---------- */
async function pageAgents() {
  const [d, ins] = await Promise.all([api("/api/agents"), api("/api/agent_install")]);
  S.agentCount = d.agents.length;
  const cmd = ins.commands;
  $("#view").innerHTML = `<h1>Websites and computers</h1><p class="sub">An agent on a web server or computer reads its web logs and watches important files, then reports here. Works on Linux, macOS and Windows.</p>
  ${d.agents.length ? `<table><thead><tr><th>Name</th><th>System</th><th>Status</th><th>Watching</th><th></th></tr></thead>${d.agents.map(a => `<tr><td><b>${esc(a.name)}</b><div class="dim small mono">${esc(a.last_ip || "")}</div></td><td>${esc(a.platform || "")}<div class="dim small">v${esc(a.version || "?")}</div></td>
  <td><i class="dot ${a.online ? "on" : ""}"></i>${a.online ? "online" : "last seen " + when(a.last_seen)}</td><td class="dim small">${(a.info.logs || []).length} log(s), ${a.info.fim_files || 0} file(s)</td>
  <td class="right"><button class="btn sm" data-act="revoke" data-id="${esc(a.id)}" data-name="${esc(a.name)}">Remove</button></td></tr>`).join("")}</table>` : '<p class="dim">No machines yet. Add one below. It takes about a minute.</p>'}
  <h2>Add a machine</h2>${ins.localhost ? `<div class="banner"><div class="grow">You opened the dashboard as <b>localhost</b>. Other machines cannot reach that. Open the dashboard using this server's real address (for example http://192.168.x.x:5000) and come back to this page.</div></div>` : ""}
  <div class="tabs"><button class="on" data-act="tab" data-tab="linux">Linux</button><button data-act="tab" data-tab="mac">macOS</button><button data-act="tab" data-tab="windows">Windows</button></div>
  <div id="tab-linux" class="tabc"><p>On the machine you want to watch, open a terminal and paste this one line:</p>${cmdBox("c-linux", cmd.linux)}<p class="hint">It needs Python 3 and sudo. It finds nginx or Apache logs by itself, sets the agent up as a service and enrolls it.</p></div>
  <div id="tab-mac" class="tabc" style="display:none"><p>Open Terminal on the Mac and paste this one line:</p>${cmdBox("c-mac", cmd.mac)}<p class="hint">Needs Python 3 (install the Xcode tools if asked). It runs as a launchd service.</p></div>
  <div id="tab-windows" class="tabc" style="display:none"><p>Open <b>PowerShell as Administrator</b> and paste this one line:</p>${cmdBox("c-windows", cmd.windows)}<p class="hint">Needs Python 3 (<span class="mono">winget install Python.Python.3.12</span>). It finds IIS logs by itself and runs as a scheduled task.</p></div>
  <div id="waiting" class="result"><span class="spin"></span>Waiting for a new machine to connect. This page updates by itself.</div>`;
  clearInterval(S._agentPoll);
  S._agentPoll = setInterval(async () => {
    if (S.page !== "agents") return clearInterval(S._agentPoll);
    const n = await api("/api/agents");
    if (n.agents.length > S.agentCount) { clearInterval(S._agentPoll); toast("A new machine connected."); pageAgents(); }
  }, 3000);
}

/* ---------- simulator ---------- */
function selftestHTML(r) {
  if (!r) return '<p class="dim">The self-test has not been run yet.</p>';
  return `<div class="dim small">${when(r.ts)}: ${r.passed} passed, ${r.failed} failed, ${r.skipped} skipped</div><div class="list">${r.tests.map(t =>
    `<div class="item"><div class="ic ${t.status === "ok" ? "ok" : t.status === "fail" ? "fail" : "warn"}"></div><div><b>${esc(t.name)}</b><div class="dim small">${esc(t.detail)}</div></div></div>`).join("")}</div>`;
}
function labReportHTML(r) {
  if (!r.rows.length) return '<p class="dim">No lab test has been run yet.</p>';
  const cell = v => v ? (v.detected ? `<span class="sev low">${v.latency}s</span>` : '<span class="sev high">missed</span>') : '<span class="dim">-</span>';
  return `<table><thead><tr><th>Attack</th><th>Suricata</th><th>Snort</th><th>Web agent</th><th>Decoy</th><th>Result</th></tr></thead>${r.rows.map(x =>
    `<tr><td>${esc(x.label)}</td><td>${cell(x.engines.suricata)}</td><td>${cell(x.engines.snort)}</td><td>${cell(x.engines.weblog)}</td><td>${cell(x.engines.honeypot)}</td><td>${x.passed ? "PASS" : "FAIL"}</td></tr>`).join("")}</table>
  <p class="dim small">${r.detected} of ${r.expected} expected detections seen. Times are from attack start to the alert appearing here.</p>`;
}
async function pageSimulator() {
  const [sc, info, rep, h] = await Promise.all([api("/api/sim/scenarios"), api("/api/sim/info"), api("/api/sim/report"), api("/api/health")]);
  $("#view").innerHTML = `<h1>Simulator and tests</h1><p class="sub">Prove that every part works, without needing a real attacker.</p>
  <h2>1. Safe demo attacks</h2><p class="dim">These send fake, clearly labelled attacks through the real pipeline: explained, decided, blocked (in Live mode) and notified. No traffic leaves this machine, and the fake addresses belong to no real computer.</p>
  <div class="scen">${sc.map(s => `<button data-act="scenario" data-id="${esc(s.id)}"><b>${esc(s.label)}</b><span>${esc(s.story)}</span></button>`).join("")}</div><div id="sim-result"></div>
  <h2>2. Real attack test on your lab</h2><p class="dim">Run real scans, password guessing, floods and web attacks from a second lab machine, and get an expected-versus-detected table for your report. Only ever against machines you own.</p>
  <p>On the attacker machine, from the project's <span class="mono">simulator/</span> folder:</p>${cmdBox("c-lab", info.command)}
  <div class="bar"><button class="btn" data-act="refresh-lab">Refresh results</button></div><div id="lab-report">${labReportHTML(rep)}</div>
  <h2>3. Self-test: does every function work?</h2><div class="bar"><button class="btn pri" data-act="selftest">Run self-test</button><span id="st-wait"></span></div><div id="st-result">${selftestHTML(h.selftest)}</div>`;
}

/* ---------- setup & health ---------- */
async function pageSetup() {
  const [h, rules] = await Promise.all([api("/api/health"), api("/api/rules")]);
  const groups = {};
  h.items.forEach(i => (groups[i.group] = groups[i.group] || []).push(i));
  const word = { green: "Everything is working.", amber: "Working, with a few things worth fixing.", red: "Something needs fixing before you can rely on this." }[h.level];
  $("#view").innerHTML = `<h1>Setup and health</h1><div class="hero ${esc(h.level)}"><div class="light"></div><div><div class="t">${esc(word)}</div><div class="m">Each line says what is wrong in plain words and how to fix it. Copy the command shown in blue.</div></div></div>
  ${Object.entries(groups).map(([g, items]) => `<h2>${esc(g)}</h2><div class="list">${items.map(i => `<div class="item"><div class="ic ${esc(i.status)}"></div><div><b>${esc(i.title)}</b><div class="dim">${esc(i.detail)}</div>${i.fix && i.status !== "ok" ? `<div class="fix">${esc(i.fix)}</div>` : ""}</div></div>`).join("")}</div>`).join("")}
  <h2>Run the self-test</h2><div class="bar"><button class="btn pri" data-act="selftest">Run self-test</button><span id="st-wait"></span></div><div id="st-result">${selftestHTML(h.selftest)}</div>
  <h2>Detection rules</h2><p class="dim">The installer already put these in place. They are shown so you can see exactly what the sensors look for, or install by hand.</p>
  ${rules.map((r, i) => `<p><b>${esc(r.name)}</b> <span class="dim small">goes in ${esc(r.target)}</span></p>${cmdBox("rule" + i, r.content)}`).join("")}`;
}

/* ---------- settings ---------- */
const SCHEMA = [
  ["Blocking", [["block_ttl_minutes", "How long a block lasts (minutes)", "number", "Repeat offenders are blocked for twice as long each time."], ["severity_block_threshold", "Block attackers rated at least", "sev", "Urgent is the safe default."], ["max_blocks_per_minute", "Safety limit: most automatic blocks per minute", "number", "Stops a flood of fake sources from locking you out."], ["dedupe_window_seconds", "Ignore repeats from the same attacker for (seconds)", "number", ""]]],
  ["Notifications", [["notify_min_severity", "Tell me about", "sev", "Dashboard always shows everything."], ["notify_cooldown_seconds", "Quiet time per attacker (seconds)", "number", "So one attacker cannot send you a message every second."], ["telegram_token", "Telegram bot token", "secret", "Free. Create a bot with @BotFather in Telegram."], ["telegram_chat_id", "Telegram chat ID", "text", "Send your bot a message, then open https://api.telegram.org/bot<token>/getUpdates to find it."], ["smtp_host", "Email server (SMTP)", "text", "For Gmail: smtp.gmail.com with an app password."], ["smtp_port", "Email port", "number", ""], ["smtp_user", "Email username", "text", ""], ["smtp_pass", "Email password", "secret", ""], ["smtp_from", "Send from", "text", ""], ["smtp_to", "Send alerts to", "text", ""]]],
  ["Decoys and threat lists", [["honeypot_enabled", "Decoy services on", "check", "Fake SSH, admin page and telnet. Anyone touching them is an attacker."], ["honeypot_ports", "Decoy ports", "text", "Space separated. Restart the service after changing."], ["intel_enabled", "Use free threat lists", "check", "FireHOL and abuse.ch lists of known bad addresses."]]],
  ["Network", [["home_net", "Your network", "text", "The range your sensors protect, e.g. 192.168.56.0/24."], ["management_ip", "Your management address (never blocked)", "text", ""], ["suricata_eve_log", "Suricata log file", "text", ""], ["snort_alert_log", "Snort alert file", "text", ""], ["retention_days", "Keep alerts for (days)", "number", ""]]],
];
function field(k, label, type, hint, v) {
  const id = "s-" + k;
  let input;
  if (type === "check") input = `<input type="checkbox" id="${id}" ${v ? "checked" : ""}>`;
  else if (type === "sev") input = `<select id="${id}">${["low", "medium", "high"].map(o => `<option value="${o}" ${o === v ? "selected" : ""}>${{ low: "Heads-up and above", medium: "Suspicious and above", high: "Urgent only" }[o]}</option>`).join("")}</select>`;
  else if (type === "secret") input = `<input type="password" id="${id}" placeholder="${v ? "saved (leave blank to keep)" : ""}" autocomplete="new-password">`;
  else input = `<input type="${type === "number" ? "number" : "text"}" id="${id}" value="${esc(Array.isArray(v) ? v.join(" ") : v)}">`;
  return `<label for="${id}">${esc(label)}</label>${input}${hint ? `<div class="hint">${esc(hint)}</div>` : ""}`;
}
async function pageSettings() {
  const [d, wl] = await Promise.all([api("/api/settings"), api("/api/whitelist")]);
  const s = d.settings;
  $("#view").innerHTML = `<h1>Settings</h1><p class="sub">Changes apply within a second. No restart needed.</p><div class="form">
  <h2>Mode</h2>${modeSwitch(s.mode)}<div class="hint">Shadow only watches. Live really blocks. Start in Shadow and switch once the alerts look right.</div>
  <h2>Protected addresses</h2><p class="dim small">These can never be blocked, whatever they do. This machine, its gateway and every monitored machine are always protected too.</p>
  ${wl.items.length ? `<table>${wl.items.map(w => `<tr><td class="mono">${esc(w.cidr)}</td><td class="dim">${esc(w.note || "")}</td><td class="right"><button class="btn sm" data-act="wl-del" data-id="${w.id}">Remove</button></td></tr>`).join("")}</table>` : '<p class="dim">None yet.</p>'}
  <div class="bar"><input type="text" id="wl-new" placeholder="192.168.56.10 or 192.168.56.0/24" style="width:230px"><input type="text" id="wl-note" placeholder="note (optional)" style="width:170px"><button class="btn" data-act="wl-add">Add</button><button class="btn" data-act="add-mine">Add my address (${esc(S.me.ip)})</button></div>
  ${SCHEMA.map(([title, fields]) => `<h2>${esc(title)}</h2>${fields.map(([k, l, t, h]) => field(k, l, t, h, s[k])).join("")}`).join("")}
  <div class="bar"><button class="btn pri" data-act="save-settings">Save settings</button><button class="btn" data-act="test-notify" data-ch="telegram">Test Telegram</button><button class="btn" data-act="test-notify" data-ch="email">Test email</button><span id="save-msg" class="dim"></span></div>
  <h2>Threat lists</h2><p class="dim small">${Object.entries(d.intel.lists).map(([k, v]) => `${esc(k)}: ${v} addresses`).join(" · ") || "Not downloaded yet."}</p>
  <div class="bar"><button class="btn" data-act="intel-update">Update lists now</button><input type="text" id="intel-ip" placeholder="Add an address to your own list" style="width:230px"><button class="btn" data-act="intel-add">Add</button></div>
  <h2>Agent enrollment password</h2><p class="dim small">Machines need this to join. Changing it does not disconnect machines that already joined.</p><div class="bar"><button class="btn" data-act="regen-enroll">Make a new one</button></div>
  <h2>Change dashboard password</h2><div class="row2"><div><label>Current password</label><input type="password" id="pw-cur" autocomplete="current-password"></div><div><label>New password (8+ characters)</label><input type="password" id="pw-new" autocomplete="new-password"></div></div>
  <div class="bar"><button class="btn" data-act="change-pw">Change password</button></div>
  <h2>Reports</h2><div class="bar"><a class="btn" href="/report?days=7" target="_blank">Open weekly report</a><a class="btn" href="/api/export/events.csv?days=30">Download 30 days as CSV</a></div></div>`;
}
async function saveSettings(btn) {
  const out = {};
  SCHEMA.forEach(([, fields]) => fields.forEach(([k, , t]) => {
    const el = $("#s-" + k); if (!el) return;
    if (t === "check") out[k] = el.checked; else if (t === "secret") { if (el.value) out[k] = el.value; } else out[k] = el.value;
  }));
  const r = await api("/api/settings", out);
  $("#save-msg").textContent = r.ok ? "Saved." : (r.errors || ["Could not save."]).join(" ");
  (r.warnings || []).forEach(w => toast(esc(w)));
}

/* ---------- actions ---------- */
const ACT = {
  close: closeDrawer,
  "open-event": t => { const e = S.events.get(+t.dataset.id); if (e) eventDrawer(e); },
  "open-ip": (t, ev) => { ev.preventDefault(); ipDrawer(t.dataset.ip); },
  "block-ip": async t => { const r = await api("/api/block", { ip: t.dataset.ip, minutes: 30 }); toast(esc(r.message || r.error)); ipDrawer(t.dataset.ip); },
  unblock: async t => { await api("/api/unblock", { ip: t.dataset.ip }); toast("Unblocked " + esc(t.dataset.ip)); closeDrawer(); route(); },
  "protect-ip": async t => { await api("/api/whitelist", { cidr: t.dataset.ip, note: "protected from the dashboard" }); toast("This address will never be blocked."); ipDrawer(t.dataset.ip); },
  "add-mine": async () => { const r = await api("/api/whitelist/mine", {}); toast("Protected " + esc(r.ip)); S.me.protected = true; route(); },
  "block-manual": async () => { const r = await api("/api/block", { ip: $("#blk-ip").value, minutes: 30 }); toast(esc(r.message || r.error)); route(); },
  panic: async () => { if (!confirm("Remove every block right now?")) return; const r = await api("/api/unblock_all", {}); toast("Released " + r.unblocked + " address(es)."); route(); },
  "set-mode": t => setMode(t.dataset.mode),
  copy: async t => { const txt = $("#" + t.dataset.target).textContent; try { await navigator.clipboard.writeText(txt); } catch (e) { const r = document.createRange(); r.selectNode($("#" + t.dataset.target)); getSelection().removeAllRanges(); getSelection().addRange(r); document.execCommand("copy"); } t.textContent = "Copied"; setTimeout(() => (t.textContent = "Copy"), 1500); },
  tab: t => { $$(".tabs button").forEach(b => b.classList.toggle("on", b === t)); $$(".tabc").forEach(c => (c.style.display = c.id === "tab-" + t.dataset.tab ? "" : "none")); },
  revoke: async t => { if (!confirm("Remove " + t.dataset.name + "? It will stop being able to report.")) return; await api("/api/agents/" + encodeURIComponent(t.dataset.id), undefined, "DELETE"); pageAgents(); },
  scenario: async t => {
    t.disabled = true; const r = await api("/api/sim/run", { scenario: t.dataset.id }); t.disabled = false;
    $("#sim-result").innerHTML = `<div class="result"><b>${esc(r.label)}</b> <span class="dim">from ${esc(r.ip || "no address")} · ${esc(r.mode)} mode</span><p>${esc(r.story)}</p><p><b>Result:</b> ${esc({ alert_only: "Logged only. Not serious enough to block.", would_block: "Shadow mode: it would have been blocked.", blocked: "Blocked in the firewall " + (r.note || ""), skip_protected: "Not blocked: protected address.", already_blocked: "Already blocked.", dedup: "Already handled.", rate_limited: "Safety limit reached.", block_failed: "Block failed: " + r.note }[r.decision] || r.decision)}</p><p class="dim small">Open Overview to watch it travel through the pipeline, or Alerts to see the full explanation.</p></div>`;
  },
  "refresh-lab": async () => { $("#lab-report").innerHTML = labReportHTML(await api("/api/sim/report")); },
  selftest: async t => { t.disabled = true; $("#st-wait").innerHTML = '<span class="spin"></span>Testing every function...'; const r = await api("/api/selftest", {}); t.disabled = false; $("#st-wait").textContent = ""; $("#st-result").innerHTML = selftestHTML(r); },
  "save-settings": saveSettings,
  "test-notify": async t => { $("#save-msg").textContent = "Sending..."; await saveSettings(); const r = await api("/api/notify/test", { channel: t.dataset.ch }); $("#save-msg").textContent = (r.ok ? "Sent. Check your " + t.dataset.ch + "." : "Failed: " + r.detail); },
  "wl-add": async () => { const r = await api("/api/whitelist", { cidr: $("#wl-new").value, note: $("#wl-note").value }); if (r.error) toast(esc(r.error)); else pageSettings(); },
  "wl-del": async t => { await api("/api/whitelist/" + t.dataset.id, undefined, "DELETE"); pageSettings(); },
  "intel-update": async () => { const r = await api("/api/intel/update", {}); toast(esc(r.message)); },
  "intel-add": async () => { const r = await api("/api/intel/custom", { ip: $("#intel-ip").value }); toast(r.error ? esc(r.error) : "Added to your threat list."); },
  "regen-enroll": async () => { await api("/api/enrollment/regenerate", {}); toast("New enrollment password created. The Agents page shows the new install command."); },
  "change-pw": async () => { const r = await api("/api/password", { current: $("#pw-cur").value, new: $("#pw-new").value }); toast(r.ok ? "Password changed." : esc(r.error)); },
  "load-more": () => loadAlerts(false),
  logout: async () => { await api("/api/logout", {}); location.href = "/login"; },
};
document.addEventListener("click", e => { const t = e.target.closest("[data-act]"); if (t && ACT[t.dataset.act]) { if (t.tagName === "A" && !t.getAttribute("href").startsWith("#")) return; ACT[t.dataset.act](t, e); } });
$("#scrim").addEventListener("click", closeDrawer);
document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

/* ---------- routing, live stream, badges ---------- */
const PAGES = { overview: pageOverview, alerts: pageAlerts, blocked: pageBlocked, agents: pageAgents, simulator: pageSimulator, setup: pageSetup, settings: pageSettings };
async function route() {
  const name = location.hash.replace("#/", "") || "overview";
  S.page = PAGES[name] ? name : "overview";
  $$("nav a.tab").forEach(a => a.classList.toggle("on", a.dataset.page === S.page));
  closeDrawer();
  try { await PAGES[S.page](); } catch (e) { $("#view").innerHTML = `<p class="dim">Could not load this page: ${esc(e.message)}</p>`; console.error(e); }
}
async function loadOverview(refreshPage) {
  S.ov = await api("/api/overview"); navBadges();
  if (refreshPage && S.page === "overview") pageOverview();
}
function navBadges() {
  const o = S.ov; if (!o) return;
  const set = (p, n) => { const a = $(`nav a[data-page=${p}]`); if (!a) return; let b = $(".badge-n", a); if (!n) { if (b) b.remove(); return; } if (!b) { b = document.createElement("span"); b.className = "badge-n"; a.appendChild(b); } b.textContent = n; };
  set("blocked", o.counts.blocked); set("setup", o.health.fails + o.health.warns);
}
let _liveTimer;
function startStream() {
  if (S.sse) S.sse.close();
  const es = (S.sse = new EventSource("/api/stream"));
  es.addEventListener("event", m => {
    const e = JSON.parse(m.data); S.events.set(e.id, e);
    if (S.page === "overview") {
      const tb = $("#feed tbody"); if (tb) { if (tb.querySelector(".dim") && !tb.querySelector("tr.click")) tb.innerHTML = ""; tb.insertAdjacentHTML("afterbegin", feedRow(e, true)); while (tb.rows.length > 14) tb.deleteRow(-1); }
      fireDot(e.severity);
    }
    if (S.page === "alerts" && !Object.values(S.filters).some(Boolean)) { const tb = $("#alist"); if (tb) tb.insertAdjacentHTML("afterbegin", feedRow(e, true)); }
    if (e.severity === "high") { toast(`<b>${esc(e.title)}</b><div class="small">${esc(e.explain)}</div><div class="dim small">${esc(e.decision_text)}</div>`, "high"); beep(); }
    clearTimeout(_liveTimer); _liveTimer = setTimeout(() => loadOverview(S.page === "overview"), 1500);
  });
  es.addEventListener("action", () => { clearTimeout(_liveTimer); _liveTimer = setTimeout(() => loadOverview(S.page === "overview" || S.page === "blocked"), 800); if (S.page === "blocked") pageBlocked(); });
  es.addEventListener("tick", m => { if (S.page === "overview") { const p = $("#pipe"); if (p) p.innerHTML = pipeHTML(JSON.parse(m.data).flow); } });
}

(async function init() {
  S.me = await api("/api/me");
  if (!S.me.version) return;
  $("#who").textContent = "Signed in from " + S.me.ip;
  window.addEventListener("hashchange", route);
  await route(); startStream(); loadOverview(false);
  setInterval(() => loadOverview(S.page === "overview" && !document.hidden), 30000);
  window.addEventListener("resize", () => { clearTimeout(S._rs); S._rs = setTimeout(() => S.page === "overview" && S.ov && (drawChart(S.ov.series), drawMap(S.ov.map)), 200); });
})();
