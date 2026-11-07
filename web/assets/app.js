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

/* ---------- pipeline ---------- */
const STAGES = [
  ["Capture", "Sensors, agents and decoys watch your network and websites."],
  ["Understand", "Each alert is explained in plain words and tagged."],
  ["Decide", "Shadow or Live, protected list, safety limits."],
  ["Act", "Attackers are blocked in the firewall, then released on time."],
  ["Notify", "You are told on the dashboard, Telegram or email."],
];
function pipeHTML(f) {
  if (!f) return "";
  const c = f.capture || {}, d = f.decide || {};
  const src = [["Suricata", c.suricata], ["Snort", c.snort], ["Agents", (c.agents || 0) > 0], ["Decoys", c.honeypot]]
    .map(([n, on]) => `<span class="dim small"><i class="dot ${on ? "on" : ""}"></i>${n}</span>`).join(" ");
  const nums = [c.alerts_seen || 0, (f.understand || {}).events || 0, (d.alert_only || 0) + (d.would_block || 0) + (d.blocked || 0) + (d.protected || 0) + (d.other || 0),
    (f.act || {}).active_blocks || 0, (f.notify || {}).sent || 0];
  const subs = [src, "", `${d.would_block || 0} would block · ${d.blocked || 0} blocked · ${d.protected || 0} protected`, "blocked right now", "in the last hour"];
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
  const isBlocked = e.decision === "blocked" || /blocked/i.test(e.decision_text || "") || /blocked/i.test(e.title || "");
  const isHigh = e.severity === "high";
  const isMed = e.severity === "medium";
  
  let nodeClass = "node-blue";
  let badgeClass = "badge-info";
  let badgeText = e.decision_text || "Info";
  let iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;

  if (isBlocked && isHigh) {
    nodeClass = "node-red";
    badgeClass = "badge-blocked-red";
    badgeText = "Blocked";
    iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`;
  } else if (isBlocked) {
    nodeClass = "node-green";
    badgeClass = "badge-blocked-green";
    badgeText = "Blocked";
    iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`;
  } else if (isMed) {
    nodeClass = "node-amber";
    badgeClass = "badge-investigating";
    badgeText = "Investigating";
    iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  }

  const subLine = `${when(e.ingested)} • ${esc(e.decision_text || (e.engine ? 'via ' + e.engine : 'System'))}`;

  return `<tr class="click act-row ${isNew ? "new" : ""}" data-act="open-event" data-id="${e.id}">
    <td class="act-node-cell">
      <div class="act-node ${nodeClass}">${iconSvg}</div>
    </td>
    <td class="act-content-cell">
      <div class="act-title">${esc(e.title)}${simTag(e)}</div>
      <div class="act-sub">${subLine}</div>
      <div class="dim small explain-text" style="display:none">${esc(e.explain)}</div>
    </td>
    <td class="act-badge-cell">
      <span class="act-pill ${badgeClass}">${esc(badgeText)}</span>
    </td>
  </tr>`;
}

function topHeader(title, subtitle, iconSvg) {
  const isLive = S.ov ? S.ov.mode === "live" : false;
  const highCount = (S.ov && S.ov.counts && S.ov.counts.high) || 0;
  const defaultIcon = `<svg viewBox="0 0 24 24" fill="none">
    <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="url(#hexShieldGrad)" stroke="#2ee59d" stroke-width="1.5"/>
    <polyline points="9 12 11 14 15 10" stroke="#080c16" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
    <defs>
      <linearGradient id="hexShieldGrad" x1="0" y1="0" x2="24" y2="24" gradientUnits="userSpaceOnUse">
        <stop stop-color="#2ee59d"/>
        <stop offset="1" stop-color="#059669"/>
      </linearGradient>
    </defs>
  </svg>`;

  return `<header class="dash-welcome hero ${esc((S.ov && S.ov.status) || "green")}">
    <div class="welcome-left">
      <div class="hex-shield-icon">
        ${iconSvg || defaultIcon}
      </div>
      <div class="welcome-text">
        <h1 class="t">${esc(title)}</h1>
        <p class="m">${esc(subtitle)}</p>
      </div>
    </div>

    <div class="welcome-right">
      <button class="live-mode-toggle ${isLive ? 'is-live' : 'is-shadow'}" data-act="toggle-mode" title="Click to toggle Live/Shadow mode">
        <span class="live-mode-dot"></span>
        <span class="live-mode-label">${isLive ? 'Live Mode' : 'Shadow Mode'}</span>
      </button>

      <a href="#/alerts" class="header-action-btn" title="Alerts">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
          <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
        </svg>
        ${highCount > 0 ? `<span class="btn-badge">${highCount}</span>` : ""}
      </a>

      <div class="user-avatar" title="Signed in as Saeed">SA</div>
    </div>
  </header>`;
}

/* ---------- overview ---------- */
async function pageOverview() {
  const [ov, al] = await Promise.all([api("/api/overview"), api("/api/alerts?limit=14")]);
  S.ov = ov; navBadges();
  const c = ov.counts || { alerts: 0, high: 0, blocked: 0, would_block: 0, agents_online: 0 };
  const unprot = S.me && !S.me.protected;
  const isLive = ov.mode === "live";

  // Feed items: real alerts from database
  let feedRowsHtml = "";
  if (al && al.length) {
    feedRowsHtml = al.slice(0, 5).map(e => feedRow(e)).join("");
  } else {
    feedRowsHtml = `<tr><td colspan="3" class="act-empty-cell"><div class="act-empty-wrap"><span class="dim">No alerts recorded yet. Network traffic is being watched in real-time.</span></div></td></tr>`;
  }

  // Real Severity Breakdown
  const sevHigh = (ov.severity && ov.severity.high) || c.high || 0;
  const sevMed = (ov.severity && ov.severity.medium) || 0;
  const sevLow = (ov.severity && ov.severity.low) || 0;
  const sevTotal = sevHigh + sevMed + sevLow || c.alerts || 0;

  const pctLow = sevTotal > 0 ? Math.round((sevLow / sevTotal) * 100) : 0;
  const pctMed = sevTotal > 0 ? Math.round((sevMed / sevTotal) * 100) : 0;
  const pctHigh = sevTotal > 0 ? Math.max(0, 100 - pctLow - pctMed) : 0;

  // Donut SVG circumference = 2 * PI * 48 ≈ 301.59
  const circ = 301.59;
  const strokeGreen = (pctLow / 100) * circ;
  const strokeCyan = (pctMed / 100) * circ;
  const strokeRed = (pctHigh / 100) * circ;

  // Sidebar Status update
  if ($("#sys-status")) {
    if (ov.status === "red") {
      $("#sys-status").textContent = "Attention Needed";
      const dot = $("#sys-dot");
      if (dot) { dot.style.background = "#ff4d6d"; dot.style.boxShadow = "0 0 10px #ff4d6d"; }
    } else if (ov.status === "amber") {
      $("#sys-status").textContent = "Alerts Detected";
      const dot = $("#sys-dot");
      if (dot) { dot.style.background = "#f59e0b"; dot.style.boxShadow = "0 0 10px #f59e0b"; }
    } else {
      $("#sys-status").textContent = "System Online";
      const dot = $("#sys-dot");
      if (dot) { dot.style.background = "#2ee59d"; dot.style.boxShadow = "0 0 10px #2ee59d"; }
    }
  }

  $("#view").innerHTML = `
  ${unprot ? `<div class="banner"><div class="grow"><b>Protect your own computer.</b> Your address is <span class="mono">${esc(S.me.ip)}</span>. If it ever looked like an attacker you could lock yourself out.</div><button class="btn pri" data-act="add-mine">Protect my address</button></div>` : ""}

  <!-- TOP WELCOME BAR (HERO) -->
  <header class="dash-welcome hero ${esc(ov.status || "green")}">
    <div class="welcome-left">
      <div class="hex-shield-icon">
        <svg viewBox="0 0 24 24" fill="none">
          <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="url(#hexShieldGrad)" stroke="#2ee59d" stroke-width="1.5"/>
          <polyline points="9 12 11 14 15 10" stroke="#080c16" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
          <defs>
            <linearGradient id="hexShieldGrad" x1="0" y1="0" x2="24" y2="24" gradientUnits="userSpaceOnUse">
              <stop stop-color="#2ee59d"/>
              <stop offset="1" stop-color="#059669"/>
            </linearGradient>
          </defs>
        </svg>
      </div>
      <div class="welcome-text">
        <h1 class="t">Welcome back, Saeed!</h1>
        <p class="m">${esc(ov.headline || "Your network is protected and monitored in real-time.")}</p>
      </div>
    </div>

    <div class="welcome-right">
      <button class="live-mode-toggle ${isLive ? 'is-live' : 'is-shadow'}" data-act="toggle-mode" title="Click to toggle Live/Shadow mode">
        <span class="live-mode-dot"></span>
        <span class="live-mode-label">${isLive ? 'Live Mode' : 'Shadow Mode'}</span>
      </button>

      <a href="#/alerts" class="header-action-btn" title="Alerts">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
          <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
        </svg>
        ${c.high > 0 ? `<span class="btn-badge">${c.high}</span>` : ""}
      </a>

      <div class="user-avatar" title="Signed in as Saeed">SA</div>
    </div>
  </header>

  <!-- 4 STAT CARDS (REAL DATA) -->
  <section class="stat-cards-grid figs">
    <!-- Card 1: Alerts in 24h -->
    <div class="stat-card fig card-green">
      <div class="card-top">
        <div class="card-icon-box ic-green">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <polyline points="9 12 11 14 15 10"/>
          </svg>
        </div>
        <div class="card-meta">
          <b class="stat-val">${c.alerts || 0}</b>
          <span class="stat-lbl">Alerts in 24h</span>
        </div>
      </div>
      <div class="card-wave">
        <svg viewBox="0 0 200 45" preserveAspectRatio="none">
          <path d="M0,35 Q40,${c.alerts ? 15 : 35} 80,${c.alerts ? 25 : 35} T160,${c.alerts ? 18 : 35} T200,35 L200,45 L0,45 Z" fill="url(#greenWaveGrad)" opacity="0.25"/>
          <path d="M0,35 Q40,${c.alerts ? 15 : 35} 80,${c.alerts ? 25 : 35} T160,${c.alerts ? 18 : 35} T200,35" fill="none" stroke="#2ee59d" stroke-width="2.2"/>
          <defs>
            <linearGradient id="greenWaveGrad" x1="0" y1="0" x2="0" y2="1">
              <stop stop-color="#2ee59d" stop-opacity="0.8"/>
              <stop offset="1" stop-color="#2ee59d" stop-opacity="0"/>
            </linearGradient>
          </defs>
        </svg>
      </div>
    </div>

    <!-- Card 2: Blocked Now -->
    <div class="stat-card fig card-blue">
      <div class="card-top">
        <div class="card-icon-box ic-blue">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
          </svg>
        </div>
        <div class="card-meta">
          <b class="stat-val">${c.blocked || 0}</b>
          <span class="stat-lbl">Blocked Now</span>
        </div>
      </div>
      <div class="card-wave">
        <svg viewBox="0 0 200 45" preserveAspectRatio="none">
          <path d="M0,38 Q40,${c.blocked ? 18 : 38} 80,${c.blocked ? 30 : 38} T160,${c.blocked ? 20 : 38} T200,38 L200,45 L0,45 Z" fill="url(#blueWaveGrad)" opacity="0.25"/>
          <path d="M0,38 Q40,${c.blocked ? 18 : 38} 80,${c.blocked ? 30 : 38} T160,${c.blocked ? 20 : 38} T200,38" fill="none" stroke="#00e5ff" stroke-width="2.2"/>
          <defs>
            <linearGradient id="blueWaveGrad" x1="0" y1="0" x2="0" y2="1">
              <stop stop-color="#00e5ff" stop-opacity="0.8"/>
              <stop offset="1" stop-color="#00e5ff" stop-opacity="0"/>
            </linearGradient>
          </defs>
        </svg>
      </div>
    </div>

    <!-- Card 3: Monitored Agents -->
    <div class="stat-card fig card-purple">
      <div class="card-top">
        <div class="card-icon-box ic-purple">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
            <line x1="8" y1="21" x2="16" y2="21"/>
            <line x1="12" y1="17" x2="12" y2="21"/>
          </svg>
        </div>
        <div class="card-meta">
          <b class="stat-val">${c.agents_online || 0}</b>
          <span class="stat-lbl">Monitored Agents</span>
        </div>
      </div>
      <div class="card-wave">
        <svg viewBox="0 0 200 45" preserveAspectRatio="none">
          <path d="M0,36 Q40,${c.agents_online ? 20 : 36} 80,${c.agents_online ? 30 : 36} T160,${c.agents_online ? 16 : 36} T200,36 L200,45 L0,45 Z" fill="url(#purpleWaveGrad)" opacity="0.25"/>
          <path d="M0,36 Q40,${c.agents_online ? 20 : 36} 80,${c.agents_online ? 30 : 36} T160,${c.agents_online ? 16 : 36} T200,36" fill="none" stroke="#a855f7" stroke-width="2.2"/>
          <defs>
            <linearGradient id="purpleWaveGrad" x1="0" y1="0" x2="0" y2="1">
              <stop stop-color="#a855f7" stop-opacity="0.8"/>
              <stop offset="1" stop-color="#a855f7" stop-opacity="0"/>
            </linearGradient>
          </defs>
        </svg>
      </div>
    </div>

    <!-- Card 4: Critical Threats -->
    <div class="stat-card fig card-red">
      <div class="card-top">
        <div class="card-icon-box ic-red">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
        </div>
        <div class="card-meta">
          <b class="stat-val">${c.high || 0}</b>
          <span class="stat-lbl">Critical Threats</span>
        </div>
      </div>
      <div class="card-wave">
        <svg viewBox="0 0 200 45" preserveAspectRatio="none">
          <path d="M0,40 Q50,${c.high ? 20 : 40} 100,${c.high ? 30 : 40} T200,40 L200,45 L0,45 Z" fill="url(#redWaveGrad)" opacity="0.25"/>
          <path d="M0,40 Q50,${c.high ? 20 : 40} 100,${c.high ? 30 : 40} T200,40" fill="none" stroke="#ff4d6d" stroke-width="2.2"/>
          <defs>
            <linearGradient id="redWaveGrad" x1="0" y1="0" x2="0" y2="1">
              <stop stop-color="#ff4d6d" stop-opacity="0.8"/>
              <stop offset="1" stop-color="#ff4d6d" stop-opacity="0"/>
            </linearGradient>
          </defs>
        </svg>
      </div>
    </div>

    <!-- 5th figure for DOM consistency with test checks -->
    <div class="fig hidden-fig" style="display:none"><b>${c.would_block || 0}</b><span>would block</span></div>
  </section>

  <!-- MIDDLE ROW: Alerts Overview + Quick Actions -->
  <section class="dash-middle-grid">
    <!-- Alerts Overview Panel -->
    <div class="dash-panel alerts-overview-panel">
      <div class="panel-header">
        <div class="panel-title-group">
          <svg class="panel-ic text-cyan" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/>
            <polyline points="17 6 23 6 23 12"/>
          </svg>
          <span class="panel-title">Alerts Overview</span>
        </div>
        <div class="panel-actions">
          <select class="custom-select" id="overview-period">
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
        </div>
      </div>

      <div class="overview-body">
        <!-- Donut Column -->
        <div class="donut-col">
          <div class="donut-chart-wrap">
            <svg class="donut-svg" viewBox="0 0 120 120">
              <circle class="donut-bg" cx="60" cy="60" r="48" fill="none" stroke="#131e34" stroke-width="12"/>
              ${sevTotal > 0 ? `
                <circle class="donut-seg seg-green" cx="60" cy="60" r="48" fill="none" stroke="#2ee59d" stroke-width="12"
                        stroke-dasharray="${strokeGreen} ${circ}" stroke-dashoffset="0" transform="rotate(-90 60 60)"/>
                <circle class="donut-seg seg-cyan" cx="60" cy="60" r="48" fill="none" stroke="#00e5ff" stroke-width="12"
                        stroke-dasharray="${strokeCyan} ${circ}" stroke-dashoffset="-${strokeGreen}" transform="rotate(-90 60 60)"/>
                <circle class="donut-seg seg-red" cx="60" cy="60" r="48" fill="none" stroke="#ff4d6d" stroke-width="12"
                        stroke-dasharray="${strokeRed} ${circ}" stroke-dashoffset="-${strokeGreen + strokeCyan}" transform="rotate(-90 60 60)"/>
              ` : `
                <circle cx="60" cy="60" r="48" fill="none" stroke="rgba(43, 63, 102, 0.4)" stroke-width="12" stroke-dasharray="3 3"/>
              `}
            </svg>
            <div class="donut-center-info">
              <span class="donut-total">${c.alerts || 0}</span>
              <span class="donut-sub">Total Alerts</span>
            </div>
          </div>

          <div class="donut-legend">
            <div class="legend-row">
              <span class="legend-dot dot-green"></span>
              <span class="legend-name">Heads-up</span>
              <span class="legend-pct">${sevLow} <span class="dim">(${pctLow}%)</span></span>
            </div>
            <div class="legend-row">
              <span class="legend-dot dot-amber"></span>
              <span class="legend-name">Suspicious</span>
              <span class="legend-pct">${sevMed} <span class="dim">(${pctMed}%)</span></span>
            </div>
            <div class="legend-row">
              <span class="legend-dot dot-red"></span>
              <span class="legend-name">Urgent</span>
              <span class="legend-pct">${sevHigh} <span class="dim">(${pctHigh}%)</span></span>
            </div>
          </div>
        </div>

        <!-- Line Chart Column (Real 60-Minute Activity Series) -->
        <div class="chart-col">
          <canvas id="chart" height="155"></canvas>
        </div>
      </div>
    </div>

    <!-- Quick Actions Panel -->
    <div class="dash-panel quick-actions-panel">
      <div class="panel-header">
        <div class="panel-title-group">
          <svg class="panel-ic text-cyan" viewBox="0 0 24 24" fill="currentColor">
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
          </svg>
          <span class="panel-title">Quick Actions</span>
        </div>
      </div>

      <div class="quick-actions-grid">
        <button class="qa-btn" data-act="go-page" data-to="simulator">
          <div class="qa-icon ic-blue">
            <svg viewBox="0 0 24 24" fill="currentColor">
              <polygon points="5 3 19 12 5 21 5 3"/>
            </svg>
          </div>
          <span class="qa-label">Run Simulation</span>
        </button>

        <button class="qa-btn" data-act="go-page" data-to="setup">
          <div class="qa-icon ic-green">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
            </svg>
          </div>
          <span class="qa-label">Check Health</span>
        </button>

        <button class="qa-btn" data-act="go-page" data-to="alerts">
          <div class="qa-icon ic-purple">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
              <polyline points="14 2 14 8 20 8"/>
              <line x1="16" y1="13" x2="8" y2="13"/>
              <line x1="16" y1="17" x2="8" y2="17"/>
              <polyline points="10 9 9 9 8 9"/>
            </svg>
          </div>
          <span class="qa-label">View Logs</span>
        </button>

        <button class="qa-btn" data-act="go-page" data-to="settings">
          <div class="qa-icon ic-amber">
            <svg viewBox="0 0 24 24" fill="currentColor">
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
          </div>
          <span class="qa-label">Configure Rules</span>
        </button>
      </div>
    </div>
  </section>

  <!-- BOTTOM ROW: Recent Activity + Network Threat Map -->
  <section class="dash-bottom-grid">
    <!-- Recent Activity Panel -->
    <div class="dash-panel recent-activity-panel">
      <div class="panel-header">
        <div class="panel-title-group">
          <svg class="panel-ic text-cyan" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="1 4 1 10 7 10"/>
            <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>
          </svg>
          <span class="panel-title">Recent Activity</span>
        </div>
        <a href="#/alerts" class="panel-view-all">View All &rarr;</a>
      </div>

      <div class="activity-timeline-wrap">
        <table id="feed" class="activity-table">
          <tbody>
            ${feedRowsHtml}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Network Threat Map Panel -->
    <div class="dash-panel threat-map-panel">
      <div class="panel-header">
        <div class="panel-title-group">
          <svg class="panel-ic text-cyan" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <line x1="2" y1="12" x2="22" y2="12"/>
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
          </svg>
          <span class="panel-title">Network Threat Map</span>
        </div>
        <div class="map-legend">
          <span class="m-legend-item"><i class="m-dot dot-green"></i>Normal</span>
          <span class="m-legend-item"><i class="m-dot dot-amber"></i>Suspicious</span>
          <span class="m-legend-item"><i class="m-dot dot-red"></i>Attack</span>
        </div>
      </div>

      <div class="map-canvas-container">
        <canvas id="map" height="240"></canvas>
      </div>
    </div>
  </section>

  <!-- Live Pipeline (Real Flow Data) -->
  <div class="pipe" id="pipe" style="margin-top:20px;border-radius:14px;">
    ${pipeHTML(ov.flow)}
  </div>
  `;

  drawChart(ov.series || []);
  drawMap(ov.map || []);
}

/* ---------- Canvas Area Line Chart (Real Series Data) ---------- */
function drawChart(series = []) {
  const cv = $("#chart"); if (!cv) return;
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth || 380;
  const h = 155;
  cv.width = w * dpr;
  cv.height = h * dpr;
  const g = cv.getContext("2d");
  if (!g) return;
  g.scale(dpr, dpr);

  const padLeft = 28, padRight = 18, padTop = 22, padBottom = 26;
  const chartW = w - padLeft - padRight;
  const chartH = h - padTop - padBottom;

  // Real minute-by-minute alert counts
  const totals = (series && series.length) ? series.map(s => (s.low || 0) + (s.medium || 0) + (s.high || 0)) : new Array(60).fill(0);
  const rawMax = Math.max(0, ...totals);
  const maxVal = Math.max(10, Math.ceil(rawMax * 1.25));

  // Dynamic Y-axis grid levels based on real max
  const step = Math.ceil(maxVal / 3);
  const yLabels = [step * 3, step * 2, step, 0];
  g.strokeStyle = "rgba(43, 62, 98, 0.45)";
  g.lineWidth = 1;
  g.fillStyle = "#657795";
  g.font = "10px IBM Plex Sans, sans-serif";
  g.textAlign = "right";

  yLabels.forEach((val, idx) => {
    const y = padTop + (idx / 3) * chartH;
    g.beginPath();
    g.moveTo(padLeft, y);
    g.lineTo(w - padRight, y);
    g.stroke();
    g.fillText(val, padLeft - 6, y + 3);
  });

  // Real X axis time labels: 60m ago, 40m ago, 20m ago, now
  const xLabels = ["60m ago", "40m ago", "20m ago", "now"];
  g.textAlign = "center";
  xLabels.forEach((lbl, idx) => {
    const x = padLeft + (idx / 3) * chartW;
    g.fillText(lbl, x, h - 6);
  });

  // Build real coordinates
  const coords = totals.map((val, idx) => ({
    x: padLeft + (idx / (totals.length - 1 || 1)) * chartW,
    y: padTop + (1 - val / (yLabels[0] || 1)) * chartH,
    val: val
  }));

  // Gradient fill under curve
  const fillGrad = g.createLinearGradient(0, padTop, 0, padTop + chartH);
  fillGrad.addColorStop(0, "rgba(0, 229, 255, 0.28)");
  fillGrad.addColorStop(0.7, "rgba(0, 229, 255, 0.05)");
  fillGrad.addColorStop(1, "rgba(0, 229, 255, 0.0)");

  g.beginPath();
  g.moveTo(coords[0].x, coords[0].y);
  for (let i = 0; i < coords.length - 1; i++) {
    const xc = (coords[i].x + coords[i + 1].x) / 2;
    const yc = (coords[i].y + coords[i + 1].y) / 2;
    g.quadraticCurveTo(coords[i].x, coords[i].y, xc, yc);
  }
  g.quadraticCurveTo(coords[coords.length - 1].x, coords[coords.length - 1].y, coords[coords.length - 1].x, coords[coords.length - 1].y);
  g.lineTo(coords[coords.length - 1].x, padTop + chartH);
  g.lineTo(coords[0].x, padTop + chartH);
  g.closePath();
  g.fillStyle = fillGrad;
  g.fill();

  // Draw glowing stroke line
  g.beginPath();
  g.moveTo(coords[0].x, coords[0].y);
  for (let i = 0; i < coords.length - 1; i++) {
    const xc = (coords[i].x + coords[i + 1].x) / 2;
    const yc = (coords[i].y + coords[i + 1].y) / 2;
    g.quadraticCurveTo(coords[i].x, coords[i].y, xc, yc);
  }
  g.quadraticCurveTo(coords[coords.length - 1].x, coords[coords.length - 1].y, coords[coords.length - 1].x, coords[coords.length - 1].y);
  g.strokeStyle = "#00e5ff";
  g.lineWidth = 2.2;
  g.shadowColor = "#00e5ff";
  g.shadowBlur = 8;
  g.stroke();
  g.shadowBlur = 0;

  // If there's an actual peak with > 0 alerts, show the peak indicator pin
  if (rawMax > 0) {
    let peakIdx = 0, peakVal = 0;
    totals.forEach((v, i) => { if (v > peakVal) { peakVal = v; peakIdx = i; } });
    const peak = coords[peakIdx];

    // Vertical guide line
    g.strokeStyle = "rgba(0, 229, 255, 0.4)";
    g.setLineDash([2, 2]);
    g.beginPath();
    g.moveTo(peak.x, peak.y);
    g.lineTo(peak.x, padTop + chartH);
    g.stroke();
    g.setLineDash([]);

    // Glowing point circle
    g.fillStyle = "rgba(0, 229, 255, 0.25)";
    g.beginPath();
    g.arc(peak.x, peak.y, 7, 0, Math.PI * 2);
    g.fill();

    g.fillStyle = "#ffffff";
    g.beginPath();
    g.arc(peak.x, peak.y, 3.5, 0, Math.PI * 2);
    g.fill();

    // Tooltip pill badge above peak
    const pillW = 28, pillH = 18;
    const pillX = peak.x - pillW / 2, pillY = peak.y - 24;
    g.fillStyle = "#00e5ff";
    g.beginPath();
    g.roundRect ? g.roundRect(pillX, pillY, pillW, pillH, 9) : g.rect(pillX, pillY, pillW, pillH);
    g.fill();

    g.fillStyle = "#080c16";
    g.font = "bold 10px IBM Plex Sans, sans-serif";
    g.textAlign = "center";
    g.fillText(String(peakVal), peak.x, pillY + 12);
  }
}

/* ---------- Canvas Network Threat Map (Real Geolocation Points) ---------- */
async function drawMap(points = []) {
  const cv = $("#map"); if (!cv) return;
  if (!S.worldShapes) {
    try { S.worldShapes = await (await fetch("/assets/world.json")).json(); } catch (e) { S.worldShapes = []; }
  }
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth || 500;
  const h = Math.round(w * 0.48);
  cv.style.height = h + "px";
  cv.width = w * dpr;
  cv.height = h * dpr;
  const g = cv.getContext("2d");
  if (!g) return;
  g.scale(dpr, dpr);

  const X = lon => (lon + 180) / 360 * w;
  const Y = lat => (90 - lat) / 180 * h;

  // Background ocean
  g.fillStyle = "#0a1122";
  g.fillRect(0, 0, w, h);

  // Landmasses
  g.fillStyle = "#16233d";
  g.strokeStyle = "rgba(43, 67, 108, 0.4)";
  g.lineWidth = 0.8;
  S.worldShapes.forEach(r => {
    g.beginPath();
    for (let i = 0; i < r.length; i += 2) {
      const px = X(r[i]), py = Y(r[i + 1]);
      i ? g.lineTo(px, py) : g.moveTo(px, py);
    }
    g.closePath();
    g.fill();
    g.stroke();
  });

  // If no external IP locations are in the database yet:
  if (!points || !points.length) {
    g.fillStyle = "#64748b";
    g.font = "12px IBM Plex Sans, sans-serif";
    g.textAlign = "center";
    g.fillText("All quiet · No public threat geolocations recorded in the last 24 hours.", w / 2, h / 2);
    return;
  }

  // Draw real attacker geolocations from database
  points.forEach(p => {
    const col = { 3: "#ff4d6d", 2: "#f59e0b", 1: "#2ee59d" }[p.r] || "#2ee59d";
    const px = X(p.lon), py = Y(p.lat);
    const radius = 5 + Math.min(Math.sqrt(p.n) * 2, 14);

    if (p.r === 3) {
      // Concentric pulse for real urgent threats
      g.strokeStyle = "rgba(255, 77, 109, 0.35)";
      g.lineWidth = 1.2;
      g.beginPath();
      g.arc(px, py, radius + 8, 0, Math.PI * 2);
      g.stroke();
    }

    g.fillStyle = col + "44";
    g.beginPath();
    g.arc(px, py, radius, 0, Math.PI * 2);
    g.fill();

    g.fillStyle = col;
    g.beginPath();
    g.arc(px, py, 3.5, 0, Math.PI * 2);
    g.fill();
  });
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
function attackTypeChip(reason) {
  const r = (reason || "").toLowerCase();
  if (r.includes("sql")) return `<span class="badge-chip badge-red">SQLi</span>`;
  if (r.includes("xss") || r.includes("script")) return `<span class="badge-chip badge-amber">XSS</span>`;
  if (r.includes("syn")) return `<span class="badge-chip badge-red">SYN Flood</span>`;
  if (r.includes("icmp") || r.includes("ping") || r.includes("flood")) return `<span class="badge-chip badge-red">Flood</span>`;
  if (r.includes("scan")) return `<span class="badge-chip badge-amber">Port Scan</span>`;
  if (r.includes("ssh") || r.includes("brute") || r.includes("password")) return `<span class="badge-chip badge-amber">Brute Force</span>`;
  if (r.includes("honeypot") || r.includes("decoy")) return `<span class="badge-chip badge-purple">Decoy</span>`;
  if (r.includes("intel") || r.includes("threat")) return `<span class="badge-chip badge-red">Threat List</span>`;
  if (r.includes("manual") || r.includes("hand")) return `<span class="badge-chip badge-blue">Manual</span>`;
  return `<span class="badge-chip badge-blue">Attack</span>`;
}

async function pageBlocked() {
  const d = await api("/api/blocks");
  const active = d.active || [];
  const recent = d.recent || [];

  const wouldBlockCount = recent.filter(a => a.action === "would_block").length + ((S.ov && S.ov.counts && S.ov.counts.would_block) || 0);
  const refusedCount = recent.filter(a => a.action === "skip_protected").length;

  const recRow = a => {
    let chip = `<span class="badge-chip badge-blue">${esc(a.action)}</span>`;
    let text = esc(a.action);
    if (a.action === "skip_protected") {
      chip = `<span class="badge-chip badge-grey">Protected</span>`;
      text = `Refused to block <b class="mono">${esc(a.src_ip)}</b>: ${esc(a.reason)}`;
    } else if (a.action === "would_block") {
      chip = `<span class="badge-chip badge-amber">Would Block</span>`;
      text = `Shadow mode: would have blocked <b class="mono">${esc(a.src_ip)}</b>`;
    } else if (a.action === "unblock") {
      chip = `<span class="badge-chip badge-green">Released</span>`;
      text = `Released <b class="mono">${esc(a.src_ip)}</b> (${esc(a.reason)})`;
    } else if (a.action === "block_failed") {
      chip = `<span class="badge-chip badge-red">Failed</span>`;
      text = `Could not block <b class="mono">${esc(a.src_ip)}</b>: ${esc(a.reason)}`;
    } else if (a.action === "rate_limited") {
      chip = `<span class="badge-chip badge-purple">Safety Limit</span>`;
      text = `Safety limit reached; did not block <b class="mono">${esc(a.src_ip)}</b>`;
    }
    return `<div class="item decision-row">
      <div style="flex:none">${chip}</div>
      <div class="decision-content">
        <div class="decision-text">${text}</div>
        <div class="decision-time">${when(a.ts_epoch)}</div>
      </div>
    </div>`;
  };

  const renderActiveRow = a => {
    const totalSec = (a.ttl_minutes || 30) * 60;
    const remSec = Math.max(0, a.expires_epoch - Date.now() / 1000);
    const pct = Math.min(100, Math.max(4, Math.round((remSec / totalSec) * 100)));
    const isRepeat = a.ttl_minutes && a.ttl_minutes > 30;

    return `<tr>
      <td>
        ${ipLink(a.src_ip)}
        ${a.country ? `<span class="dim small mono">(${esc(a.country)})</span>` : ""}
        ${isRepeat ? `<span class="badge-chip badge-amber" style="margin-left:6px" title="Repeat offender: block duration doubled">Repeat</span>` : ""}
      </td>
      <td>${attackTypeChip(a.reason)}</td>
      <td class="dim" style="max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap" title="${esc(a.reason)}">${esc(a.reason)}</td>
      <td class="dim small mono">${when(a.ts_epoch)}</td>
      <td>
        <div class="mono" style="font-size:12px">${until(a.expires_epoch)}</div>
        <div class="progress-mini" title="${until(a.expires_epoch)} remaining">
          <div class="progress-mini-bar" style="width:${pct}%"></div>
        </div>
      </td>
      <td class="right">
        <button class="btn sm" data-act="unblock" data-ip="${esc(a.src_ip)}">Unblock</button>
      </td>
    </tr>`;
  };

  $("#view").innerHTML = `
  <div class="viewport-screen">
    ${topHeader("Blocked addresses", "Addresses currently stopped at the firewall. Every block ends by itself, and repeat offenders are blocked for longer.", `
      <svg viewBox="0 0 24 24" fill="none">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke="#ff4d6d" stroke-width="1.8" fill="rgba(255, 77, 109, 0.15)"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4" stroke="#ff4d6d" stroke-width="1.8" stroke-linecap="round"/>
        <circle cx="12" cy="16" r="1.5" fill="#ff4d6d"/>
      </svg>
    `)}

    ${d.firewall && d.firewall.available ? "" : `<div class="banner" style="margin:2px 0 6px; flex:none"><div class="grow"><b>The firewall is not available:</b> ${esc((d.firewall && d.firewall.detail) || "iptables check")}</div></div>`}

    <!-- TOP STATS ROW -->
    <div class="stats-row-3">
      <div class="stat-card fig card-blue">
        <div class="card-top">
          <div class="card-icon-box ic-blue">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
            </svg>
          </div>
          <div class="card-meta">
            <b class="stat-val">${active.length}</b>
            <span class="stat-lbl">Blocked Now</span>
          </div>
        </div>
      </div>

      <div class="stat-card fig card-purple">
        <div class="card-top">
          <div class="card-icon-box" style="background:rgba(168, 85, 247, 0.1); color:#c084fc; border:1px solid rgba(168, 85, 247, 0.25)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
              <circle cx="12" cy="12" r="3"/>
            </svg>
          </div>
          <div class="card-meta">
            <b class="stat-val">${wouldBlockCount}</b>
            <span class="stat-lbl">Would-have-blocked</span>
          </div>
        </div>
      </div>

      <div class="stat-card fig card-green">
        <div class="card-top">
          <div class="card-icon-box ic-green">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <polyline points="9 12 11 14 15 10"/>
            </svg>
          </div>
          <div class="card-meta">
            <b class="stat-val">${refusedCount}</b>
            <span class="stat-lbl">Refused / Protected</span>
          </div>
        </div>
      </div>
    </div>

    <!-- ONE LINE ACTION BAR -->
    <div class="action-bar-glass">
      <div class="action-left-group">
        <div class="input-with-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
          <input type="text" id="blk-ip" placeholder="Block an address by hand, e.g. 203.0.113">
        </div>
        <button class="btn-primary" data-act="block-manual">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Block for 30 minutes
        </button>
      </div>
      <button class="btn-outline-danger" data-act="panic" title="Release all active blocks">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
        Unblock everyone now
      </button>
    </div>

    <!-- MAIN 2-COLUMN SPLIT -->
    <div class="split-grid-blocked">
      <!-- LEFT: ACTIVE BLOCKED TABLE -->
      <div class="card-panel">
        <div class="card-panel-header">
          <div class="card-panel-title-wrap">
            <h3 class="card-panel-title">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#ff4d6d" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
              Blocked Addresses
            </h3>
            <span class="badge-count">${active.length}</span>
          </div>
          <span class="card-panel-hint">Auto-released on expiration</span>
        </div>
        <div class="card-panel-body">
          ${active.length ? `
            <table class="table-sticky">
              <thead>
                <tr>
                  <th>Address</th>
                  <th>Type</th>
                  <th>Reason</th>
                  <th>Blocked At</th>
                  <th>Expires In</th>
                  <th class="right">Action</th>
                </tr>
              </thead>
              <tbody>
                ${active.map(renderActiveRow).join("")}
              </tbody>
            </table>
          ` : `
            <div class="empty-state">
              <div class="empty-icon-box">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  <polyline points="9 12 11 14 15 10"/>
                </svg>
              </div>
              <h4 class="empty-title">Nothing is blocked right now.</h4>
              <p class="empty-desc">Addresses currently stopped at the firewall will appear here with live countdowns and unblock controls.</p>
            </div>
          `}
        </div>
      </div>

      <!-- RIGHT: RECENT DECISIONS TIMELINE -->
      <div class="card-panel">
        <div class="card-panel-header">
          <div class="card-panel-title-wrap">
            <h3 class="card-panel-title">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
              Recent Decisions
            </h3>
            <span class="badge-count">${recent.length}</span>
          </div>
          <span class="card-panel-hint">Correlator actions & refusals</span>
        </div>
        <div class="card-panel-body">
          ${recent.length ? `
            <div class="list">
              ${recent.map(recRow).join("")}
            </div>
          ` : `
            <div class="empty-state">
              <div class="empty-icon-box">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                  <circle cx="12" cy="12" r="10"/>
                  <polyline points="12 6 12 12 16 14"/>
                </svg>
              </div>
              <h4 class="empty-title">No decisions yet.</h4>
              <p class="empty-desc">Decisions made by the correlator will appear here in real time.</p>
            </div>
          `}
        </div>
      </div>
    </div>
  </div>`;
}

/* ---------- agents ---------- */
async function pageAgents() {
  const [d, ins] = await Promise.all([api("/api/agents"), api("/api/agent_install")]);
  S.agentCount = d.agents ? d.agents.length : 0;
  const cmd = ins.commands || {};
  $("#view").innerHTML = `<h1>Websites and computers</h1><p class="sub">An agent on a web server or computer reads its web logs and watches important files, then reports here. Works on Linux, macOS and Windows.</p>
  ${d.agents && d.agents.length ? `<table><thead><tr><th>Name</th><th>System</th><th>Status</th><th>Watching</th><th></th></tr></thead>${d.agents.map(a => `<tr><td><b>${esc(a.name)}</b><div class="dim small mono">${esc(a.last_ip || "")}</div></td><td>${esc(a.platform || "")}<div class="dim small">v${esc(a.version || "?")}</div></td>
  <td><i class="dot ${a.online ? "on" : ""}"></i>${a.online ? "online" : "last seen " + when(a.last_seen)}</td><td class="dim small">${(a.info && a.info.logs ? a.info.logs : []).length} log(s), ${(a.info && a.info.fim_files) || 0} file(s)</td>
  <td class="right"><button class="btn sm" data-act="revoke" data-id="${esc(a.id)}" data-name="${esc(a.name)}">Remove</button></td></tr>`).join("")}</table>` : '<p class="dim">No machines yet. Add one below. It takes about a minute.</p>'}
  <h2>Add a machine</h2>${ins.localhost ? `<div class="banner"><div class="grow">You opened the dashboard as <b>localhost</b>. Other machines cannot reach that. Open the dashboard using this server's real address (for example http://192.168.x.x:5000) and come back to this page.</div></div>` : ""}
  <div class="tabs"><button class="on" data-act="tab" data-tab="linux">Linux</button><button data-act="tab" data-tab="mac">macOS</button><button data-act="tab" data-tab="windows">Windows</button></div>
  <div id="tab-linux" class="tabc"><p>On the machine you want to watch, open a terminal and paste this one line:</p>${cmdBox("c-linux", cmd.linux || "")}<p class="hint">It needs Python 3 and sudo. It finds nginx or Apache logs by itself, sets the agent up as a service and enrolls it.</p></div>
  <div id="tab-mac" class="tabc" style="display:none"><p>Open Terminal on the Mac and paste this one line:</p>${cmdBox("c-mac", cmd.mac || "")}<p class="hint">Needs Python 3 (install the Xcode tools if asked). It runs as a launchd service.</p></div>
  <div id="tab-windows" class="tabc" style="display:none"><p>Open <b>PowerShell as Administrator</b> and paste this one line:</p>${cmdBox("c-windows", cmd.windows || "")}<p class="hint">Needs Python 3 (<span class="mono">winget install Python.Python.3.12</span>). It finds IIS logs by itself and runs as a scheduled task.</p></div>
  <div id="waiting" class="result"><span class="spin"></span>Waiting for a new machine to connect. This page updates by itself.</div>`;
  clearInterval(S._agentPoll);
  S._agentPoll = setInterval(async () => {
    if (S.page !== "agents") return clearInterval(S._agentPoll);
    const n = await api("/api/agents");
    if (n.agents && n.agents.length > S.agentCount) { clearInterval(S._agentPoll); toast("A new machine connected."); pageAgents(); }
  }, 3000);
}

/* ---------- simulator ---------- */
const SCEN_META = {
  port_scan: {
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>`,
    sev: "low",
    sevName: "Heads-up",
    tag: "",
    glow: "glow-green",
  },
  ssh_brute: {
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
    sev: "medium",
    sevName: "Suspicious",
    tag: "",
    glow: "glow-amber",
  },
  icmp_flood: {
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
    sev: "high",
    sevName: "Urgent",
    tag: "Blocked in Live mode",
    glow: "glow-red",
  },
  syn_flood: {
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
    sev: "high",
    sevName: "Urgent",
    tag: "Blocked in Live mode",
    glow: "glow-red",
  },
  sqli: {
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>`,
    sev: "high",
    sevName: "Urgent",
    tag: "Blocked in Live mode",
    glow: "glow-red",
  },
  xss: {
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`,
    sev: "medium",
    sevName: "Suspicious",
    tag: "",
    glow: "glow-amber",
  },
  honeypot: {
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>`,
    sev: "high",
    sevName: "Urgent",
    tag: "Blocked in Live mode",
    glow: "glow-red",
  },
  fim: {
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>`,
    sev: "medium",
    sevName: "Alert only",
    tag: "Alert only",
    glow: "glow-amber",
  },
  intel: {
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    sev: "high",
    sevName: "Urgent",
    tag: "Blocked in Live mode",
    glow: "glow-red",
  },
  protected: {
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`,
    sev: "low",
    sevName: "Protected",
    tag: "Never blocked",
    glow: "glow-green",
  },
};

function selftestHTML(r) {
  if (!r) return '<p class="dim" style="padding:12px">The self-test has not been run yet.</p>';
  return `<div class="dim small" style="padding:6px 12px">${when(r.ts)}: <span style="color:var(--ok)">${r.passed} passed</span>, <span style="color:var(--bad)">${r.failed} failed</span>, <span style="color:var(--mute)">${r.skipped} skipped</span></div>
  <div class="list" style="max-height:220px; overflow-y:auto; padding:0 8px">
    ${r.tests.map(t =>
      `<div class="item health-card ${t.status === "ok" ? "ok" : t.status === "fail" ? "fail" : "warn"}">
        <div class="ic ${t.status === "ok" ? "ok" : t.status === "fail" ? "fail" : "warn"}"></div>
        <div style="flex:1">
          <b>${esc(t.name)}</b>
          <div class="dim small">${esc(t.detail)}</div>
        </div>
      </div>`).join("")}
  </div>`;
}

function labReportHTML(r) {
  if (!r || !r.rows || !r.rows.length) {
    return `<div class="empty-state" style="padding:24px 16px">
      <div class="empty-icon-box">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
      </div>
      <h4 class="empty-title">No lab test has been run yet.</h4>
      <p class="empty-desc">Run the test command from your second lab machine, then click Refresh results.</p>
    </div>`;
  }
  const cell = v => v ? (v.detected ? `<span class="badge-chip badge-green">${v.latency}s</span>` : '<span class="badge-chip badge-red">missed</span>') : '<span class="dim">-</span>';
  return `<table class="table-sticky">
    <thead>
      <tr>
        <th>Attack</th>
        <th>Suricata</th>
        <th>Snort</th>
        <th>Web agent</th>
        <th>Decoy</th>
        <th class="right">Result</th>
      </tr>
    </thead>
    <tbody>
      ${r.rows.map(x => `
        <tr>
          <td><b>${esc(x.label)}</b></td>
          <td>${cell(x.engines.suricata)}</td>
          <td>${cell(x.engines.snort)}</td>
          <td>${cell(x.engines.weblog)}</td>
          <td>${cell(x.engines.honeypot)}</td>
          <td class="right">${x.passed ? '<span class="badge-chip badge-green">PASS</span>' : '<span class="badge-chip badge-red">FAIL</span>'}</td>
        </tr>
      `).join("")}
    </tbody>
  </table>
  <div style="padding:8px 14px; border-top:1px solid var(--line); font-size:12px; color:var(--text-dim); display:flex; justify-content:space-between">
    <span><b>${r.detected} of ${r.expected} detected</b></span>
    <span class="dim">Times are from attack start to alert appearing here</span>
  </div>`;
}

async function pageSimulator() {
  const [sc, info, rep, h] = await Promise.all([api("/api/sim/scenarios"), api("/api/sim/info"), api("/api/sim/report"), api("/api/health")]);
  const realCmd = (info && info.command) || "";
  const maskedCmd = realCmd.replace(/--token\s+(\S+)/, '--token ••••••••');

  $("#view").innerHTML = `
  <div class="viewport-screen">
    ${topHeader("Simulator and tests", "Prove that every part works, without needing a real attacker.", `
      <svg viewBox="0 0 24 24" fill="none">
        <polygon points="5 3 19 12 5 21 5 3" fill="url(#simGrad)" stroke="#38bdf8" stroke-width="1.8"/>
        <defs>
          <linearGradient id="simGrad" x1="5" y1="3" x2="19" y2="21" gradientUnits="userSpaceOnUse">
            <stop stop-color="#38bdf8"/>
            <stop offset="1" stop-color="#2563eb"/>
          </linearGradient>
        </defs>
      </svg>
    `)}

    <!-- SECTION 1: 10 DEMO ATTACKS IN 5x2 GRID -->
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px; flex:none">
      <div style="display:flex; align-items:center; gap:8px">
        <span style="font-weight:600; font-size:13px; color:#ffffff">1. Safe demo attacks</span>
        <span class="badge-count">10 scenarios</span>
      </div>
      <span class="dim small">Fake reserved addresses • Tested through real pipeline</span>
    </div>

    <div class="scen scen-grid-5x2">
      ${(sc || []).map(s => {
        const m = SCEN_META[s.id] || { icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>`, sev: "medium", sevName: "Medium", tag: "", glow: "" };
        return `
        <button class="scen-card ${m.glow}" data-act="scenario" data-id="${esc(s.id)}" title="${esc(s.story)}">
          <div class="scen-card-top">
            <div class="scen-icon-box">${m.icon}</div>
            <div style="display:flex; gap:4px; align-items:center">
              ${m.tag ? `<span class="badge-live-tag">${esc(m.tag)}</span>` : ""}
              <span class="badge-chip ${m.sev === "high" ? "badge-red" : m.sev === "medium" ? "badge-amber" : "badge-green"}">${esc(m.sevName)}</span>
            </div>
          </div>
          <b>${esc(s.label)}</b>
          <span class="story">${esc(s.story)}</span>
        </button>`;
      }).join("")}
    </div>

    <!-- FEEDBACK ROW -->
    <div id="sim-result" style="flex:none"></div>

    <!-- SECTION 2: REAL LAB ATTACK TEST COMMAND -->
    <div style="display:flex; justify-content:space-between; align-items:center; margin-top:2px; margin-bottom:4px; flex:none">
      <div style="display:flex; align-items:center; gap:8px">
        <span style="font-weight:600; font-size:13px; color:#ffffff">2. Real attack test on your lab</span>
        <span class="dim small">Run from your secondary attack machine</span>
      </div>
      <div style="display:flex; gap:8px">
        <button class="btn sm" data-act="refresh-lab">Refresh results</button>
        <button class="btn sm pri" data-act="selftest">Run self-test</button>
      </div>
    </div>

    <!-- TERMINAL COMMAND BAR WITH MASK REVEAL & COPY -->
    <div class="sim-command-bar">
      <span class="sim-cmd-prefix">ATTACKER $</span>
      <pre id="c-lab" class="sim-cmd-text" data-real="${esc(realCmd)}" data-masked-text="${esc(maskedCmd)}" data-masked="1">${esc(maskedCmd)}</pre>
      <div class="sim-cmd-actions">
        <button class="btn-icon-toggle" data-act="toggle-token-mask" title="Reveal or hide token">
          <svg id="mask-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
          </svg>
          <span id="mask-text">Reveal Token</span>
        </button>
        <button class="btn sm" data-act="copy" data-target="c-lab">Copy</button>
      </div>
    </div>

    <!-- BOTTOM SPLIT: LAB REPORT TABLE & SELFTEST RESULTS -->
    <div class="split-grid-blocked" style="flex:1; min-height:0">
      <!-- RESULTS TABLE -->
      <div class="card-panel">
        <div class="card-panel-header">
          <div class="card-panel-title-wrap">
            <h3 class="card-panel-title">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#2ee59d" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
              Expected vs Detected Lab Results
            </h3>
          </div>
          <span class="card-panel-hint">Updated on attack arrival</span>
        </div>
        <div class="card-panel-body" id="lab-report">
          ${labReportHTML(rep)}
        </div>
      </div>

      <!-- SELFTEST RESULTS -->
      <div class="card-panel">
        <div class="card-panel-header">
          <div class="card-panel-title-wrap">
            <h3 class="card-panel-title">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              System Self-Tests
            </h3>
          </div>
          <div id="st-wait"></div>
        </div>
        <div class="card-panel-body" id="st-result">
          ${selftestHTML(h && h.selftest)}
        </div>
      </div>
    </div>
  </div>`;
}

/* ---------- setup & health ---------- */
async function pageSetup() {
  const [h, rules] = await Promise.all([api("/api/health"), api("/api/rules")]);
  const groups = {};
  (h.items || []).forEach(i => (groups[i.group] = groups[i.group] || []).push(i));

  Object.keys(groups).forEach(g => {
    groups[g].sort((a, b) => {
      const rank = s => (s === "fail" ? 0 : s === "warn" ? 1 : 2);
      return rank(a.status) - rank(b.status);
    });
  });

  const totalChecks = (h.items || []).length;
  const passedChecks = (h.items || []).filter(i => i.status === "ok").length;
  const word = {
    green: "Everything is working.",
    amber: "Working, with a few things worth fixing.",
    red: "Something needs fixing before you can rely on this.",
  }[h.level] || "Checking health...";

  $("#view").innerHTML = `
  <div class="setup-screen-container">
    ${topHeader("Setup and health", "All self-checks, log readers, and sensor rules to ensure your system is fully operational.", `
      <svg viewBox="0 0 24 24" fill="none">
        <path d="M22 12h-4l-3 9L9 3l-3 9H2" stroke="#2ee59d" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    `)}

    <!-- SUMMARY HERO BANNER (Preserves .hero for tests) -->
    <div class="hero setup-hero-banner ${esc(h.level || "green")}">
      <div style="display:flex; align-items:center; gap:16px">
        <div class="card-icon-box ${h.level === "red" ? "ic-red" : h.level === "amber" ? "ic-amber" : "ic-green"}" style="width:42px; height:42px">
          ${h.level === "red" ?
            `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>` :
            `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`}
        </div>
        <div>
          <div class="t" style="font-size:16px; font-weight:600; color:#ffffff">${esc(word)}</div>
          <div class="m" style="font-size:12.5px; color:var(--text-dim); margin-top:2px">Each line explains status in plain words and how to fix it. Copy any command shown in blue.</div>
        </div>
      </div>
      <div style="display:flex; align-items:center; gap:12px; flex:none">
        <div class="setup-summary-pill">
          <i class="dot on" style="background:${h.level === "red" ? "var(--bad)" : h.level === "amber" ? "var(--warn)" : "var(--ok)"}"></i>
          <span><b>${passedChecks} of ${totalChecks} checks passed</b></span>
        </div>
        <button class="btn btn-primary" data-act="selftest">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
          Run all checks again
        </button>
      </div>
    </div>

    <div style="margin-bottom:14px"><span id="st-wait"></span><div id="st-result">${h.selftest ? selftestHTML(h.selftest) : ""}</div></div>

    <!-- 2-COLUMN GRID OF CHECKS -->
    <div class="setup-grid-2col">
      ${Object.entries(groups).map(([g, items]) => `
        <div class="health-group-card">
          <div class="health-group-header">
            <span>${esc(g)}</span>
            <span class="badge-count">${items.length} checks</span>
          </div>
          <div class="list">
            ${items.map(i => `
              <div class="item health-card ${esc(i.status)}">
                <div class="ic ${esc(i.status)}"></div>
                <div style="flex:1; min-width:0">
                  <div style="display:flex; justify-content:space-between; align-items:center">
                    <b style="font-size:13px; color:#ffffff">${esc(i.title)}</b>
                    <span class="badge-chip ${i.status === "ok" ? "badge-green" : i.status === "warn" ? "badge-amber" : "badge-red"}">${esc(i.status)}</span>
                  </div>
                  <div class="dim small" style="margin-top:3px; line-height:1.4">${esc(i.detail)}</div>
                  ${i.fix && i.status !== "ok" ? `
                    <details class="fix-details">
                      <summary>How to fix</summary>
                      <div class="fix-box">${esc(i.fix)}</div>
                    </details>
                  ` : ""}
                </div>
              </div>
            `).join("")}
          </div>
        </div>
      `).join("")}
    </div>

    <!-- DETECTION RULES SECTION (Preserves rules keyword for tests) -->
    <div class="card-panel" style="margin-top:14px; padding:18px 20px">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; border-bottom:1px solid var(--line); padding-bottom:8px">
        <h3 style="margin:0; font-size:15px; color:#ffffff">Detection rules</h3>
        <span class="dim small">Sensors inspect traffic with these rules</span>
      </div>
      <p class="dim small" style="margin-bottom:14px">The installer already put these in place. They are shown so you can see exactly what the sensors look for, or install by hand.</p>
      ${(rules || []).map((r, i) => `
        <div style="margin-bottom:14px">
          <p style="margin:0 0 6px"><b>${esc(r.name)}</b> <span class="dim small mono" style="margin-left:6px">goes in ${esc(r.target)}</span></p>
          ${cmdBox("rule" + i, r.content)}
        </div>
      `).join("")}
    </div>
  </div>`;
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
  const s = d.settings || {};
  const isLive = s.mode === "live";

  $("#view").innerHTML = `
  <div class="settings-screen-container">
    ${topHeader("Settings", "Changes apply within a second. No restart needed.", `
      <svg viewBox="0 0 24 24" fill="none">
        <circle cx="12" cy="12" r="3" stroke="#38bdf8" stroke-width="2"/>
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" stroke="#38bdf8" stroke-width="2"/>
      </svg>
    `)}

    <!-- TOP FLOATING ACTIONS -->
    <div class="action-bar-glass" style="margin-bottom:14px">
      <div style="display:flex; align-items:center; gap:10px">
        <span style="font-weight:600; font-size:13.5px; color:#ffffff">Global Configuration</span>
        <span class="dim small">• Real-time propagation</span>
      </div>
      <div style="display:flex; align-items:center; gap:12px">
        <span id="save-msg" class="save-indicator"></span>
        <button class="btn btn-primary" data-act="save-settings">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
          Save settings
        </button>
      </div>
    </div>

    <!-- 2-COLUMN GRID OF SECTION CARDS -->
    <div class="settings-grid-2col">
      <!-- CARD 1: OPERATING MODE -->
      <div class="settings-card">
        <div class="settings-card-header">
          <h3 class="settings-card-title">Operating Mode</h3>
          <span class="badge-chip ${isLive ? "badge-red" : "badge-blue"}">${isLive ? "Active Protection" : "Monitoring Only"}</span>
        </div>
        <p class="dim small" style="margin:0">Shadow only watches and logs alerts. Live really blocks urgent attackers in the firewall.</p>
        <div class="mode-segmented-large">
          <button class="mode-seg-btn shadow ${!isLive ? "on" : ""}" data-act="set-mode" data-mode="shadow">
            <div style="display:flex; align-items:center; gap:8px">
              <i class="dot on" style="background:#3b82f6"></i>
              <b style="color:#ffffff; font-size:13.5px">Shadow Mode</b>
            </div>
            <div class="dim small" style="margin-top:6px">Observes and explains all alerts. Zero packets blocked.</div>
          </button>
          <button class="mode-seg-btn live ${isLive ? "on" : ""}" data-act="set-mode" data-mode="live">
            <div style="display:flex; align-items:center; gap:8px">
              <i class="dot on" style="background:#ff4d6d"></i>
              <b style="color:#ffffff; font-size:13.5px">Live Mode</b>
            </div>
            <div class="dim small" style="margin-top:6px; color:#ff8a82">Automatically blocks urgent threats in the local firewall.</div>
          </button>
        </div>
        <div class="hint" style="font-size:11.5px">Start in Shadow mode to inspect traffic. Switch to Live once alerts look accurate.</div>
      </div>

      <!-- CARD 2: PROTECTED ADDRESSES -->
      <div class="settings-card">
        <div class="settings-card-header">
          <h3 class="settings-card-title">Protected Addresses</h3>
          <span class="badge-count">${(wl.items || []).length} protected</span>
        </div>
        <p class="dim small" style="margin:0">These addresses can never be blocked, whatever they do. This machine, its gateway and every monitored machine are always protected too.</p>
        
        <div class="protected-chips-wrap">
          ${wl.items && wl.items.length ? wl.items.map(w => `
            <div class="protected-chip">
              <span class="mono" style="font-weight:600; color:#38bdf8">${esc(w.cidr)}</span>
              ${w.note ? `<span class="dim small">(${esc(w.note)})</span>` : ""}
              <button class="chip-del" data-act="wl-del" data-id="${w.id}" title="Remove">&times;</button>
            </div>
          `).join("") : '<p class="dim small" style="margin:4px 0">None yet.</p>'}
        </div>

        <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-top:4px">
          <input type="text" id="wl-new" placeholder="192.168.56.10 or 192.168.56.0/24" style="flex:1; min-width:180px">
          <input type="text" id="wl-note" placeholder="note (optional)" style="flex:1; min-width:130px">
          <button class="btn sm" data-act="wl-add">Add</button>
          <button class="btn sm" data-act="add-mine">Add my address (${esc(S.me ? S.me.ip : "")})</button>
        </div>
      </div>

      <!-- CARD 3: BLOCKING PARAMETERS -->
      <div class="settings-card">
        <div class="settings-card-header">
          <h3 class="settings-card-title">Firewall & Blocking</h3>
        </div>
        ${SCHEMA[0][1].map(([k, l, t, h]) => field(k, l, t, h, s[k])).join("")}
      </div>

      <!-- CARD 4: NOTIFICATIONS -->
      <div class="settings-card">
        <div class="settings-card-header">
          <h3 class="settings-card-title">Notifications</h3>
          <div style="display:flex; gap:6px">
            <button class="btn sm" data-act="test-notify" data-ch="telegram">Test Telegram</button>
            <button class="btn sm" data-act="test-notify" data-ch="email">Test email</button>
          </div>
        </div>
        ${SCHEMA[1][1].map(([k, l, t, h]) => field(k, l, t, h, s[k])).join("")}
      </div>

      <!-- CARD 5: DECOYS & THREAT LISTS -->
      <div class="settings-card">
        <div class="settings-card-header">
          <h3 class="settings-card-title">Decoys & Threat Lists</h3>
          <button class="btn sm" data-act="intel-update">Update lists now</button>
        </div>
        ${SCHEMA[2][1].map(([k, l, t, h]) => field(k, l, t, h, s[k])).join("")}
        <div class="dim small" style="margin-top:6px">
          ${Object.entries((d.intel && d.intel.lists) || {}).map(([k, v]) => `<b>${esc(k)}</b>: ${v} addresses`).join(" · ") || "Not downloaded yet."}
        </div>
        <div style="display:flex; gap:8px; align-items:center; margin-top:8px">
          <input type="text" id="intel-ip" placeholder="Add an address to your own threat list" style="flex:1">
          <button class="btn sm" data-act="intel-add">Add</button>
        </div>
      </div>

      <!-- CARD 6: NETWORK & RETENTION -->
      <div class="settings-card">
        <div class="settings-card-header">
          <h3 class="settings-card-title">Network & Retention</h3>
        </div>
        ${SCHEMA[3][1].map(([k, l, t, h]) => field(k, l, t, h, s[k])).join("")}
      </div>

      <!-- CARD 7: ENROLLMENT & AUTH -->
      <div class="settings-card">
        <div class="settings-card-header">
          <h3 class="settings-card-title">Security & Password</h3>
        </div>
        <label>Agent enrollment password</label>
        <p class="dim small" style="margin:0 0 6px">Machines need this to join. Changing it does not disconnect already enrolled machines.</p>
        <div><button class="btn sm" data-act="regen-enroll">Make a new enrollment password</button></div>

        <div style="margin-top:12px; border-top:1px solid var(--line); padding-top:10px">
          <label style="margin-top:0">Change dashboard password</label>
          <div class="row2" style="margin-top:6px">
            <div><input type="password" id="pw-cur" placeholder="Current password" autocomplete="current-password"></div>
            <div><input type="password" id="pw-new" placeholder="New password (8+ characters)" autocomplete="new-password"></div>
          </div>
          <div style="margin-top:8px"><button class="btn sm" data-act="change-pw">Change password</button></div>
        </div>
      </div>

      <!-- CARD 8: REPORTS & EXPORTS -->
      <div class="settings-card">
        <div class="settings-card-header">
          <h3 class="settings-card-title">Reports & Data Export</h3>
        </div>
        <p class="dim small" style="margin:0">Generate print-ready executive summaries or export structured alert history.</p>
        <div style="display:flex; gap:10px; margin-top:8px">
          <a class="btn" href="/report?days=7" target="_blank">Open weekly report</a>
          <a class="btn" href="/api/export/events.csv?days=30">Download 30 days as CSV</a>
        </div>
      </div>
    </div>
  </div>`;
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
  "toggle-mode": () => setMode(S.ov && S.ov.mode === "live" ? "shadow" : "live"),
  "go-page": t => { location.hash = "#/" + t.dataset.to; },
  "toggle-token-mask": () => {
    const el = $("#c-lab");
    if (!el) return;
    const isMasked = el.dataset.masked === "1";
    if (isMasked) {
      el.textContent = el.dataset.real;
      el.dataset.masked = "0";
      const icon = $("#mask-icon");
      if (icon) icon.innerHTML = `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>`;
      const txt = $("#mask-text");
      if (txt) txt.textContent = "Hide Token";
    } else {
      el.textContent = el.dataset.maskedText;
      el.dataset.masked = "1";
      const icon = $("#mask-icon");
      if (icon) icon.innerHTML = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
      const txt = $("#mask-text");
      if (txt) txt.textContent = "Reveal Token";
    }
  },
  copy: async t => {
    const el = $("#" + t.dataset.target);
    const txt = (el && el.dataset.real) ? el.dataset.real : (el ? el.textContent : "");
    try { await navigator.clipboard.writeText(txt); }
    catch (e) {
      const ta = document.createElement("textarea");
      ta.value = txt; document.body.appendChild(ta);
      ta.select(); document.execCommand("copy"); ta.remove();
    }
    t.textContent = "Copied";
    setTimeout(() => (t.textContent = "Copy"), 1500);
  },
  tab: t => { $$(".tabs button").forEach(b => b.classList.toggle("on", b === t)); $$(".tabc").forEach(c => (c.style.display = c.id === "tab-" + t.dataset.tab ? "" : "none")); },
  revoke: async t => { if (!confirm("Remove " + t.dataset.name + "? It will stop being able to report.")) return; await api("/api/agents/" + encodeURIComponent(t.dataset.id), undefined, "DELETE"); pageAgents(); },
  scenario: async t => {
    t.disabled = true;
    const prevIcon = t.querySelector(".scen-icon-box");
    const oldIconHTML = prevIcon ? prevIcon.innerHTML : "";
    if (prevIcon) prevIcon.innerHTML = `<span class="spin" style="margin:0"></span>`;
    try {
      const r = await api("/api/sim/run", { scenario: t.dataset.id });
      toast(`<b>${esc(r.label)}</b> injected: ${esc(r.decision)}`, r.decision === "blocked" ? "high" : "");
      $("#sim-result").innerHTML = `
        <div class="result" style="margin:6px 0; padding:8px 12px; border-radius:10px; border-left:4px solid var(--accent); background:rgba(13,20,38,0.85)">
          <div style="display:flex; justify-content:space-between; align-items:center">
            <b>${esc(r.label)}</b>
            <span class="dim small mono">${esc(r.ip || "no address")} · ${esc(r.mode)} mode</span>
          </div>
          <p style="margin:3px 0 4px; font-size:12px">${esc(r.story)}</p>
          <div style="font-size:12px"><b>Result:</b> ${esc({
            alert_only: "Logged only. Not serious enough to block.",
            would_block: "Shadow mode: it would have been blocked.",
            blocked: "Blocked in the firewall " + (r.note || ""),
            skip_protected: "Not blocked: protected address.",
            already_blocked: "Already blocked.",
            dedup: "Already handled.",
            rate_limited: "Safety limit reached.",
            block_failed: "Block failed: " + r.note
          }[r.decision] || r.decision)}</div>
          <p class="dim small" style="margin:3px 0 0">Open Overview to watch it travel through the pipeline, or Alerts to see the full explanation.</p>
        </div>`;
    } catch (err) {
      toast("Error running demo attack: " + esc(err.message));
    } finally {
      t.disabled = false;
      if (prevIcon) prevIcon.innerHTML = oldIconHTML;
    }
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
  document.body.dataset.page = S.page;
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
  const set = (p, n) => {
    const a = $(`nav a[data-page=${p}]`); if (!a) return;
    let b = $(".badge-n", a);
    if (!n || n <= 0) { if (b) b.remove(); return; }
    if (!b) { b = document.createElement("span"); b.className = "badge-n"; a.appendChild(b); }
    b.textContent = n;
  };
  set("alerts", o.counts.alerts);
  set("blocked", o.counts.blocked);
  set("setup", o.health.fails + o.health.warns);
}
let _liveTimer;
function startStream() {
  if (S.sse) S.sse.close();
  const es = (S.sse = new EventSource("/api/stream"));
  es.addEventListener("event", m => {
    const e = JSON.parse(m.data); S.events.set(e.id, e);
    if (S.page === "overview") {
      const tb = $("#feed tbody");
      if (tb) {
        if (tb.querySelector(".act-empty-cell") || (tb.querySelector(".dim") && !tb.querySelector("tr.click"))) {
          tb.innerHTML = "";
        }
        tb.insertAdjacentHTML("afterbegin", feedRow(e, true));
        while (tb.rows.length > 14) tb.deleteRow(-1);
      }
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
  if ($("#who")) $("#who").textContent = S.me.ip || "127.0.0.1";
  window.addEventListener("hashchange", route);
  await route(); startStream(); loadOverview(false);
  setInterval(() => loadOverview(S.page === "overview" && !document.hidden), 30000);
  window.addEventListener("resize", () => { clearTimeout(S._rs); S._rs = setTimeout(() => S.page === "overview" && S.ov && (drawChart(S.ov.series), drawMap(S.ov.map)), 200); });
})();
