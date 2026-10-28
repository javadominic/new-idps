// Loads the REAL dashboard in jsdom against a running API, clicks through every page,
// and checks hostile text from logs is shown as text, never executed.
const { JSDOM, VirtualConsole } = require(process.env.JSDOM_PATH || "jsdom");
const BASE = process.env.BASE, PASS = process.env.PASS;
let cookie = "", results = [], errors = [];
const check = (n, ok, d = "") => { results.push(ok); console.log(`  [${ok ? "PASS" : "FAIL"}] ${n} ${d ? "- " + d : ""}`); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function nodeFetch(u, o = {}) {
  o.headers = Object.assign({}, o.headers, cookie ? { Cookie: cookie } : {});
  const r = await fetch(new URL(u, BASE), o);
  const sc = r.headers.get("set-cookie"); if (sc) cookie = sc.split(";")[0];
  return r;
}
(async () => {
  const lr = await nodeFetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json", "X-IDPS": "1" }, body: JSON.stringify({ password: PASS }) });
  check("login over HTTP", lr.ok);
  const html = await (await nodeFetch("/")).text();
  const vc = new VirtualConsole();
  vc.on("jsdomError", e => errors.push("jsdomError: " + e.message));
  vc.on("error", (...a) => errors.push("console.error: " + a.join(" ")));
  const dom = new JSDOM(html, { url: BASE + "/", runScripts: "dangerously", resources: "usable", pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(w) {
      w.fetch = (u, o) => nodeFetch(u, o);
      w.EventSource = class { constructor() { this.l = {}; w.__es = this; } addEventListener(n, f) { this.l[n] = f; } close() {} };
      w.confirm = () => true; w.alert = () => {};
      w.HTMLCanvasElement.prototype.getContext = () => null;
    } });
  const w = dom.window, $ = s => w.document.querySelector(s), $$ = s => [...w.document.querySelectorAll(s)];
  const go = async h => { w.location.hash = h; await sleep(900); };
  await sleep(1500);

  check("overview renders hero, figures and pipeline", !!$(".hero") && $$(".fig").length === 5 && $$(".pipe .st").length === 5, $(".hero .t") && $(".hero .t").textContent.slice(0, 60));
  check("live feed shows seeded alerts as plain-English rows", $$("#feed tr.click").length >= 3, $$("#feed tr.click").length + " rows");
  check("hostile text from logs is NOT executed on overview", w.__xss === undefined && !$("#view img"));
  $("#feed tr.click").click(); await sleep(300);
  check("clicking an alert opens the explanation drawer", $("#drawer").classList.contains("open") && /What the system did/.test($("#drawer").textContent));
  check("hostile text is NOT executed in the drawer", w.__xss === undefined && !$("#drawer img") && !$("#drawer script"));
  $("#drawer [data-act=close]").click();

  // live stream: push an event through the handler like the server would
  w.__es.l.event({ data: JSON.stringify({ id: 99999, ingested: Date.now() / 1000, engine: "suricata", severity: "high", title: "Traffic flood", explain: "<b>x</b> is flooding", decision_text: "Blocked.", src_ip: "1.2.3.4", count: 1, raw: "r", advice: "a", mitre: "T1498", mitre_name: "n", signature: "s", intel: [] }) });
  await sleep(300);
  check("live event appears at top of the feed and fires the pipeline dot", /Traffic flood/.test($("#feed tr.click").textContent) && $("#track i") !== null);
  check("live event with HTML in its text is escaped", !$("#feed .small b") && /<b>x<\/b> is flooding/.test($("#feed").textContent));
  check("urgent live event shows a toast", !!$(".toast.high"));

  await go("#/alerts");
  check("alerts page lists history with filters", $$("#alist tr.click").length >= 3 && !!$("#f-sev"));
  let sawRaw = false;
  for (const r of $$("#alist tr.click")) { r.click(); await sleep(120); if (/onload/.test($("#drawer pre").textContent)) { sawRaw = true; break; } }
  check("hostile raw log line is shown as inert text in the drawer", sawRaw && w.__xss === undefined && !$("#drawer img") && !$("#drawer svg") && !$("#drawer script"));
  $("#drawer [data-act=close]").click();
  $("#f-sev").value = "high"; $("#f-sev").dispatchEvent(new w.Event("input")); await sleep(800);
  check("severity filter narrows the list", $$("#alist tr.click").every(r => /Urgent/.test(r.textContent)) && $$("#alist tr.click").length >= 1);

  await go("#/blocked");
  check("blocked page renders with manual block and panic button", !!$("#blk-ip") && !!$("[data-act=panic]"));
  await go("#/agents");
  check("agents page shows one-line install commands for all three systems", /sudo sh/.test($("#c-linux").textContent) && /sudo sh/.test($("#c-mac").textContent) && /DownloadString/.test($("#c-windows").textContent));
  check("agent install command carries the manager address and token", /agent\/install\.sh\?token=\S{8,}/.test($("#c-linux").textContent));
  $("[data-tab=windows]").click(); await sleep(100);
  check("OS tabs switch", $("#tab-windows").style.display === "" && $("#tab-linux").style.display === "none");
  w.clearInterval && clearInterval; 

  await go("#/simulator");
  check("simulator shows demo scenarios and real-lab section", $$(".scen button").length >= 8 && /lab_attacks\.py/.test($("#c-lab").textContent));
  $("[data-id=icmp_flood]").click(); await sleep(1500);
  check("running a demo scenario shows what happened", /Result:/.test($("#sim-result").textContent), $("#sim-result").textContent.slice(0, 90));
  $("[data-act=selftest]").click(); await sleep(9000);
  check("self-test runs from the page and lists every function", $$("#st-result .item").length >= 15, $$("#st-result .item").length + " items");

  await go("#/setup");
  check("setup page shows the checklist with fixes and the rules", $$(".list .item").length >= 8 && /rules/.test($("#view").textContent));
  await go("#/settings");
  check("settings page renders all sections and protected list", !!$("#s-block_ttl_minutes") && !!$("#wl-new") && !!$("#s-telegram_token"));
  $("#s-block_ttl_minutes").value = "45"; $("[data-act=save-settings]").click(); await sleep(800);
  check("saving settings works", /Saved/.test($("#save-msg").textContent), $("#save-msg").textContent);
  $("[data-act=set-mode][data-mode=live]").click(); await sleep(1200);
  const mode = await (await nodeFetch("/api/settings")).json();
  check("switching to Live from the page changes the real setting", mode.settings.mode === "live" && mode.settings.block_ttl_minutes === 45);
  await nodeFetch("/api/settings", { method: "POST", headers: { "Content-Type": "application/json", "X-IDPS": "1" }, body: JSON.stringify({ mode: "shadow" }) });

  check("no JavaScript errors anywhere", errors.length === 0, errors.slice(0, 3).join(" | "));
  console.log(`\n${results.filter(Boolean).length}/${results.length} UI checks passed`);
  process.exit(results.every(Boolean) ? 0 : 1);
})();
