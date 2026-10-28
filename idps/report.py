"""Printable summary report (and CSV export) for your project write-up."""
import csv
import html
import io
import time
from . import config, db, knowledge, simulate


def _e(x):
    return html.escape(str(x if x is not None else ""))


def _t(ts):
    return time.strftime("%d %b %Y %H:%M", time.localtime(ts)) if ts else "-"


def csv_export(days=7):
    since = time.time() - days * 86400
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["time", "source", "agent", "severity", "kind", "mitre", "src_ip", "dst_port", "signature", "count", "decision", "simulated"])
    for r in db.q("SELECT * FROM events WHERE ingested>? ORDER BY id", (since,)):
        w.writerow([_t(r["ingested"]), r["engine"], r["agent"] or "", r["severity"], r["kind"], r["mitre"] or "",
                    r["src_ip"] or "", r["dst_port"] or "", r["signature"], r["count"], r["decision"], r["simulated"]])
    return out.getvalue()


def _bars(rows, key, val, color="#2f6fed"):
    mx = max([r[val] for r in rows] or [1]) or 1
    return "".join('<tr><td>%s</td><td class="bar"><i style="width:%d%%;background:%s"></i></td><td class="n">%s</td></tr>'
                   % (_e(r[key]), int(100 * r[val] / mx), color, _e(r[val])) for r in rows)


def render(days=7):
    since = time.time() - days * 86400
    tot = db.one("SELECT IFNULL(SUM(count),0) n, SUM(CASE WHEN severity='high' THEN count ELSE 0 END) h, COUNT(*) rows FROM events WHERE ingested>? AND simulated=0", (since,))
    sim = db.one("SELECT IFNULL(SUM(count),0) n FROM events WHERE ingested>? AND simulated=1", (since,))["n"]
    blocks = db.q("SELECT * FROM actions WHERE action='block' AND ts_epoch>? ORDER BY ts_epoch DESC LIMIT 40", (since,))
    would = db.one("SELECT COUNT(*) n FROM actions WHERE action='would_block' AND ts_epoch>?", (since,))["n"]
    skipped = db.one("SELECT COUNT(*) n FROM actions WHERE action='skip_protected' AND ts_epoch>?", (since,))["n"]
    perday = db.q("SELECT strftime('%%d %%b', ingested,'unixepoch','localtime') d, SUM(count) n FROM events WHERE ingested>? AND simulated=0 GROUP BY d ORDER BY MIN(ingested)", (since,))
    sev = db.q("SELECT severity s, SUM(count) n FROM events WHERE ingested>? AND simulated=0 GROUP BY severity", (since,))
    kinds = db.q("SELECT kind, mitre, SUM(count) n FROM events WHERE ingested>? AND simulated=0 GROUP BY kind ORDER BY n DESC LIMIT 10", (since,))
    for k in kinds:
        k["name"] = "%s (%s %s)" % (knowledge.title(k["kind"]), k["mitre"] or "-", knowledge.mitre_name(k["kind"]))
    engines = db.q("SELECT engine e, SUM(count) n FROM events WHERE ingested>? AND simulated=0 GROUP BY engine ORDER BY n DESC", (since,))
    top = db.q("SELECT src_ip ip, MAX(country) c, SUM(count) n, MAX(CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) r "
               "FROM events WHERE ingested>? AND src_ip IS NOT NULL AND simulated=0 GROUP BY src_ip ORDER BY n DESC LIMIT 10", (since,))
    agents = db.q("SELECT name, platform, last_seen FROM agents ORDER BY name")
    lab = simulate.report()

    rows_top = "".join("<tr><td class='m'>%s</td><td>%s</td><td class='n'>%s</td><td>%s</td></tr>" % (
        _e(r["ip"]), _e(r["c"] or "-"), r["n"], {3: "Urgent", 2: "Suspicious", 1: "Heads-up"}[r["r"]]) for r in top)
    rows_blk = "".join("<tr><td class='m'>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
        _e(b["src_ip"]), _t(b["ts_epoch"]), _e("%g min" % b["ttl_minutes"] if b["ttl_minutes"] else "-"), _e(b["reason"])) for b in blocks)
    rows_lab = ""
    for r in lab["rows"]:
        cells = ""
        for eng in ("suricata", "snort", "weblog", "honeypot"):
            v = r["engines"].get(eng)
            cells += "<td>%s</td>" % (("detected in %ss" % v["latency"]) if v and v["detected"] else ("MISSED" if v else "-"))
        rows_lab += "<tr><td>%s</td>%s<td>%s</td></tr>" % (_e(r["label"]), cells, "PASS" if r["passed"] else "FAIL")
    lab_html = ("<h2>Real lab test: expected vs detected</h2><table><tr><th>Attack</th><th>Suricata</th><th>Snort</th><th>Web agent</th><th>Honeypot</th><th>Result</th></tr>%s</table>"
                "<p class='note'>%d of %d expected detections were seen. Times are from attack start to the alert reaching the dashboard.</p>" % (rows_lab, lab["detected"], lab["expected"])) if lab["rows"] else ""

    return """<!doctype html><html><head><meta charset="utf-8"><title>IDPS report</title><style>
body{font:15px/1.5 "IBM Plex Sans",Segoe UI,system-ui,sans-serif;color:#1b2333;max-width:860px;margin:32px auto;padding:0 20px}
h1{font-size:26px;margin:0}h2{font-size:17px;margin:28px 0 8px;border-bottom:1px solid #d8deea;padding-bottom:4px}
.sub{color:#5b6679}.figs{display:flex;gap:28px;flex-wrap:wrap;margin:18px 0}.figs b{display:block;font:600 28px "IBM Plex Mono",monospace}
table{border-collapse:collapse;width:100%%}td,th{padding:5px 8px;border-bottom:1px solid #e6eaf2;text-align:left;font-size:14px}th{color:#5b6679;font-weight:500}
.m{font-family:"IBM Plex Mono",monospace}.n{text-align:right;font-family:"IBM Plex Mono",monospace}.bar{width:55%%}.bar i{display:block;height:10px;border-radius:2px}
.note{color:#5b6679;font-size:13px}@media print{body{margin:0}}</style></head><body>
<h1>Security summary</h1><div class="sub">Last %d days &middot; generated %s &middot; mode: %s</div>
<div class="figs"><div><b>%s</b>alerts seen</div><div><b>%s</b>urgent</div><div><b>%d</b>blocked</div><div><b>%d</b>would-have-blocked (shadow)</div><div><b>%d</b>protected skips</div></div>
%s
<h2>Alerts per day</h2><table>%s</table>
<h2>By severity</h2><table>%s</table>
<h2>What kinds of attack (with MITRE ATT&amp;CK)</h2><table>%s</table>
<h2>Where alerts came from</h2><table>%s</table>
<h2>Top sources</h2><table><tr><th>Address</th><th>Country</th><th>Alerts</th><th>Worst</th></tr>%s</table>
<h2>Blocks</h2><table><tr><th>Address</th><th>When</th><th>For</th><th>Reason</th></tr>%s</table>
%s
<h2>Machines monitored</h2><table>%s</table>
<p class="note">Simulated demo alerts (%s) are excluded from all figures above.</p></body></html>""" % (
        days, _t(time.time()), _e(config.get("mode")), tot["n"], tot["h"] or 0, len(blocks), would, skipped,
        "" if tot["rows"] else "<p class='note'>No real alerts in this period.</p>",
        _bars(perday, "d", "n"), _bars([{"s": r["s"], "n": r["n"]} for r in sev], "s", "n", "#d9534f"),
        _bars(kinds, "name", "n", "#7a5af8"), _bars(engines, "e", "n", "#2a9d8f"),
        rows_top or "<tr><td colspan=4>None</td></tr>", rows_blk or "<tr><td colspan=4>None</td></tr>", lab_html,
        "".join("<tr><td>%s</td><td>%s</td><td>last seen %s</td></tr>" % (_e(a["name"]), _e(a["platform"]), _t(a["last_seen"])) for a in agents) or "<tr><td>None</td></tr>",
        sim)
