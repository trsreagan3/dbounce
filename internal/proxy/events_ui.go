// events_ui.go ships the minimal live audit-stream web UI served at
// GET / on the dbounce mgmt port alongside /healthz + /audit/events
// (#272).
//
// The page is a single self-contained HTML+CSS+JS file (no build
// step, no external CDN, no Google Fonts, no analytics, no telemetry)
// that long-polls /audit/events?since=<cursor> every two seconds and
// renders a colour-coded live-updating table.
//
// Wire choice
// -----------
//
// The page LONG-POLLS rather than using SSE. SSE would require
// streaming response semantics that the existing auditEventsHandler
// doesn't provide today, and the operator UX is identical at the 2 s
// tick. A future bump can swap the JS polling loop for an
// EventSource without touching the server contract. The other three
// Bounce-suite products (ibounce / kbounce / gbounce) ship the same
// HTML page for cross-product parity per [[cross-product-agent-
// parity]].
//
// Auth model
// ----------
//
//   - Loopback bind (default): no Authorization header required.
//   - External bind: the same bearer token /audit/events enforces is
//     accepted via Authorization header OR via the URL fragment
//     (#token=...) which the JS extracts client-side. The rendered
//     HTML body NEVER embeds the token regardless of auth mode.
//
// Per [[creates-never-mutates]] the UI is read-only — no buttons
// mutate dbounce state. Per [[security-team-positioning-safety-not-
// surveillance]] labels use "deny" / "allow" / "policy mismatch",
// never "violation" / "infraction" / "unauthorized". Per
// [[self-host-zero-billing-dependency]] no CDN; everything inline +
// offline-ready.
package proxy

import (
	"html"
	"net/http"
	"strings"
)

// bouncerNameDbounce is the product name baked into the served HTML.
const bouncerNameDbounce = "dbounce"

// renderAuditEventsUI returns the rendered HTML page for GET /. The
// bouncerName is HTML-escaped before substitution so an exotic
// product label can never inject script via the page title.
func renderAuditEventsUI(bouncerName string) string {
	safe := html.EscapeString(bouncerName)
	return strings.ReplaceAll(auditEventsUITemplate, "{{BOUNCER_NAME}}", safe)
}

// auditEventsUIHandler builds the http.HandlerFunc for GET /. The
// page itself is harmless and contains no secret shape; we still
// honour an Authorization Bearer header when requireBearer is set
// (programmatic 403 path) but a browser visit without a header
// renders the page so the JS can show its "auth required - append
// #token=..." banner.
func auditEventsUIHandler(requireBearer string) http.HandlerFunc {
	body := renderAuditEventsUI(bouncerNameDbounce)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "only GET is supported", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if requireBearer != "" {
			ah := r.Header.Get("Authorization")
			if ah != "" {
				tok, ok := parseBearerHeader(ah)
				if !ok || tok != requireBearer {
					http.Error(w, "bearer token rejected", http.StatusForbidden)
					return
				}
			}
		}
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'none'; "+
				"form-action 'none'")
		_, _ = w.Write([]byte(body))
	}
}

// auditEventsUITemplate is the cross-product-identical HTML page
// (only the {{BOUNCER_NAME}} token varies per bouncer). Kept inline
// as one Go raw string literal so the binary has zero on-disk
// dependencies. Under 500 lines per spec.
const auditEventsUITemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{BOUNCER_NAME}} - live audit stream</title>
<style>
:root {
  --bg: #0d1117;
  --panel: #161b22;
  --line: #30363d;
  --text: #c9d1d9;
  --muted: #8b949e;
  --allow: #2ea043;
  --deny: #f85149;
  --admin: #58a6ff;
  --heartbeat: #6e7681;
  --warn: #d29922;
  --accent: #f0883e;
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  padding: 0;
  background: var(--bg);
  color: var(--text);
  font: 13px/1.45 ui-monospace, SFMono-Regular, "SF Mono", Menlo,
        Consolas, "Liberation Mono", monospace;
}
header {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 18px;
  align-items: center;
  padding: 10px 14px;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
  position: sticky;
  top: 0;
  z-index: 10;
}
header .brand { font-weight: 700; font-size: 15px; letter-spacing: 0.3px; }
header .brand .dot {
  display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  margin-right: 6px; vertical-align: middle;
  background: var(--allow); box-shadow: 0 0 6px var(--allow);
}
header .brand .dot.stale { background: var(--warn); box-shadow: 0 0 6px var(--warn); }
header .brand .dot.err { background: var(--deny); box-shadow: 0 0 6px var(--deny); }
header .counts { display: flex; gap: 14px; flex-wrap: wrap; color: var(--muted); font-size: 12px; }
header .counts b { color: var(--text); }
header .controls { display: flex; gap: 8px; margin-left: auto; flex-wrap: wrap; }
header input[type="text"] {
  background: var(--bg); color: var(--text);
  border: 1px solid var(--line); border-radius: 4px;
  padding: 5px 8px; font: inherit; width: 240px;
}
header input[type="text"]::placeholder { color: var(--muted); }
header button {
  background: var(--bg); color: var(--text);
  border: 1px solid var(--line); border-radius: 4px;
  padding: 5px 10px; font: inherit; cursor: pointer;
}
header button:hover { border-color: var(--accent); }
header button.active { border-color: var(--accent); color: var(--accent); }
main { padding: 0; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
thead th {
  text-align: left; font-weight: 600;
  background: var(--panel); color: var(--muted);
  border-bottom: 1px solid var(--line);
  padding: 6px 10px;
  position: sticky; top: 49px; z-index: 5;
  letter-spacing: 0.4px; text-transform: uppercase; font-size: 11px;
}
tbody tr { border-bottom: 1px solid #1d232b; }
tbody tr:hover { background: #1a2029; }
tbody td { padding: 6px 10px; vertical-align: top; word-break: break-word; }
.verdict {
  display: inline-block; padding: 1px 7px; border-radius: 3px;
  font-weight: 700; font-size: 11px; letter-spacing: 0.5px;
  border: 1px solid transparent;
}
.verdict.allow { color: var(--allow); border-color: var(--allow); }
.verdict.deny { color: var(--deny); border-color: var(--deny); }
.verdict.admin { color: var(--admin); border-color: var(--admin); }
.verdict.heartbeat { color: var(--heartbeat); border-color: var(--heartbeat); }
.verdict.unknown { color: var(--muted); border-color: var(--muted); }
tr.row-deny td { background: rgba(248, 81, 73, 0.05); }
tr.row-admin td { background: rgba(88, 166, 255, 0.05); }
tr.row-heartbeat td { color: var(--muted); }
.empty { padding: 40px 20px; text-align: center; color: var(--muted); }
.err-banner {
  padding: 8px 14px; background: rgba(248, 81, 73, 0.12);
  border-bottom: 1px solid var(--deny);
  color: var(--deny); font-size: 12px;
}
.err-banner:empty { display: none; }
footer {
  padding: 8px 14px; color: var(--muted); font-size: 11px;
  border-top: 1px solid var(--line); text-align: center;
}
@media (max-width: 720px) {
  header .controls { width: 100%; margin-left: 0; }
  header input[type="text"] { flex: 1 1 auto; width: auto; }
  thead th { top: 0; position: static; }
  table { font-size: 12px; }
  tbody td { padding: 5px 6px; }
}
</style>
</head>
<body>
<header>
  <div class="brand"><span class="dot" id="status-dot"></span>{{BOUNCER_NAME}} <span style="color: var(--muted); font-weight: 400;">- live audit stream</span></div>
  <div class="counts">
    <span>total <b id="count-total">0</b></span>
    <span>allow <b id="count-allow">0</b></span>
    <span>deny <b id="count-deny">0</b></span>
    <span>admin <b id="count-admin">0</b></span>
    <span>heartbeat <b id="count-heartbeat">0</b></span>
  </div>
  <div class="controls">
    <input type="text" id="filter" placeholder="filter: field=value or field~regex">
    <button type="button" id="pause-btn">pause</button>
    <button type="button" id="clear-btn">clear</button>
  </div>
</header>
<div class="err-banner" id="err-banner"></div>
<main>
<table>
<thead>
<tr>
  <th style="width: 168px;">time</th>
  <th style="width: 80px;">severity</th>
  <th style="width: 140px;">event type</th>
  <th style="width: 160px;">actor</th>
  <th>operation</th>
  <th style="width: 110px;">verdict</th>
</tr>
</thead>
<tbody id="events-body">
<tr class="empty-row"><td colspan="6" class="empty">waiting for events&hellip;</td></tr>
</tbody>
</table>
</main>
<footer>read-only viewer - <a href="/healthz" style="color: var(--muted);">/healthz</a> | <a href="/audit/events?limit=10" style="color: var(--muted);">/audit/events</a></footer>
<script>
"use strict";
(function () {
  var POLL_MS = 2000;
  var MAX_ROWS = 500;
  var token = null;
  try {
    var m = window.location.hash.match(/[#&]token=([^&]+)/);
    if (m) { token = decodeURIComponent(m[1]); }
  } catch (e) { /* ignore */ }

  var elBody = document.getElementById("events-body");
  var elFilter = document.getElementById("filter");
  var elPause = document.getElementById("pause-btn");
  var elClear = document.getElementById("clear-btn");
  var elErr = document.getElementById("err-banner");
  var elDot = document.getElementById("status-dot");
  var elCountTotal = document.getElementById("count-total");
  var elCountAllow = document.getElementById("count-allow");
  var elCountDeny = document.getElementById("count-deny");
  var elCountAdmin = document.getElementById("count-admin");
  var elCountHeartbeat = document.getElementById("count-heartbeat");

  var counts = { total: 0, allow: 0, deny: 0, admin: 0, heartbeat: 0 };
  var seenIds = Object.create(null);
  var paused = false;
  var lastTimeMs = 0;
  var pollHandle = null;

  function setErr(msg) { elErr.textContent = msg || ""; }
  function setDot(state) {
    elDot.classList.remove("stale", "err");
    if (state === "stale") elDot.classList.add("stale");
    if (state === "err") elDot.classList.add("err");
  }

  function fmtTime(ms) {
    if (!ms) return "-";
    var d = new Date(typeof ms === "number" ? ms : Date.parse(ms));
    if (isNaN(d.getTime())) return String(ms);
    var pad = function (n) { return n < 10 ? "0" + n : "" + n; };
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
           " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }

  function classifyVerdict(ev) {
    var u = ev && ev.unmapped && ev.unmapped.iam_jit || {};
    var v = (u.verdict || ev.verdict || "").toString().toUpperCase();
    var et = (u.event_type || ev.event_type || ev.class_name || "").toString().toUpperCase();
    if (et.indexOf("HEARTBEAT") !== -1) return { label: "HEARTBEAT", cls: "heartbeat" };
    if (et.indexOf("ADMIN") !== -1) return { label: et.replace(/[_-]/g, " "), cls: "admin" };
    if (v === "DENY" || v === "DENIED") return { label: "DENIED", cls: "deny" };
    if (v === "ALLOW" || v === "ALLOWED") return { label: "ALLOWED", cls: "allow" };
    if (v) return { label: v, cls: "unknown" };
    return { label: "-", cls: "unknown" };
  }

  function extractSeverity(ev) {
    if (ev.severity) return String(ev.severity);
    if (ev.severity_id != null) {
      var map = { 1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical" };
      return map[ev.severity_id] || ("sev=" + ev.severity_id);
    }
    return "-";
  }

  function extractActor(ev) {
    var u = ev && ev.unmapped && ev.unmapped.iam_jit || {};
    if (ev.actor && ev.actor.user && ev.actor.user.name) return ev.actor.user.name;
    if (u.actor) return String(u.actor);
    if (u.agent && u.agent.name) return String(u.agent.name);
    return "-";
  }

  function extractOperation(ev) {
    if (ev.api && ev.api.operation) return ev.api.operation;
    var u = ev && ev.unmapped && ev.unmapped.iam_jit || {};
    if (u.operation) return String(u.operation);
    if (ev.activity_name) return String(ev.activity_name);
    return "-";
  }

  function extractEventType(ev) {
    var u = ev && ev.unmapped && ev.unmapped.iam_jit || {};
    if (u.event_type) return String(u.event_type);
    if (ev.event_type) return String(ev.event_type);
    if (ev.class_name) return String(ev.class_name);
    return "-";
  }

  function eventId(ev) {
    return [ev.time || "", extractActor(ev), extractOperation(ev), extractEventType(ev)].join("|");
  }

  function eventTimeMs(ev) {
    var t = ev.time;
    if (typeof t === "number") return t;
    if (typeof t === "string") {
      var n = Date.parse(t);
      if (!isNaN(n)) return n;
    }
    return Date.now();
  }

  function bump(cls) {
    counts.total += 1;
    if (cls === "allow") counts.allow += 1;
    else if (cls === "deny") counts.deny += 1;
    else if (cls === "admin") counts.admin += 1;
    else if (cls === "heartbeat") counts.heartbeat += 1;
    elCountTotal.textContent = counts.total;
    elCountAllow.textContent = counts.allow;
    elCountDeny.textContent = counts.deny;
    elCountAdmin.textContent = counts.admin;
    elCountHeartbeat.textContent = counts.heartbeat;
  }

  function renderRow(ev) {
    var v = classifyVerdict(ev);
    var tr = document.createElement("tr");
    tr.className = "row-" + v.cls;
    var cells = [
      fmtTime(eventTimeMs(ev)),
      extractSeverity(ev),
      extractEventType(ev),
      extractActor(ev),
      extractOperation(ev),
    ];
    cells.forEach(function (text) {
      var td = document.createElement("td");
      td.textContent = text;
      tr.appendChild(td);
    });
    var tdv = document.createElement("td");
    var span = document.createElement("span");
    span.className = "verdict " + v.cls;
    span.textContent = v.label;
    tdv.appendChild(span);
    tr.appendChild(tdv);
    return tr;
  }

  function appendEvents(events) {
    if (!events.length) return;
    var empty = elBody.querySelector(".empty-row");
    if (empty) empty.remove();
    events.forEach(function (ev) {
      var id = eventId(ev);
      if (seenIds[id]) return;
      seenIds[id] = true;
      var tms = eventTimeMs(ev);
      if (tms > lastTimeMs) lastTimeMs = tms;
      var v = classifyVerdict(ev);
      bump(v.cls);
      elBody.appendChild(renderRow(ev));
    });
    while (elBody.children.length > MAX_ROWS) {
      elBody.removeChild(elBody.firstChild);
    }
    window.scrollTo(0, document.body.scrollHeight);
  }

  function parseNdjson(text) {
    var out = [];
    if (!text) return out;
    var lines = text.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i].trim();
      if (!ln) continue;
      try { out.push(JSON.parse(ln)); }
      catch (e) { /* skip malformed */ }
    }
    return out;
  }

  function buildUrl() {
    var qs = ["limit=200"];
    if (lastTimeMs) {
      qs.push("since=" + encodeURIComponent(new Date(lastTimeMs + 1).toISOString()));
    }
    var f = (elFilter.value || "").trim();
    if (f) qs.push("filter=" + encodeURIComponent(f));
    return "/audit/events?" + qs.join("&");
  }

  function poll() {
    if (paused) { schedulePoll(); return; }
    var req = new XMLHttpRequest();
    req.open("GET", buildUrl(), true);
    req.setRequestHeader("Accept", "application/x-ndjson");
    if (token) req.setRequestHeader("Authorization", "Bearer " + token);
    req.timeout = 10000;
    req.onload = function () {
      if (req.status === 200) {
        setDot("ok");
        setErr("");
        appendEvents(parseNdjson(req.responseText));
      } else if (req.status === 401 || req.status === 403) {
        setDot("err");
        setErr("auth required - append #token=YOUR_TOKEN to the URL");
      } else {
        setDot("stale");
        setErr("/audit/events returned " + req.status);
      }
      schedulePoll();
    };
    req.onerror = function () {
      setDot("err");
      setErr("network error - bouncer unreachable");
      schedulePoll();
    };
    req.ontimeout = function () {
      setDot("stale");
      setErr("/audit/events poll timed out");
      schedulePoll();
    };
    req.send();
  }

  function schedulePoll() {
    if (pollHandle) clearTimeout(pollHandle);
    pollHandle = setTimeout(poll, POLL_MS);
  }

  elPause.addEventListener("click", function () {
    paused = !paused;
    elPause.classList.toggle("active", paused);
    elPause.textContent = paused ? "resume" : "pause";
  });
  elClear.addEventListener("click", function () {
    elBody.innerHTML = "";
    seenIds = Object.create(null);
    counts = { total: 0, allow: 0, deny: 0, admin: 0, heartbeat: 0 };
    elCountTotal.textContent = "0";
    elCountAllow.textContent = "0";
    elCountDeny.textContent = "0";
    elCountAdmin.textContent = "0";
    elCountHeartbeat.textContent = "0";
    var tr = document.createElement("tr");
    tr.className = "empty-row";
    var td = document.createElement("td");
    td.colSpan = 6;
    td.className = "empty";
    td.textContent = "cleared - waiting for events…";
    tr.appendChild(td);
    elBody.appendChild(tr);
  });
  elFilter.addEventListener("change", function () { poll(); });

  poll();
})();
</script>
</body>
</html>
`
