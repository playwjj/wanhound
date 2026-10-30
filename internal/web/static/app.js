// WanHound web UI. Plain JS, no build step. Every value that came from
// a scanned target (banners, titles, certificate names) is untrusted:
// it is only ever inserted with textContent, never as HTML.
"use strict";

const app = document.getElementById("app");
let session = null;
let pollTimer = null;
let lastScanBody = null;

// ---- helpers ---------------------------------------------------------

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    n.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return n;
}

async function api(method, path, body) {
  const opts = { method, credentials: "same-origin", headers: {} };
  if (method !== "GET") opts.headers["X-WanHound"] = "1";
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (res.status === 401 && path !== "/api/login") {
    session = null;
    showLogin();
    throw new Error("login required");
  }
  if (!res.ok) throw new Error((data && data.error) || res.statusText);
  return data;
}

const q = (o) => new URLSearchParams(o).toString();
const fmtTime = (s) => new Date(s).toLocaleString();
const ms = (ns) => Math.round(ns / 1e6) + " ms";
const dur = (ns) => {
  const s = Math.round(ns / 1e9);
  return s < 60 ? s + "s" : Math.floor(s / 60) + "m " + (s % 60) + "s";
};
const riskOrder = { high: 3, medium: 2, low: 1, info: 0 };
const badge = (r) => el("span", { class: "badge " + r }, r === "none" ? "CLEAN" : r.toUpperCase());
const maxRisk = (fs) => (fs && fs.length ? fs.reduce((m, f) => (riskOrder[f.risk] > riskOrder[m] ? f.risk : m), "info") : "none");
const where = (f) => (f.port ? f.port + "/" + f.proto : "whole target");
const confText = { high: "high — matched identifying evidence", medium: "medium — protocol recognized", low: "low — port number only" };

function evidenceOf(info) {
  const parts = [];
  if (info.banner) parts.push("banner " + JSON.stringify(info.banner));
  if (info.tls) {
    let s = "TLS" + (info.tls.cn ? " cn=" + JSON.stringify(info.tls.cn) : "");
    if (info.tls.issuer && info.tls.issuer !== info.tls.cn) s += " issuer=" + JSON.stringify(info.tls.issuer);
    if (info.tls.self_signed) s += " self-signed";
    if (info.tls.expired) s += " EXPIRED";
    parts.push(s);
  }
  if (info.http) {
    let s = "HTTP " + info.http.status;
    if (info.http.title) s += " title=" + JSON.stringify(info.http.title);
    if (info.http.server) s += " server=" + JSON.stringify(info.http.server);
    if (info.http.https_only) s += " (HTTPS-only port: plaintext request rejected)";
    parts.push(s);
  }
  return parts.join("; ");
}

function setView(...nodes) {
  app.replaceChildren(...nodes.filter((n) => n !== null && n !== undefined && n !== false));
  const h = location.hash || "#/";
  document.querySelectorAll("#nav a").forEach((a) => {
    const target = a.getAttribute("href");
    a.classList.toggle("on", target === "#/" ? h === "#/" : h.startsWith(target));
  });
}

function errorBox(msg) { return el("div", { class: "err", role: "alert" }, msg); }

// ---- login -----------------------------------------------------------

function showLogin(message) {
  stopPolling();
  document.getElementById("nav").hidden = true;
  const pw = el("input", { type: "password", id: "pw", autocomplete: "current-password", required: true });
  const msg = el("div");
  if (message) msg.append(errorBox(message));
  const form = el("form", { class: "card login", onsubmit: async (e) => {
    e.preventDefault();
    btn.disabled = true;
    msg.replaceChildren();
    try {
      await api("POST", "/api/login", { password: pw.value });
      await boot();
    } catch (err) {
      msg.append(errorBox(err.message));
      btn.disabled = false;
      pw.select();
    }
  } },
    el("h1", {}, "Sign in"),
    el("p", { class: "muted small" }, "This WanHound server is password-protected. Every audit is logged."),
    el("label", { class: "f", for: "pw" }, "Password"), pw, msg);
  const btn = el("button", { class: "primary", type: "submit", style: "margin-top:12px" }, "Sign in");
  form.append(btn);
  setView(form);
  pw.focus();
}

document.getElementById("logout").addEventListener("click", async () => {
  try { await api("POST", "/api/logout"); } catch (_) { /* ignore */ }
  session = null;
  showLogin();
});

// ---- new audit ---------------------------------------------------------

async function viewNew() {
  let labels = [];
  let task = null;
  try {
    [labels, task] = await Promise.all([api("GET", "/api/labels"), api("GET", "/api/task").then((r) => r.task)]);
  } catch (_) { return; }

  const lastLabel = labels[0] ? labels[0].label : "home";
  const f = {
    label: el("input", { type: "text", id: "label", list: "labels", value: lastLabel, maxlength: 64, required: true }),
    ipv4: el("input", { type: "text", id: "ipv4", placeholder: "e.g. 203.0.113.7", inputmode: "decimal", autocomplete: "off" }),
    ipv6: el("input", { type: "text", id: "ipv6", placeholder: "e.g. 2001:db8::7", autocomplete: "off" }),
    ports: el("input", { type: "text", id: "ports", placeholder: "22,80,8000-8100", disabled: true }),
    udp: el("input", { type: "checkbox", id: "udp", checked: true }),
    offline: el("input", { type: "checkbox", id: "offline" }),
    authorized: el("input", { type: "checkbox", id: "authorized", required: true }),
  };
  const last = labels.find((l) => l.label === lastLabel);
  if (last && last.last) {
    if (last.last.family === "v4") f.ipv4.value = last.last.ip; else f.ipv6.value = last.last.ip;
  }
  const radio = (v, text, checked) => el("label", { class: "check" },
    el("input", { type: "radio", name: "portset", value: v, checked, onchange: () => { f.ports.disabled = v !== "custom"; } }), text);
  const msg = el("div");
  const submit = el("button", { class: "primary", type: "submit" }, "Start audit");

  const form = el("form", { class: "card", onsubmit: async (e) => {
    e.preventDefault();
    msg.replaceChildren();
    const body = {
      label: f.label.value.trim(), ipv4: f.ipv4.value.trim(), ipv6: f.ipv6.value.trim(),
      port_set: form.querySelector("input[name=portset]:checked").value, ports: f.ports.value.trim(),
      udp: f.udp.checked, offline: f.offline.checked, authorized: f.authorized.checked, accept_inside: false,
    };
    if (!body.ipv4 && !body.ipv6) { msg.append(errorBox("Enter at least one address.")); return; }
    if (!body.authorized) { msg.append(errorBox("Confirm that you own or are authorized to test these addresses.")); return; }
    submit.disabled = true;
    try {
      await api("POST", "/api/scan", body);
      lastScanBody = body;
      location.hash = "#/task";
    } catch (err) {
      msg.append(errorBox(err.message));
      submit.disabled = false;
    }
  } },
    el("h1", {}, "New audit"),
    el("p", { class: "muted small" }, "Audit one public IPv4 and/or one IPv6 address of your own home, from this server's vantage point. Run WanHound outside the network being audited."),
    el("datalist", { id: "labels" }, labels.map((l) => el("option", { value: l.label }))),
    el("div", { class: "grid2" },
      el("div", {}, el("label", { class: "f", for: "label" }, "Home label (history is kept per label, not per IP)"), f.label),
      el("div"),
      el("div", {}, el("label", { class: "f", for: "ipv4" }, "Public IPv4"), f.ipv4),
      el("div", {}, el("label", { class: "f", for: "ipv6" }, "Public IPv6"), f.ipv6)),
    el("h3", {}, "Ports"),
    el("div", { class: "opts" },
      radio("full", "All 65,535 ports (recommended, 1–3 min)", true),
      radio("quick", `Quick set (${session.quick_ports} common ports, seconds)`, false),
      radio("custom", "Custom:", false), f.ports),
    el("label", { class: "check" }, f.udp, el("span", {}, `Also probe the home UDP set (${(session.udp_ports || []).join(", ")}) — advisory only`)),
    el("label", { class: "check" }, f.offline, el("span", {}, "Offline: no third-party lookups (ASN/ISP profile and egress self-check send the address to public lookup services)")),
    el("label", { class: "check" }, f.authorized, el("span", {}, el("b", {}, "I own these addresses or am authorized to test them."), " The audit, its targets and your address are recorded in the audit log.")),
    msg, submit);

  const nodes = [];
  if (task && task.state === "running") {
    nodes.push(el("div", { class: "warn" }, "An audit is running (", task.targets.join(", "), "). ", el("a", { href: "#/task" }, "Watch progress")));
    submit.disabled = true;
  }
  if (session.lab) nodes.push(el("div", { class: "warn" }, "Lab mode: private and loopback targets are allowed on this server (test bench)."));
  setView(...nodes, form);
}

// ---- running task ------------------------------------------------------

function stopPolling() {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = null;
}

async function viewTask() {
  stopPolling();
  let task;
  try { task = (await api("GET", "/api/task")).task; } catch (_) { return; }
  if (location.hash !== "#/task") return;
  if (!task) {
    setView(el("div", { class: "card" }, el("h1", {}, "No audit yet"), el("p", {}, el("a", { href: "#/" }, "Start one"))));
    return;
  }
  const head = el("div", { class: "card" },
    el("h1", {}, task.state === "running" ? "Auditing…" : "Audit " + task.state),
    el("p", { class: "muted small" }, `label "${task.label}" · ${task.targets.join(" + ")} · ${task.port_set} scan · started ${fmtTime(task.started)}`));
  if (task.state === "running") {
    const c = task.current || {};
    const pct = c.stage === "tcp" && c.total ? Math.floor((c.done || 0) * 100 / c.total) : null;
    const bar = el("div", { class: "bar", role: "progressbar", "aria-valuemin": 0, "aria-valuemax": 100, "aria-valuenow": pct ?? 0 }, el("div"));
    bar.firstChild.style.width = (pct ?? 3) + "%";
    head.append(bar, el("p", { class: "small" }, c.target ? c.target + " — " : "", stageText(c), pct !== null ? ` ${pct}% (${c.done}/${c.total})` : ""));
    head.append(el("button", { class: "danger", type: "button", onclick: async (e) => {
      e.target.disabled = true;
      try { await api("POST", "/api/task/cancel"); } catch (err) { head.append(errorBox(err.message)); }
    } }, "Cancel"));
  }
  if (task.log && task.log.length) head.append(el("ul", { class: "log" }, task.log.map((l) => el("li", {}, l))));
  if (task.error) head.append(errorBox(task.error));
  const nodes = [head];
  if (task.report) nodes.push(...renderReport(task.report));
  setView(...nodes);
  if (task.state === "running") pollTimer = setTimeout(viewTask, 1000);
}

function stageText(c) {
  return { check: "checking vantage point", profile: "profiling address", tcp: "TCP connect scan", probe: "identifying services", udp: "UDP probes" }[c.stage] || c.stage || "starting";
}

function renderReport(rep) {
  const nodes = [];
  for (const e of rep.errors || []) {
    const box = el("div", { class: "card" }, el("h2", {}, "Not audited: " + e.ip), el("p", {}, e.reason));
    if (e.inside && lastScanBody) {
      box.append(el("button", { type: "button", onclick: async (ev) => {
        ev.target.disabled = true;
        try {
          await api("POST", "/api/scan", { ...lastScanBody, accept_inside: true, ipv4: e.ip.includes(":") ? "" : e.ip, ipv6: e.ip.includes(":") ? e.ip : "" });
          viewTask();
        } catch (err) { box.append(errorBox(err.message)); }
      } }, "Continue anyway (results will be distorted)"));
    }
    nodes.push(box);
  }
  for (const s of rep.targets || []) nodes.push(...renderSnapshot(s));
  return nodes;
}

// ---- snapshot report ---------------------------------------------------

function renderSnapshot(s) {
  const card = el("div", { class: "card" });
  const risk = maxRisk(s.findings);
  card.append(el("h2", {}, s.ip, " ", el("span", { class: "muted small" }, "IP" + s.family), " ", badge(risk)));
  if (s.intel) {
    const p = s.intel;
    const bits = [[p.asn, p.org].filter(Boolean).join(" "), p.country, (p.ptr || []).map((x) => "ptr " + x).join(", ")].filter(Boolean);
    if (bits.length) card.append(el("p", { class: "muted small" }, bits.join(" · "), p.source ? ` (via ${p.source})` : ""));
    for (const h of p.hints || []) card.append(el("div", { class: "warn small" }, h));
  }
  card.append(el("div", { class: "stats" },
    stat(s.counts.open, "open"), stat(s.counts.closed, "closed"), stat(s.counts.filtered, "filtered"),
    stat(dur(s.duration_ns), s.port_set + " scan"), stat(ms(s.timeout_ns), s.rtt_ns ? "timeout (rtt " + ms(s.rtt_ns) + ")" : "timeout")));
  card.append(renderChanges(s.changes));

  // Port table.
  const byPort = {};
  for (const f of s.findings || []) if (f.proto === "tcp") (byPort[f.port] = byPort[f.port] || []).push(f);
  if ((s.open || []).length) {
    card.append(el("h3", {}, "Open TCP ports"), el("div", { class: "scroll" }, el("table", { class: "tbl" },
      el("thead", {}, el("tr", {}, el("th", {}, "Port"), el("th", {}, "Risk"), el("th", {}, "Service"), el("th", {}, "What answered"))),
      el("tbody", {}, s.open.map((o) => {
        const top = (byPort[o.port] || [{ risk: "info", service: "?" }])[0];
        return el("tr", { class: "r-" + top.risk }, el("td", { class: "mono" }, o.port + "/tcp"), el("td", {}, badge(top.risk)),
          el("td", {}, top.service), el("td", {}, el("code", {}, evidenceOf(o) || "—")));
      })))));
  }
  if ((s.udp || []).length) {
    card.append(el("h3", {}, "UDP ", el("span", { class: "muted small" }, "(advisory: silence cannot tell open from filtered)")),
      el("div", { class: "scroll" }, el("table", { class: "tbl" },
        el("tbody", {}, s.udp.map((u) => el("tr", {}, el("td", { class: "mono" }, u.port + "/udp"), el("td", {}, u.service),
          el("td", {}, u.state), el("td", { class: "small" }, u.detail || "")))))));
  }

  // Findings.
  card.append(el("h3", {}, "Findings"));
  if (!(s.findings || []).length) card.append(el("div", { class: "good" }, "Nothing answered. From this vantage point, nothing is exposed."));
  for (const f of s.findings || []) {
    card.append(el("details", { class: "finding " + f.risk, open: f.risk === "high" },
      el("summary", {}, badge(f.risk), el("span", { class: "mono" }, where(f)), el("b", {}, f.title), el("span", { class: "muted small" }, f.rule_id)),
      el("div", { class: "body" },
        f.evidence ? el("p", {}, el("span", { class: "k" }, "Evidence"), el("code", {}, f.evidence)) : null,
        el("p", {}, el("span", { class: "k" }, "What is this"), f.explain),
        el("p", {}, el("span", { class: "k" }, "What to do"), f.advice),
        el("p", { class: "small muted" }, el("span", { class: "k" }, "Rule"), f.rule_id, f.confidence ? " · confidence " + confText[f.confidence] : ""))));
  }
  if ((s.notes || []).length) card.append(el("ul", { class: "small muted" }, s.notes.map((n) => el("li", {}, n))));
  card.append(el("p", { class: "small muted" },
    `Audited ${fmtTime(s.time)} · source ${s.egress || "not checked"} · rules ${s.rules_version} · snapshot ${s.id} · `,
    el("a", { href: "/api/snapshot/html?" + q({ label: s.label, id: s.id }) }, "Download HTML report"), " · ",
    el("a", { href: "#/history/" + encodeURIComponent(s.label) }, "History")));
  return [card];
}

function stat(v, label) { return el("div", { class: "stat" }, el("b", {}, String(v)), el("span", { class: "muted small" }, label)); }

function renderChanges(ch) {
  if (!ch) return el("p", { class: "muted small" }, "First audit for this label and address family — this is the baseline.");
  const box = el("div", { class: ch.opened || ch.udp_opened ? "warn" : "good" },
    el("div", { class: "small" }, `Compared with ${fmtTime(ch.prev_time)} (${ch.prev_ip}):`));
  if (ch.ip_changed) box.append(el("div", { class: "event" }, `Address changed: ${ch.prev_ip} → this run. It may not be the same line; compare with care.`));
  if (ch.opened) box.append(el("div", { class: "new" }, "NEW open TCP ports: " + ch.opened.join(", ")));
  if (ch.udp_opened) box.append(el("div", { class: "new" }, "NEW answering UDP ports: " + ch.udp_opened.join(", ")));
  if (ch.closed) box.append(el("div", { class: "gone" }, "No longer open: " + ch.closed.join(", ")));
  if (ch.udp_closed) box.append(el("div", { class: "gone" }, "UDP no longer answering: " + ch.udp_closed.join(", ")));
  for (const c of ch.changed || []) box.append(el("div", { class: "small" }, `${c.port}/tcp answers differently: `, el("code", {}, c.before), " → ", el("code", {}, c.after)));
  if (!ch.opened && !ch.closed && !ch.changed && !ch.udp_opened && !ch.udp_closed) box.append(el("div", {}, "No change in open ports."));
  if (ch.coverage) box.append(el("div", { class: "small muted" }, ch.coverage));
  return box;
}

// ---- history -----------------------------------------------------------

async function viewLabels() {
  let labels;
  try { labels = await api("GET", "/api/labels"); } catch (_) { return; }
  if (!labels.length) {
    setView(el("div", { class: "card" }, el("h1", {}, "History"), el("p", {}, "No audits yet. ", el("a", { href: "#/" }, "Start one"))));
    return;
  }
  setView(el("h1", {}, "History"), el("div", { class: "labels" }, labels.map((l) =>
    el("a", { href: "#/history/" + encodeURIComponent(l.label) }, el("div", { class: "card" },
      el("h2", {}, l.label),
      l.last ? el("p", { class: "small" }, badge(l.last.max_risk), ` ${l.last.counts.open} open · ${l.last.ip}`) : null,
      el("p", { class: "muted small" }, `${l.count} snapshot(s)`, l.last ? " · last " + fmtTime(l.last.time) : ""))))));
}

async function viewHistory(label) {
  let metas;
  try { metas = await api("GET", "/api/history?" + q({ label })); } catch (_) { return; }
  const picked = [];
  const cmp = el("button", { class: "primary", type: "button", disabled: true, onclick: () => {
    location.hash = `#/diff/${encodeURIComponent(label)}/${picked[0]}/${picked[1]}`;
  } }, "Compare selected");
  const hint = el("span", { class: "muted small" }, "Select two snapshots of the same address family to compare side by side.");
  const list = el("ul", { class: "timeline" }, metas.map((m) => {
    const box = el("input", { type: "checkbox", "aria-label": "select " + m.id, onchange: (e) => {
      if (e.target.checked) picked.push(m.id); else picked.splice(picked.indexOf(m.id), 1);
      if (picked.length > 2) {
        const drop = picked.shift();
        list.querySelector(`input[data-id="${CSS.escape(drop)}"]`).checked = false;
      }
      cmp.disabled = picked.length !== 2;
    } });
    box.dataset.id = m.id;
    return el("li", {}, box, el("div", {},
      el("div", { class: "meta" }, badge(m.max_risk),
        el("a", { href: `#/snap/${encodeURIComponent(label)}/${m.id}` }, fmtTime(m.time)),
        el("span", { class: "mono" }, m.ip), el("span", { class: "muted small" }, `IP${m.family} · ${m.port_set} · ${m.counts.open} open`)),
      m.ip_change ? el("div", { class: "event" }, "Address changed: " + m.ip_change) : null,
      m.opened ? el("div", { class: "new small" }, "New: " + m.opened.join(", ")) : null,
      m.closed ? el("div", { class: "gone small" }, "Closed: " + m.closed.join(", ")) : null));
  }));
  setView(el("h1", {}, "History — " + label), el("div", { class: "card" }, el("div", { class: "row" }, cmp, hint), list));
}

async function viewSnapshot(label, id) {
  let s;
  try { s = await api("GET", "/api/snapshot?" + q({ label, id })); } catch (err) { setView(errorBox(err.message)); return; }
  setView(el("p", {}, el("a", { href: "#/history/" + encodeURIComponent(label) }, "← History — " + label)), ...renderSnapshot(s));
}

async function viewDiff(label, a, b) {
  let d;
  try { d = await api("GET", "/api/diff?" + q({ label, a, b })); } catch (err) { setView(errorBox(err.message)); return; }
  const A = d.a, B = d.b;
  const ports = [...new Set([...(A.open || []), ...(B.open || [])].map((o) => o.port))].sort((x, y) => x - y);
  const find = (s, p) => (s.open || []).find((o) => o.port === p);
  const topRisk = (s, p) => { const f = (s.findings || []).find((x) => x.port === p && x.proto === "tcp"); return f ? f : null; };
  const cell = (s, p, cls) => {
    const o = find(s, p);
    if (!o && !covers(s.scanned, p)) return el("td", { class: "diffcell" }, el("span", { class: "muted" }, "not scanned in this run"));
    if (!o) return el("td", { class: "diffcell " + cls }, el("span", { class: "muted" }, "not open"));
    const f = topRisk(s, p);
    return el("td", { class: "diffcell " + cls }, f ? badge(f.risk) : null, " ", f ? f.title : "", el("div", {}, el("code", {}, evidenceOf(o))));
  };
  const head = (s) => el("th", {}, fmtTime(s.time), el("div", { class: "mono" }, s.ip), el("div", { class: "muted small" }, `${s.port_set} · ${s.counts.open} open`));
  const rows = ports.map((p) => {
    const inA = !!find(A, p), inB = !!find(B, p);
    let cls = "";
    const comparable = covers(A.scanned, p) && covers(B.scanned, p);
    if (!comparable) cls = "";
    else if (inA && !inB) cls = "removed"; else if (!inA && inB) cls = "added";
    else if (evidenceOf(find(A, p)) !== evidenceOf(find(B, p))) cls = "changed";
    return el("tr", {}, el("td", { class: "mono" }, p + "/tcp"), cell(A, p, cls), cell(B, p, cls));
  });
  setView(
    el("p", {}, el("a", { href: "#/history/" + encodeURIComponent(label) }, "← History — " + label)),
    el("h1", {}, "Compare"),
    d.warning ? el("div", { class: "warn" }, d.warning) : null,
    el("div", { class: "card" }, renderChanges(d.changes),
      el("div", { class: "scroll" }, el("table", { class: "tbl" },
        el("thead", {}, el("tr", {}, el("th", {}, "Port"), head(A), head(B))),
        el("tbody", {}, rows.length ? rows : el("tr", {}, el("td", { colspan: 3 }, "No open ports in either snapshot.")))))));
}

// covers reports whether a compact port spec ("1-1024,8080") includes port.
function covers(spec, port) {
  return (spec || "").split(",").some((part) => {
    const [lo, hi] = part.split("-").map(Number);
    return hi ? port >= lo && port <= hi : port === lo;
  });
}

// ---- audit log ---------------------------------------------------------

async function viewLog() {
  let entries;
  try { entries = await api("GET", "/api/audit-log"); } catch (_) { return; }
  setView(el("h1", {}, "Audit log"), el("p", { class: "muted small" }, "Every login and audit on this server, newest first (", "audit.log in the data directory)."),
    el("div", { class: "card scroll" }, el("table", { class: "tbl" },
      el("thead", {}, el("tr", {}, el("th", {}, "Time"), el("th", {}, "Action"), el("th", {}, "From"), el("th", {}, "Details"))),
      el("tbody", {}, entries.map((e) => {
        const { time, action, remote, user_agent, ...rest } = e;
        return el("tr", {}, el("td", { class: "small" }, fmtTime(time)), el("td", {}, action), el("td", { class: "mono" }, remote || ""),
          el("td", {}, el("code", {}, Object.entries(rest).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : v}`).join("  "))));
      })))));
}

// ---- routing -----------------------------------------------------------

function route() {
  if (!session) return;
  stopPolling();
  const parts = (location.hash.replace(/^#\/?/, "") || "").split("/").map(decodeURIComponent);
  switch (parts[0]) {
    case "": return viewNew();
    case "task": return viewTask();
    case "history": return parts[1] ? viewHistory(parts[1]) : viewLabels();
    case "snap": return viewSnapshot(parts[1], parts[2]);
    case "diff": return viewDiff(parts[1], parts[2], parts[3]);
    case "log": return viewLog();
    default: location.hash = "#/";
  }
}

async function boot() {
  try {
    const s = await api("GET", "/api/session");
    if (!s.authenticated) { showLogin(); return; }
    session = s;
  } catch (err) {
    setView(errorBox("Cannot reach the server: " + err.message));
    return;
  }
  document.getElementById("nav").hidden = false;
  route();
}

window.addEventListener("hashchange", route);
boot();
