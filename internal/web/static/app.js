// WanHound web UI. Plain JS, no build step. Every value that came from
// a scanned target (banners, titles, certificate names) is untrusted:
// it is only ever inserted with textContent, never as HTML.
"use strict";

const app = document.getElementById("app");
let session = null;
let pollTimer = null;
let lastScanBody = null;

// ---- i18n --------------------------------------------------------------

const L = {
  en: {
    signin: "Sign in", signin_note: "This WanHound server is password-protected. Every audit is logged.", password: "Password",
    bad_pw: "Wrong password.", throttled: "Too many failed attempts. Try again later.",
    nav_new: "New audit", nav_task: "Current", nav_history: "History", nav_log: "Audit log", logout: "Log out",
    footer: "Self-audit of your own home network's public exposure. Only audit addresses you own or are authorized to test.",
    ph_v4: "your router's WAN IPv4", ph_v6: "a device's global IPv6",
    start: "Start audit", need_addr: "Enter at least one address.", need_auth: "Confirm that you own or are authorized to test these addresses.",
    new_title: "New audit", new_intro: "Audit one public IPv4 and/or one IPv6 address of your own home, from this server's vantage point. Run WanHound outside the network being audited.",
    label_lbl: "Home label (history is kept per label, not per IP)", v4_lbl: "Public IPv4", v6_lbl: "Public IPv6", ports: "Ports",
    ps_full: "All 65,535 ports (recommended, 1–3 min)", ps_quick: "Quick set ({0} common ports, seconds)", ps_custom: "Custom:",
    udp_opt: "Also probe the home UDP set ({0}) — advisory only",
    offline_opt: "Offline: no third-party lookups (ASN/ISP profile and egress self-check send the address to public lookup services)",
    auth_b: "I own these addresses or am authorized to test them.", auth_rest: " The audit, its targets and your address are recorded in the audit log.",
    running: "An audit is running ({0}). ", watch: "Watch progress", lab: "Lab mode: private and loopback targets are allowed on this server (test bench).",
    no_audit: "No audit yet", start_one: "Start one", auditing: "Auditing…", st_done: "Audit done", st_failed: "Audit failed", st_cancelled: "Audit cancelled",
    task_meta: "label \"{0}\" · {1} · {2} scan · started {3}", cancel: "Cancel",
    stg_check: "checking vantage point", stg_profile: "profiling address", stg_tcp: "TCP connect scan", stg_probe: "identifying services", stg_udp: "UDP probes", stg_start: "starting",
    not_audited: "Not audited: {0}", continue_anyway: "Continue anyway (results will be distorted)",
    via: " (via {0})", ptr: "ptr {0}",
    open: "open", closed: "closed", filtered: "filtered", scan_kind: "{0} scan", timeout: "timeout", timeout_rtt: "timeout (rtt {0})",
    open_tcp: "Open TCP ports", col_port: "Port", col_risk: "Risk", col_service: "Service", col_answered: "What answered",
    udp_note: "(advisory: silence cannot tell open from filtered)", findings: "Findings", nothing: "Nothing answered. From this vantage point, nothing is exposed.",
    evidence: "Evidence", what: "What is this", todo: "What to do", rule: "Rule", confidence: " · confidence {0}",
    conf_high: "high — matched identifying evidence", conf_medium: "medium — protocol recognized", conf_low: "low — port number only",
    footer_rec: "Audited {0} · source {1} · rules {2} · snapshot {3} · ", not_checked: "not checked", egress_failed: "lookup failed", dl_html: "Download HTML report", history: "History",
    baseline: "First audit for this label and address family — this is the baseline.", compared: "Compared with {0} ({1}):",
    addr_changed: "Address changed: {0} → this run. It may not be the same line; compare with care.",
    new_tcp: "NEW open TCP ports: {0}", new_udp: "NEW answering UDP ports: {0}", gone: "No longer open: {0}", udp_gone: "UDP no longer answering: {0}",
    answers_diff: "{0}/tcp answers differently: ", no_change: "No change in open ports.",
    no_audits: "No audits yet. ", n_open: "{0} open", n_snaps: "{0} snapshot(s)", last: " · last {0}",
    compare_sel: "Compare selected", compare_hint: "Select two snapshots of the same address family to compare side by side.",
    hist_title: "History — {0}", addr_event: "Address changed: {0}", new_short: "New: {0}", closed_short: "Closed: {0}", back: "← History — {0}",
    compare: "Compare", not_scanned: "not scanned in this run", not_open: "not open", no_ports: "No open ports in either snapshot.",
    log_title: "Audit log", log_note: "Every login and audit on this server, newest first (audit.log in the data directory).",
    col_time: "Time", col_action: "Action", col_from: "From", col_details: "Details", unreachable: "Cannot reach the server: {0}",
    risk_high: "HIGH", risk_medium: "MEDIUM", risk_low: "LOW", risk_info: "INFO", risk_none: "CLEAN",
    ps_name_full: "full", ps_name_quick: "quick", ps_name_custom: "custom", whole: "whole target",
    "udp_open": "open", "udp_closed": "closed", "udp_open|filtered": "open|filtered",
    https_only: " (HTTPS-only port: plaintext request rejected)", self_signed: " self-signed", expired: " EXPIRED", lang_switch: "中文",
    lh_title: "From LanHound: each device's IPv6", lh_intro: "IPv6 has no NAT, so every device is its own exposure. Load the device table exported by LanHound (devices.csv); WanHound audits each device's public IPv6 address one at a time.",
    lh_file: "LanHound export (devices.csv)", lh_all: "Use every public IPv6 of each device (default: the most recent one)", lh_preview: "Read devices",
    lh_none: "No device in this export has a public IPv6 address.", lh_found: "{0} device address(es) found — select up to {1}:", lh_device: "Device",
    lh_rotate: "IPv6 privacy addresses rotate; addresses LanHound saw a while ago may be gone.", lh_start: "Audit selected devices", lh_need: "Select at least one device.",
    lh_too_many: "Select at most {0} devices.", ps_quick_short: "Quick set (recommended for many devices)", ps_full_short: "All ports",
    batch: "Device {0} of {1}: {2}", batch_summary: "Devices", col_ipv6: "IPv6", col_new: "New", col_worst: "Worst",
    del: "Delete", del_confirm: "Confirm delete", del_label: "Delete this label and its history", deleted: "Deleted.",
  },
  zh: {
    signin: "登录", signin_note: "这台 WanHound 服务器受口令保护，每次审计都会被记录。", password: "口令",
    bad_pw: "口令错误。", throttled: "失败次数过多，请稍后再试。",
    nav_new: "新建审计", nav_task: "当前任务", nav_history: "历史", nav_log: "审计日志", logout: "退出",
    footer: "对你自家网络公网暴露面的自查。只审计你拥有或已获授权测试的地址。",
    ph_v4: "路由器 WAN 口的 IPv4", ph_v6: "设备的公网 IPv6",
    start: "开始审计", need_addr: "请至少填写一个地址。", need_auth: "请确认你拥有这些地址或已获授权测试。",
    new_title: "新建审计", new_intro: "从这台服务器的视角，审计你家的一个公网 IPv4 和/或一个 IPv6 地址。请在被审计网络之外运行 WanHound。",
    label_lbl: "家庭标签（历史按标签保存，而不是按 IP）", v4_lbl: "公网 IPv4", v6_lbl: "公网 IPv6", ports: "端口",
    ps_full: "全部 65535 个端口（推荐，1–3 分钟）", ps_quick: "快速集（{0} 个常用端口，几秒钟）", ps_custom: "自定义：",
    udp_opt: "同时探测家庭常用 UDP 端口（{0}）——仅供参考",
    offline_opt: "离线：不做任何第三方查询（ASN/运营商画像和出口自检会把地址发送给公共查询服务）",
    auth_b: "我拥有这些地址，或已获授权测试。", auth_rest: "本次审计、目标地址和你的访问地址都会记入审计日志。",
    running: "有审计正在进行（{0}）。", watch: "查看进度", lab: "实验模式：这台服务器允许私网和回环目标（测试靶机）。",
    no_audit: "还没有审计", start_one: "开始一次", auditing: "审计中…", st_done: "审计完成", st_failed: "审计失败", st_cancelled: "审计已取消",
    task_meta: "标签「{0}」· {1} · {2}扫描 · 开始于 {3}", cancel: "取消",
    stg_check: "检查扫描位置", stg_profile: "查询地址画像", stg_tcp: "TCP 连接扫描", stg_probe: "识别服务", stg_udp: "UDP 探测", stg_start: "启动中",
    not_audited: "未审计：{0}", continue_anyway: "仍然继续（结果会失真）",
    via: "（经由 {0}）", ptr: "反向解析 {0}",
    open: "开放", closed: "关闭", filtered: "被过滤", scan_kind: "{0}扫描", timeout: "超时", timeout_rtt: "超时（RTT {0}）",
    open_tcp: "开放的 TCP 端口", col_port: "端口", col_risk: "风险", col_service: "服务", col_answered: "应答内容",
    udp_note: "（仅供参考：没有应答无法区分开放与被过滤）", findings: "结论", nothing: "没有任何端口应答。从这个扫描点看，没有暴露面。",
    evidence: "证据", what: "这是什么", todo: "怎么办", rule: "规则", confidence: " · 置信度{0}",
    conf_high: "高（匹配到识别性证据）", conf_medium: "中（识别出协议）", conf_low: "低（仅凭端口号）",
    footer_rec: "审计于 {0} · 扫描源 {1} · 规则库 {2} · 快照 {3} · ", not_checked: "未检查", egress_failed: "查询失败", dl_html: "下载 HTML 报告", history: "历史",
    baseline: "这是该标签和地址族的第一次审计——作为基线。", compared: "与 {0}（{1}）相比：",
    addr_changed: "地址已变化：{0} → 本次。可能已不是同一条线路，对比请谨慎。",
    new_tcp: "新开放的 TCP 端口：{0}", new_udp: "新应答的 UDP 端口：{0}", gone: "已不再开放：{0}", udp_gone: "UDP 已不再应答：{0}",
    answers_diff: "{0}/tcp 的应答发生变化：", no_change: "开放端口没有变化。",
    no_audits: "还没有审计。", n_open: "{0} 个开放", n_snaps: "{0} 个快照", last: " · 最近 {0}",
    compare_sel: "对比所选", compare_hint: "选择同一地址族的两个快照进行并排对比。",
    hist_title: "历史 — {0}", addr_event: "地址变化：{0}", new_short: "新开放：{0}", closed_short: "已关闭：{0}", back: "← 历史 — {0}",
    compare: "对比", not_scanned: "本次未扫描该端口", not_open: "未开放", no_ports: "两个快照都没有开放端口。",
    log_title: "审计日志", log_note: "这台服务器上的所有登录和审计，按时间倒序（数据目录下的 audit.log）。",
    col_time: "时间", col_action: "动作", col_from: "来源", col_details: "详情", unreachable: "无法连接服务器：{0}",
    risk_high: "高危", risk_medium: "中危", risk_low: "低危", risk_info: "提示", risk_none: "无风险",
    ps_name_full: "全端口", ps_name_quick: "快速", ps_name_custom: "自定义", whole: "整体",
    "udp_open": "开放", "udp_closed": "关闭", "udp_open|filtered": "开放或被过滤",
    https_only: "（仅 HTTPS：明文请求被拒绝）", self_signed: " 自签名", expired: " 已过期", lang_switch: "EN",
    lh_title: "从 LanHound 导入：逐台审计设备 IPv6", lh_intro: "IPv6 没有 NAT，每台设备都是独立的暴露面。载入 LanHound 导出的设备表（devices.csv），WanHound 会逐台审计每台设备的公网 IPv6 地址。",
    lh_file: "LanHound 导出文件（devices.csv）", lh_all: "使用每台设备的全部公网 IPv6（默认只用最近的一个）", lh_preview: "读取设备",
    lh_none: "这个导出文件中没有任何设备拥有公网 IPv6 地址。", lh_found: "找到 {0} 个设备地址——最多选择 {1} 个：", lh_device: "设备",
    lh_rotate: "IPv6 隐私地址会轮换，LanHound 较早看到的地址可能已失效。", lh_start: "审计所选设备", lh_need: "请至少选择一台设备。",
    lh_too_many: "最多选择 {0} 台设备。", ps_quick_short: "快速集（设备多时推荐）", ps_full_short: "全部端口",
    batch: "第 {0}/{1} 台设备：{2}", batch_summary: "设备", col_ipv6: "IPv6", col_new: "新开放", col_worst: "最高风险",
    del: "删除", del_confirm: "确认删除", del_label: "删除此标签及全部历史", deleted: "已删除。",
  },
};

function storedLang() {
  try { return localStorage.getItem("wanhound_lang"); } catch (_) { return null; }
}
let lang = storedLang() || ((navigator.language || "").toLowerCase().startsWith("zh") ? "zh" : "en");

// tr looks up a UI string and fills {0}, {1}… placeholders.
function tr(key, ...args) {
  const s = (L[lang] && L[lang][key]) || L.en[key] || key;
  return s.replace(/\{(\d)\}/g, (_, i) => String(args[+i]));
}
const txt = (m) => (m && typeof m === "object" ? m.text : m) || "";

function applyStatic() {
  document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
  document.querySelectorAll("[data-i18n]").forEach((n) => { n.textContent = tr(n.dataset.i18n); });
}

document.getElementById("lang").addEventListener("click", () => {
  lang = lang === "zh" ? "en" : "zh";
  try { localStorage.setItem("wanhound_lang", lang); } catch (_) { /* private mode */ }
  applyStatic();
  if (session) route(); else showLogin();
});

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
const badge = (r) => el("span", { class: "badge " + r }, tr("risk_" + r));
const maxRisk = (fs) => (fs && fs.length ? fs.reduce((m, f) => (riskOrder[f.risk] > riskOrder[m] ? f.risk : m), "info") : "none");
const where = (f) => (f.port ? f.port + "/" + f.proto : tr("whole"));

function evidenceOf(info) {
  const parts = [];
  if (info.banner) parts.push("banner " + JSON.stringify(info.banner));
  if (info.tls) {
    let s = "TLS" + (info.tls.cn ? " cn=" + JSON.stringify(info.tls.cn) : "");
    if (info.tls.issuer && info.tls.issuer !== info.tls.cn) s += " issuer=" + JSON.stringify(info.tls.issuer);
    if (info.tls.self_signed) s += tr("self_signed");
    if (info.tls.expired) s += tr("expired");
    parts.push(s);
  }
  if (info.http) {
    let s = "HTTP " + info.http.status;
    if (info.http.title) s += " title=" + JSON.stringify(info.http.title);
    if (info.http.server) s += " server=" + JSON.stringify(info.http.server);
    if (info.http.https_only) s += tr("https_only");
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
  document.body.classList.add("is-login");
  const pw = el("input", { type: "password", id: "pw", autocomplete: "current-password", required: true });
  const msg = el("div");
  if (message) msg.append(errorBox(message));
  const btn = el("button", { class: "primary block", type: "submit" }, tr("signin"));
  const form = el("form", { class: "card login", onsubmit: async (e) => {
    e.preventDefault();
    btn.disabled = true;
    msg.replaceChildren();
    try {
      await api("POST", "/api/login", { password: pw.value });
      await boot();
    } catch (err) {
      const m = err.message || "";
      msg.append(errorBox(m === "wrong password" ? tr("bad_pw") : m.startsWith("too many failed logins") ? tr("throttled") : m));
      btn.disabled = false;
      pw.select();
    }
  } },
    el("div", { class: "login-brand" }, el("img", { src: "logo.svg", alt: "", width: 56, height: 56 }),
      el("div", { class: "login-name" }, "Wan", el("b", {}, "Hound"))),
    el("h1", {}, tr("signin")),
    el("p", { class: "muted small" }, tr("signin_note")),
    el("label", { class: "f", for: "pw" }, tr("password")), pw, msg, btn);
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
    ipv4: el("input", { type: "text", id: "ipv4", placeholder: tr("ph_v4"), inputmode: "decimal", autocomplete: "off" }),
    ipv6: el("input", { type: "text", id: "ipv6", placeholder: tr("ph_v6"), autocomplete: "off" }),
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
  const submit = el("button", { class: "primary", type: "submit" }, tr("start"));

  const form = el("form", { class: "card", onsubmit: async (e) => {
    e.preventDefault();
    msg.replaceChildren();
    const body = {
      label: f.label.value.trim(), ipv4: f.ipv4.value.trim(), ipv6: f.ipv6.value.trim(),
      port_set: form.querySelector("input[name=portset]:checked").value, ports: f.ports.value.trim(),
      udp: f.udp.checked, offline: f.offline.checked, authorized: f.authorized.checked, accept_inside: false, lang,
    };
    if (!body.ipv4 && !body.ipv6) { msg.append(errorBox(tr("need_addr"))); return; }
    if (!body.authorized) { msg.append(errorBox(tr("need_auth"))); return; }
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
    el("h1", {}, tr("new_title")),
    el("p", { class: "muted small" }, tr("new_intro")),
    el("datalist", { id: "labels" }, labels.map((l) => el("option", { value: l.label }))),
    el("div", { class: "grid2" },
      el("div", {}, el("label", { class: "f", for: "label" }, tr("label_lbl")), f.label),
      el("div"),
      el("div", {}, el("label", { class: "f", for: "ipv4" }, tr("v4_lbl")), f.ipv4),
      el("div", {}, el("label", { class: "f", for: "ipv6" }, tr("v6_lbl")), f.ipv6)),
    el("h3", {}, tr("ports")),
    el("div", { class: "opts" },
      radio("full", tr("ps_full"), true),
      radio("quick", tr("ps_quick", session.quick_ports), false),
      radio("custom", tr("ps_custom"), false), f.ports),
    el("label", { class: "check" }, f.udp, el("span", {}, tr("udp_opt", (session.udp_ports || []).join(", ")))),
    el("label", { class: "check" }, f.offline, el("span", {}, tr("offline_opt"))),
    el("label", { class: "check" }, f.authorized, el("span", {}, el("b", {}, tr("auth_b")), tr("auth_rest"))),
    msg, submit);

  const nodes = [];
  if (task && task.state === "running") {
    nodes.push(el("div", { class: "warn" }, tr("running", task.targets.join(", ")), el("a", { href: "#/task" }, tr("watch"))));
    submit.disabled = true;
  }
  if (session.lab) nodes.push(el("div", { class: "warn" }, tr("lab")));
  setView(...nodes, form, lanhoundCard(f.label, task && task.state === "running"));
}

// lanhoundCard: upload a LanHound devices.csv, pick devices, audit each
// device's public IPv6 one after another.
function lanhoundCard(labelInput, busy) {
  const file = el("input", { type: "file", id: "lhfile", accept: ".csv,text/csv" });
  const all = el("input", { type: "checkbox", id: "lhall" });
  const msg = el("div");
  const list = el("div");
  const read = el("button", { type: "button", onclick: async () => {
    msg.replaceChildren(); list.replaceChildren();
    if (!file.files.length) return;
    try {
      const text = await file.files[0].text();
      const res = await api("POST", "/api/lanhound/preview", { csv: text, all: all.checked });
      renderPicker(res.targets, res.max);
    } catch (err) { msg.append(errorBox(err.message)); }
  } }, tr("lh_preview"));

  function renderPicker(targets, max) {
    if (!targets.length) { list.append(el("div", { class: "warn" }, tr("lh_none"))); return; }
    const boxes = targets.map((t, i) => el("input", { type: "checkbox", checked: i < max, "aria-label": t.device }));
    const quick = el("input", { type: "radio", name: "lhset", value: "quick", checked: true });
    const full = el("input", { type: "radio", name: "lhset", value: "full" });
    const udp = el("input", { type: "checkbox", checked: true });
    const auth = el("input", { type: "checkbox" });
    const go = el("button", { class: "primary", type: "button", disabled: busy, onclick: async () => {
      msg.replaceChildren();
      const picked = targets.filter((_, i) => boxes[i].checked);
      if (!picked.length) { msg.append(errorBox(tr("lh_need"))); return; }
      if (picked.length > max) { msg.append(errorBox(tr("lh_too_many", max))); return; }
      if (!auth.checked) { msg.append(errorBox(tr("need_auth"))); return; }
      go.disabled = true;
      try {
        await api("POST", "/api/lanhound/scan", { label: labelInput.value.trim(), port_set: full.checked ? "full" : "quick",
          udp: udp.checked, offline: false, authorized: true, lang, targets: picked });
        location.hash = "#/task";
      } catch (err) { msg.append(errorBox(err.message)); go.disabled = false; }
    } }, tr("lh_start"));
    list.append(
      el("p", { class: "small" }, tr("lh_found", targets.length, max)),
      el("div", { class: "scroll" }, el("table", { class: "tbl" },
        el("thead", {}, el("tr", {}, el("th", {}, ""), el("th", {}, tr("lh_device")), el("th", {}, tr("col_ipv6")))),
        el("tbody", {}, targets.map((t, i) => el("tr", {}, el("td", {}, boxes[i]), el("td", {}, t.device), el("td", { class: "mono" }, t.ipv6)))))),
      el("p", { class: "muted small" }, tr("lh_rotate")),
      el("div", { class: "opts" }, el("label", { class: "check" }, quick, tr("ps_quick_short")), el("label", { class: "check" }, full, tr("ps_full_short"))),
      el("label", { class: "check" }, udp, el("span", {}, tr("udp_opt", (session.udp_ports || []).join(", ")))),
      el("label", { class: "check" }, auth, el("span", {}, el("b", {}, tr("auth_b")), tr("auth_rest"))),
      go);
  }

  return el("div", { class: "card" },
    el("h2", {}, tr("lh_title")),
    el("p", { class: "muted small" }, tr("lh_intro")),
    el("label", { class: "f", for: "lhfile" }, tr("lh_file")),
    el("div", { class: "row" }, file, read),
    el("label", { class: "check" }, all, el("span", {}, tr("lh_all"))),
    msg, list);
}

// ---- running task ------------------------------------------------------

function stopPolling() {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = null;
}

async function viewTask() {
  stopPolling();
  let task;
  try { task = (await api("GET", "/api/task?" + q({ lang }))).task; } catch (_) { return; }
  if (location.hash !== "#/task") return;
  if (!task) {
    setView(el("div", { class: "card" }, el("h1", {}, tr("no_audit")), el("p", {}, el("a", { href: "#/" }, tr("start_one")))));
    return;
  }
  const head = el("div", { class: "card" },
    el("h1", {}, task.state === "running" ? tr("auditing") : tr("st_" + task.state)),
    el("p", { class: "muted small" }, tr("task_meta", task.label, task.targets.join(" + "), tr("ps_name_" + task.port_set), fmtTime(task.started))));
  if (task.state === "running") {
    const c = task.current || {};
    const pct = c.stage === "tcp" && c.total ? Math.floor((c.done || 0) * 100 / c.total) : null;
    const bar = el("div", { class: "bar", role: "progressbar", "aria-valuemin": 0, "aria-valuemax": 100, "aria-valuenow": pct ?? 0 }, el("div"));
    bar.firstChild.style.width = (pct ?? 3) + "%";
    if (task.devices && task.devices.length > 1) head.append(el("p", { class: "small" }, tr("batch", task.index + 1, task.devices.length, task.devices[task.index])));
    head.append(bar, el("p", { class: "small" }, c.target ? c.target + " — " : "", stageText(c), pct !== null ? ` ${pct}% (${c.done}/${c.total})` : ""));
    head.append(el("button", { class: "danger", type: "button", onclick: async (e) => {
      e.target.disabled = true;
      try { await api("POST", "/api/task/cancel"); } catch (err) { head.append(errorBox(err.message)); }
    } }, tr("cancel")));
  }
  if (task.log && task.log.length) head.append(el("ul", { class: "log" }, task.log.map((l) => el("li", {}, l))));
  if (task.error) head.append(errorBox(task.error));
  const nodes = [head];
  const reports = task.reports || [];
  if (reports.length > 1 || (task.devices && task.devices.length > 1)) nodes.push(batchSummary(task, reports));
  else if (reports.length === 1) nodes.push(...renderReport(reports[0]));
  setView(...nodes);
  if (task.state === "running") pollTimer = setTimeout(viewTask, 1000);
}

// batchSummary: one row per audited device, linking to its snapshot.
function batchSummary(task, reports) {
  const rows = reports.map((rep, i) => {
    const s = (rep.targets || [])[0];
    const device = (task.devices || [])[i] || "";
    if (!s) return el("tr", {}, el("td", {}, device), el("td", { colspan: 4 }, (rep.errors || []).map((e) => txt(e.reason)).join(" ")));
    const worst = maxRisk(s.findings);
    return el("tr", { class: "r-" + worst },
      el("td", {}, el("a", { href: `#/snap/${encodeURIComponent(s.label)}/${s.id}` }, device)),
      el("td", { class: "mono" }, s.ip), el("td", {}, String(s.counts.open)), el("td", {}, badge(worst)),
      el("td", { class: "new" }, s.changes && s.changes.opened ? s.changes.opened.join(", ") : ""));
  });
  return el("div", { class: "card scroll" }, el("h2", {}, tr("batch_summary")), el("table", { class: "tbl" },
    el("thead", {}, el("tr", {}, el("th", {}, tr("lh_device")), el("th", {}, tr("col_ipv6")), el("th", {}, tr("open")), el("th", {}, tr("col_worst")), el("th", {}, tr("col_new")))),
    el("tbody", {}, rows)));
}

// confirmButton: a two-step inline confirmation (no browser dialogs).
function confirmButton(label, onConfirm) {
  const b = el("button", { type: "button", class: "danger small-btn" }, label);
  let armed = false;
  b.addEventListener("click", async () => {
    if (!armed) { armed = true; b.textContent = tr("del_confirm"); setTimeout(() => { armed = false; b.textContent = label; }, 4000); return; }
    b.disabled = true;
    try { await onConfirm(); } catch (err) { b.after(errorBox(err.message)); b.disabled = false; }
  });
  return b;
}

function stageText(c) {
  return c.stage ? tr("stg_" + c.stage) : tr("stg_start");
}

function renderReport(rep) {
  const nodes = [];
  for (const e of rep.errors || []) {
    const box = el("div", { class: "card" }, el("h2", {}, tr("not_audited", e.ip)), el("p", {}, txt(e.reason)));
    if (e.inside && lastScanBody) {
      box.append(el("button", { type: "button", onclick: async (ev) => {
        ev.target.disabled = true;
        try {
          await api("POST", "/api/scan", { ...lastScanBody, accept_inside: true, lang, ipv4: e.ip.includes(":") ? "" : e.ip, ipv6: e.ip.includes(":") ? e.ip : "" });
          viewTask();
        } catch (err) { box.append(errorBox(err.message)); }
      } }, tr("continue_anyway")));
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
    const bits = [[p.asn, p.org].filter(Boolean).join(" "), p.country, (p.ptr || []).map((x) => tr("ptr", x)).join(", ")].filter(Boolean);
    if (bits.length) card.append(el("p", { class: "muted small" }, bits.join(" · "), p.source ? tr("via", p.source) : ""));
    for (const h of p.hints || []) card.append(el("div", { class: "warn small" }, txt(h)));
  }
  card.append(el("div", { class: "stats" },
    stat(s.counts.open, tr("open")), stat(s.counts.closed, tr("closed")), stat(s.counts.filtered, tr("filtered")),
    stat(dur(s.duration_ns), tr("scan_kind", tr("ps_name_" + s.port_set))), stat(ms(s.timeout_ns), s.rtt_ns ? tr("timeout_rtt", ms(s.rtt_ns)) : tr("timeout"))));
  card.append(renderChanges(s.changes));

  // Port table.
  const byPort = {};
  for (const f of s.findings || []) if (f.proto === "tcp") (byPort[f.port] = byPort[f.port] || []).push(f);
  if ((s.open || []).length) {
    card.append(el("h3", {}, tr("open_tcp")), el("div", { class: "scroll" }, el("table", { class: "tbl" },
      el("thead", {}, el("tr", {}, el("th", {}, tr("col_port")), el("th", {}, tr("col_risk")), el("th", {}, tr("col_service")), el("th", {}, tr("col_answered")))),
      el("tbody", {}, s.open.map((o) => {
        const top = (byPort[o.port] || [{ risk: "info", service: "?" }])[0];
        return el("tr", { class: "r-" + top.risk }, el("td", { class: "mono" }, o.port + "/tcp"), el("td", {}, badge(top.risk)),
          el("td", {}, top.service), el("td", {}, el("code", {}, evidenceOf(o) || "—")));
      })))));
  }
  if ((s.udp || []).length) {
    card.append(el("h3", {}, "UDP ", el("span", { class: "muted small" }, tr("udp_note"))),
      el("div", { class: "scroll" }, el("table", { class: "tbl" },
        el("tbody", {}, s.udp.map((u) => el("tr", {}, el("td", { class: "mono" }, u.port + "/udp"), el("td", {}, u.service),
          el("td", {}, tr("udp_" + u.state)), el("td", { class: "small" }, u.detail || "")))))));
  }

  // Findings.
  card.append(el("h3", {}, tr("findings")));
  if (!(s.findings || []).length) card.append(el("div", { class: "good" }, tr("nothing")));
  for (const f of s.findings || []) {
    card.append(el("details", { class: "finding " + f.risk, open: f.risk === "high" },
      el("summary", {}, badge(f.risk), el("span", { class: "mono" }, where(f)), el("b", {}, f.title), el("span", { class: "muted small" }, f.rule_id)),
      el("div", { class: "body" },
        f.evidence ? el("p", {}, el("span", { class: "k" }, tr("evidence")), el("code", {}, f.evidence)) : null,
        el("p", {}, el("span", { class: "k" }, tr("what")), f.explain),
        el("p", {}, el("span", { class: "k" }, tr("todo")), f.advice),
        el("p", { class: "small muted" }, el("span", { class: "k" }, tr("rule")), f.rule_id, f.confidence ? tr("confidence", tr("conf_" + f.confidence)) : ""))));
  }
  if ((s.notes || []).length) card.append(el("ul", { class: "small muted" }, s.notes.map((n) => el("li", {}, txt(n)))));
  card.append(el("p", { class: "small muted" },
    tr("footer_rec", fmtTime(s.time), s.egress || (s.egress_source === "failed" ? tr("egress_failed") : tr("not_checked")), s.rules_version, s.id),
    el("a", { href: "/api/snapshot/html?" + q({ label: s.label, id: s.id, lang }) }, tr("dl_html")), " · ",
    el("a", { href: "#/history/" + encodeURIComponent(s.label) }, tr("history"))));
  return [card];
}

function stat(v, label) { return el("div", { class: "stat" }, el("b", {}, String(v)), el("span", { class: "muted small" }, label)); }

function renderChanges(ch) {
  if (!ch) return el("p", { class: "muted small" }, tr("baseline"));
  const box = el("div", { class: ch.opened || ch.udp_opened ? "warn" : "good" },
    el("div", { class: "small" }, tr("compared", fmtTime(ch.prev_time), ch.prev_ip)));
  if (ch.ip_changed) box.append(el("div", { class: "event" }, tr("addr_changed", ch.prev_ip)));
  if (ch.opened) box.append(el("div", { class: "new" }, tr("new_tcp", ch.opened.join(", "))));
  if (ch.udp_opened) box.append(el("div", { class: "new" }, tr("new_udp", ch.udp_opened.join(", "))));
  if (ch.closed) box.append(el("div", { class: "gone" }, tr("gone", ch.closed.join(", "))));
  if (ch.udp_closed) box.append(el("div", { class: "gone" }, tr("udp_gone", ch.udp_closed.join(", "))));
  for (const c of ch.changed || []) box.append(el("div", { class: "small" }, tr("answers_diff", c.port), el("code", {}, c.before), " → ", el("code", {}, c.after)));
  if (!ch.opened && !ch.closed && !ch.changed && !ch.udp_opened && !ch.udp_closed) box.append(el("div", {}, tr("no_change")));
  if (ch.coverage) box.append(el("div", { class: "small muted" }, txt(ch.coverage)));
  return box;
}

// ---- history -----------------------------------------------------------

async function viewLabels() {
  let labels;
  try { labels = await api("GET", "/api/labels"); } catch (_) { return; }
  if (!labels.length) {
    setView(el("div", { class: "card" }, el("h1", {}, tr("history")), el("p", {}, tr("no_audits"), el("a", { href: "#/" }, tr("start_one")))));
    return;
  }
  setView(el("h1", {}, tr("history")), el("div", { class: "labels" }, labels.map((l) =>
    el("a", { href: "#/history/" + encodeURIComponent(l.label) }, el("div", { class: "card" },
      el("h2", {}, l.label),
      l.last ? el("p", { class: "small" }, badge(l.last.max_risk), " " + tr("n_open", l.last.counts.open) + " · " + l.last.ip) : null,
      el("p", { class: "muted small" }, tr("n_snaps", l.count), l.last ? tr("last", fmtTime(l.last.time)) : ""))))));
}

async function viewHistory(label) {
  let metas;
  try { metas = await api("GET", "/api/history?" + q({ label })); } catch (_) { return; }
  const picked = [];
  const cmp = el("button", { class: "primary", type: "button", disabled: true, onclick: () => {
    location.hash = `#/diff/${encodeURIComponent(label)}/${picked[0]}/${picked[1]}`;
  } }, tr("compare_sel"));
  const hint = el("span", { class: "muted small" }, tr("compare_hint"));
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
        el("span", { class: "mono" }, m.ip), el("span", { class: "muted small" }, `IP${m.family} · ${tr("ps_name_" + m.port_set)} · ${tr("n_open", m.counts.open)}`)),
      m.ip_change ? el("div", { class: "event" }, tr("addr_event", m.ip_change)) : null,
      m.opened ? el("div", { class: "new small" }, tr("new_short", m.opened.join(", "))) : null,
      m.closed ? el("div", { class: "gone small" }, tr("closed_short", m.closed.join(", "))) : null,
      el("div", {}, confirmButton(tr("del"), async () => {
        await api("POST", "/api/snapshot/delete", { label, id: m.id });
        viewHistory(label);
      }))));
  }));
  const delLabel = confirmButton(tr("del_label"), async () => {
    await api("POST", "/api/label/delete", { label });
    location.hash = "#/history";
  });
  setView(el("h1", {}, tr("hist_title", label)), el("div", { class: "card" }, el("div", { class: "row" }, cmp, hint), list),
    el("div", { class: "row" }, delLabel));
}

async function viewSnapshot(label, id) {
  let s;
  try { s = await api("GET", "/api/snapshot?" + q({ label, id, lang })); } catch (err) { setView(errorBox(err.message)); return; }
  setView(el("p", {}, el("a", { href: "#/history/" + encodeURIComponent(label) }, tr("back", label))), ...renderSnapshot(s));
}

async function viewDiff(label, a, b) {
  let d;
  try { d = await api("GET", "/api/diff?" + q({ label, a, b, lang })); } catch (err) { setView(errorBox(err.message)); return; }
  const A = d.a, B = d.b;
  const ports = [...new Set([...(A.open || []), ...(B.open || [])].map((o) => o.port))].sort((x, y) => x - y);
  const find = (s, p) => (s.open || []).find((o) => o.port === p);
  const topRisk = (s, p) => { const f = (s.findings || []).find((x) => x.port === p && x.proto === "tcp"); return f ? f : null; };
  const cell = (s, p, cls) => {
    const o = find(s, p);
    if (!o && !covers(s.scanned, p)) return el("td", { class: "diffcell" }, el("span", { class: "muted" }, tr("not_scanned")));
    if (!o) return el("td", { class: "diffcell " + cls }, el("span", { class: "muted" }, tr("not_open")));
    const f = topRisk(s, p);
    return el("td", { class: "diffcell " + cls }, f ? badge(f.risk) : null, " ", f ? f.title : "", el("div", {}, el("code", {}, evidenceOf(o))));
  };
  const head = (s) => el("th", {}, fmtTime(s.time), el("div", { class: "mono" }, s.ip), el("div", { class: "muted small" }, `${tr("ps_name_" + s.port_set)} · ${tr("n_open", s.counts.open)}`));
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
    el("p", {}, el("a", { href: "#/history/" + encodeURIComponent(label) }, tr("back", label))),
    el("h1", {}, tr("compare")),
    d.warning ? el("div", { class: "warn" }, d.warning) : null,
    el("div", { class: "card" }, renderChanges(d.changes),
      el("div", { class: "scroll" }, el("table", { class: "tbl" },
        el("thead", {}, el("tr", {}, el("th", {}, tr("col_port")), head(A), head(B))),
        el("tbody", {}, rows.length ? rows : el("tr", {}, el("td", { colspan: 3 }, tr("no_ports"))))))));
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
  setView(el("h1", {}, tr("log_title")), el("p", { class: "muted small" }, tr("log_note")),
    el("div", { class: "card scroll" }, el("table", { class: "tbl" },
      el("thead", {}, el("tr", {}, el("th", {}, tr("col_time")), el("th", {}, tr("col_action")), el("th", {}, tr("col_from")), el("th", {}, tr("col_details")))),
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
    setView(errorBox(tr("unreachable", err.message)));
    return;
  }
  document.getElementById("nav").hidden = false;
  document.body.classList.remove("is-login");
  route();
}

window.addEventListener("hashchange", route);
applyStatic();
boot();
