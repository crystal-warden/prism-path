// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
"use strict";
const API = "/api/v1";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => (s == null ? "" : String(s)).replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const jget = async url => (await fetch(API + url)).json();
const jpost = async (url, b) => (await fetch(API + url, {
  method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {})
})).json();
let TAB = "graph", cy = null, GRAPH = null, RETR = [];

function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.classList.remove("hidden");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add("hidden"), 2600);
}
const short = s => { s = (s || "").replace(/^when\s+/i, ""); return s.length > 26 ? s.slice(0, 24) + "…" : s; };

/* ---------------- status pills + control ---------------- */
function updateStatus(s) {
  if (!s) return;
  const run = $("#p-run");
  run.textContent = s.running ? "running" : (s.paused ? "paused" : "idle");
  run.className = "pill " + (s.running ? "run" : "stopped");
  $("#p-iter").textContent = s.iteration != null ? "it " + s.iteration : "";
  const v = $("#p-valid");
  if (s.iteration != null) { v.textContent = s.valid ? "gate ✓" : "gate ✗"; v.className = "pill " + (s.valid ? "ok" : "bad"); }
  else v.textContent = "";
  const buf = $("#p-buf");
  buf.textContent = s.unbuffered === true ? "unbuffered" : s.unbuffered === false ? "buffered" : "";
  $("#p-audit").textContent = "audit " + (s.audit_n ?? 0);
  $("#c-proj").textContent = s.dir || "";
}
function setConn(on) {
  const c = $("#p-conn");
  c.textContent = on ? "● live" : "● offline";
  c.className = "pill " + (on ? "on" : "off");
}

/* ---------------- SSE ---------------- */
function connectSSE() {
  const es = new EventSource(API + "/events");
  es.onopen = () => setConn(true);
  es.onerror = () => setConn(false);                 // EventSource auto-reconnects
  es.onmessage = ev => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.type === "status") updateStatus(m.status);
    else if (m.type === "interactions") { loadRetrievals(); if (TAB === "audit") loadAudit(); }
    else if (m.type === "graph") { if (TAB === "graph") refreshActive(); }
  };
}

/* ---------------- tabs ---------------- */
function showTab(v) {
  TAB = v;
  $$(".tab").forEach(t => t.classList.toggle("active", t.dataset.v === v));
  $$(".view").forEach(el => el.classList.toggle("active", el.id === "v-" + v));
  if (v === "graph") loadGraph(true);
  else if (v === "files") loadFiles();
  else if (v === "audit") loadAudit();
  else if (v === "queue") loadQueue();
  else if (v === "flows") loadFlows();
}

/* ---------------- graph (the command center) ---------------- */
const STYLE = [
  { selector: "node", style: { label: "data(label)", "background-color": "#16233a", "border-width": 1.5,
    "border-color": "#2d6b7a", color: "#dbe7ea", "font-size": 11, "font-family": "monospace",
    "text-valign": "center", "text-halign": "center", shape: "round-rectangle", padding: 8,
    width: "label", height: "label", "text-wrap": "wrap", "text-max-width": 120 } },
  { selector: "node.start", style: { "border-color": "#a0e8e0", "border-width": 3 } },
  { selector: "node.terminal", style: { "background-color": "#12233a", "border-color": "#3db87a" } },
  { selector: "node.active", style: { "border-color": "#a0e8e0", "border-width": 4, "background-color": "#163049" } },
  { selector: "node.v-yes", style: { "border-color": "#3db87a", "border-width": 3 } },
  { selector: "node.v-may", style: { "border-color": "#d19a3a", "border-width": 3 } },
  { selector: "node.v-no", style: { "border-color": "#6b7f89", "border-width": 3, "background-color": "#0c121e" } },
  { selector: "edge", style: { width: 2, "curve-style": "bezier", "target-arrow-shape": "triangle",
    "line-color": "#2d6b7a", "target-arrow-color": "#2d6b7a", label: "data(label)", "font-size": 9,
    color: "#8ea3ad", "text-background-color": "#0c121e", "text-background-opacity": 0.85,
    "text-background-padding": 2, "text-rotation": "autorotate" } },
  { selector: "edge.deterministic", style: { "line-color": "#3db87a", "target-arrow-color": "#3db87a" } },
  { selector: "edge.semantic", style: { "line-color": "#d19a3a", "target-arrow-color": "#d19a3a" } },
  { selector: "edge.error", style: { "line-color": "#d9563a", "target-arrow-color": "#d9563a" } },
  { selector: "edge.event", style: { "line-color": "#9a86c9", "target-arrow-color": "#9a86c9" } },
  { selector: "edge.nonm", style: { "line-style": "dashed", "line-color": "#e07b39", "target-arrow-color": "#e07b39", width: 3 } },
];

function buildElements(payload) {
  const els = [];
  for (const [name, n] of Object.entries(payload.nodes || {})) {
    const cls = [];
    if (name === payload.start) cls.push("start");
    if (n.terminal) cls.push("terminal");
    els.push({ data: { id: name, label: name, instr: n.instruction || "" }, classes: cls.join(" ") });
  }
  for (const [name, n] of Object.entries(payload.nodes || {})) {
    (n.edges || []).forEach((e, i) => els.push({ data: {
      id: name + "→" + e.target + "#" + i, source: name, target: e.target,
      cond: e.condition || "", label: short(e.condition) }, classes: e.tier }));
  }
  return els;
}

async function loadGraph(full) {
  let payload; try { payload = await jget("/flow/graph"); } catch { return; }
  if (payload.error) { $("#cy").innerHTML = "<div class=muted style='padding:20px'>" + esc(payload.error) + "</div>"; return; }
  const sameShape = GRAPH && cy && JSON.stringify(Object.keys(payload.nodes || {})) === JSON.stringify(Object.keys(GRAPH.nodes || {}));
  GRAPH = payload;
  $("#g-name").textContent = payload.name || payload.flow_path || "flow";
  // populate reach targets
  const sel = $("#r-targets"); sel.innerHTML = Object.keys(payload.nodes || {}).map(n => `<option>${esc(n)}</option>`).join("");
  if (full || !sameShape) {
    cy = cytoscape({ container: $("#cy"), elements: buildElements(payload), style: STYLE, wheelSensitivity: 0.2 });
    cy.layout({ name: "breadthfirst", directed: true, roots: cy.getElementById(payload.start), spacingFactor: 1.35, padding: 24 }).run();
    cy.on("tap", "node", ev => showNode(ev.target.id()));
  }
  refreshActivePaint();
}
async function refreshActive() {   // light update: active node only, no re-layout
  let payload; try { payload = await jget("/flow/graph"); } catch { return; }
  if (payload.error) return;
  const sameShape = GRAPH && JSON.stringify(Object.keys(payload.nodes || {})) === JSON.stringify(Object.keys(GRAPH.nodes || {}));
  GRAPH = payload;
  if (!sameShape) return loadGraph(true);
  refreshActivePaint();
}
function refreshActivePaint() {
  if (!cy) return;
  cy.nodes().removeClass("active");
  if (GRAPH.active_node) cy.getElementById(GRAPH.active_node).addClass("active");
}

async function proveLevelM() {
  if (!GRAPH || !GRAPH.flow_text) return;
  const r = await jpost("/prove/level-m", { flow: GRAPH.flow_text });
  const chip = $("#g-levelm-chip");
  if (r.error) { chip.textContent = r.error.message || "error"; chip.className = "chip bad"; return; }
  cy.edges().removeClass("nonm");
  (r.non_member_edges || []).forEach(row => {
    cy.edges().filter(e => e.data("source") === row.node && e.data("target") === row.target).addClass("nonm");
  });
  if (r.level_m) { chip.textContent = "Level M ✓ — compiles to a table"; chip.className = "chip ok"; }
  else { chip.textContent = (r.non_member_edges || []).length + " edge(s) outside the fragment"; chip.className = "chip bad"; }
}

async function proveReach() {
  if (!GRAPH || !GRAPH.flow_text) return;
  const targets = $$("#r-targets option").filter(optionEl => optionEl.selected).map(optionEl => optionEl.value);
  if (!targets.length) { toast("select a target node"); return; }
  const assume = $("#r-assume").value.trim();
  const r = await jpost("/prove/reach", { flow: GRAPH.flow_text, reach: targets, assume: assume || undefined });
  const box = $("#r-verdicts");
  if (r.error) { box.innerHTML = `<div class=muted>${esc(r.error.message)}</div>`; return; }
  cy.nodes().removeClass("v-yes v-may v-no");
  box.innerHTML = Object.entries(r.verdicts).map(([n, v]) => {
    cy.getElementById(n).addClass("v-" + v);
    return `<div class="verdict"><span>${esc(n)}</span><span class="v-${v}">${v}</span></div>`;
  }).join("");
}

function showNode(name) {
  const n = GRAPH.nodes[name]; if (!n) return;
  $("#nd-empty").classList.add("hidden");
  const body = $("#nd-body"); body.classList.remove("hidden");
  const edges = (n.edges || []).map(e =>
    `<div class="edge"><b>→ ${esc(e.target)}</b> <span class="muted">[${e.tier}]</span><br>${esc(e.condition || "(default)")}</div>`).join("");
  const nameQuery = name.toLowerCase();
  const hits = RETR.filter(r => (r.query || "").toLowerCase().includes(nameQuery))
    .flatMap(r => r.hits || []).slice(0, 6);
  const retr = hits.length
    ? `<label class=muted style="margin-top:8px;display:block">RAG docs pulled</label>` +
      hits.map(hit => `<div class="retr">[${(hit.score ?? 0).toFixed ? hit.score.toFixed(2) : hit.score}] ${esc(hit.source)}/${esc(hit.path)}</div>`).join("")
    : `<div class="retr" style="margin-top:8px">no matched retrievals</div>`;
  body.innerHTML = `<div style="color:#7fd1ff;font-weight:600">${esc(name)}</div>
    <div class="instr">${esc(n.instruction || "")}</div>${edges}${retr}`;
}

async function loadRetrievals() { try { RETR = (await jget("/retrievals")).retrievals || []; } catch {} }

/* ---------------- files ---------------- */
let CURFILE = null;
async function loadFiles() {
  const payload = await jget("/files");
  $("#filelist").innerHTML = (payload.files || []).map(f =>
    `<div class="f" data-p="${esc(f.path)}"><span>${esc(f.path)}</span><span class="sz">${f.size}</span></div>`).join("");
  $$("#filelist .f").forEach(el => el.onclick = () => openFile(el.dataset.p, el));
}
async function openFile(path, el) {
  $$("#filelist .f").forEach(f => f.classList.remove("sel")); if (el) el.classList.add("sel");
  const payload = await jget("/file?path=" + encodeURIComponent(path));
  if (payload.error) { toast(payload.error.message || "error"); return; }
  CURFILE = path; $("#ed-path").textContent = path; $("#ed-body").value = payload.content; $("#ed-save").disabled = false;
}
async function saveFile() {
  if (!CURFILE) return;
  const r = await jpost("/file", { path: CURFILE, content: $("#ed-body").value });
  toast(r.error ? (r.error.message || "error") : "saved " + CURFILE);
}

/* ---------------- audit ---------------- */
async function loadAudit() {
  const payload = await jget("/audit");
  const vc = $("#a-verify"); vc.textContent = payload.verify ? "verified ✓" : "TAMPERED ✗"; vc.className = "chip " + (payload.verify ? "ok" : "bad");
  $("#a-meta").textContent = `root ${(payload.root || "").slice(0, 20)} · ${payload.n} events`;
  $("#a-events").innerHTML = (payload.events || []).slice().reverse().map(e =>
    `<div class="row"><span class="a">${esc(e.actor || "")}·${esc(e.action || "")}</span>` +
    `<span class="muted">${e.ts ? new Date(e.ts * 1000).toLocaleTimeString() : ""}</span>` +
    `<span class="muted">${esc(JSON.stringify(e.data || {}).slice(0, 120))}</span></div>`).join("");
}

/* ---------------- queue (HITL) ---------------- */
async function loadQueue() {
  const payload = await jget("/queue");
  const items = payload.items || [];
  $("#q-items").innerHTML = items.length ? items.map((it, i) => {
    const opts = (it.options || it.choices || []);
    const id = it.id || it.path || String(i);
    return `<div class="q-item"><div class="a">${esc(id)}</div>
      <div class="muted">${esc(JSON.stringify(it).slice(0, 240))}</div>
      <div class="opts"><input placeholder="edge / choice" data-id="${esc(id)}">
      <button class="btn go" data-decide="${esc(id)}">Decide</button></div></div>`;
  }).join("") : "<div class=muted>nothing awaiting a decision.</div>";
  $$("[data-decide]").forEach(b => b.onclick = async () => {
    const id = b.dataset.decide, choose = $(`input[data-id="${CSS.escape(id)}"]`).value.trim();
    if (!choose) { toast("enter a choice"); return; }
    const r = await jpost("/queue/decide", { id, choose });
    toast(r.error ? (r.error.message || "error") : "recorded"); loadQueue();
  });
}

/* ---------------- flows (fan-outs) ---------------- */
async function loadFlows() {
  const payload = await jget("/fanouts");
  $("#f-tree").innerHTML = (payload.fanouts && payload.fanouts.length)
    ? `<pre class="tree">${esc(JSON.stringify(payload.fanouts, null, 2))}</pre>`
    : "<div class=muted>no fan-out compositions.</div>";
}

/* ---------------- control ---------------- */
async function startSprint(ev) {
  ev.preventDefault();
  const f = ev.target, cfg = {
    proj: f.proj.value.trim() || undefined, gate: f.gate.value.trim() || undefined,
    nudge_file: f.nudge_file.value.trim() || undefined, model: f.model.value.trim() || undefined,
    rag: f.rag.checked, lessons: f.lessons.checked, fresh: f.fresh.checked, unbuffered: f.unbuffered.checked,
  };
  const r = await jpost("/sprint/start", cfg);
  toast(r.error ? (r.error.message || "error") : (r.ok ? `launched (${r.unbuffered ? "unbuffered" : "buffered"}) pid ${r.pid}` : r.error));
}

/* ---------------- wire up ---------------- */
$("#tabs").onclick = e => { if (e.target.dataset.v) showTab(e.target.dataset.v); };
$("#g-refresh").onclick = () => loadGraph(true);
$("#g-levelm").onclick = proveLevelM;
$("#r-go").onclick = proveReach;
$("#ed-save").onclick = saveFile;
$("#c-start-toggle").onclick = () => { $("#startform").classList.toggle("hidden"); };
$("#startform").onsubmit = startSprint;
$$("[data-act]").forEach(b => b.onclick = async () => {
  const r = await jpost("/sprint/" + b.dataset.act, {}); toast(r.error ? r.error.message : (b.dataset.act + " ok"));
});

loadRetrievals();
connectSSE();
showTab("graph");
