// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// Mission Control, operator console.
//
// The whole browser half of the console. It reads the FastAPI app under /api/v1, follows the live
// event stream, and paints five screens into the element ids that index.html declares: the flow
// graph with its two proofs, the project files, the audit log, the human decision queue, and the
// fan-out compositions.
//
// The element ids and the request paths in this file are an unchecked contract with index.html and
// with the FastAPI routers, so they are spelled here exactly as they are spelled there. Anything
// else in this file is local and free to move.
"use strict";

const API_PREFIX = "/api/v1";
const TOAST_MS = 2600;
const CONDITION_LABEL_MAX = 26;

/* ---------------- document and transport helpers ---------------- */
function select(selector, root = document) {
  return root.querySelector(selector);
}

function selectAll(selector, root = document) {
  return [...root.querySelectorAll(selector)];
}

async function getJson(path) {
  const response = await fetch(API_PREFIX + path);
  return response.json();
}

async function postJson(path, body) {
  const response = await fetch(API_PREFIX + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return response.json();
}

/* ---------------- markup ----------------
   One tagged template does every render, so no screen has to remember to escape a server string:
   values interpolate escaped, arrays join, and only markup this helper produced passes through raw. */
const HTML_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;" };

class Markup {
  constructor(text) {
    this.text = text;
  }
}

function escapeText(value) {
  const text = value == null ? "" : String(value);
  return text.replace(/[&<>]/g, character => HTML_ESCAPES[character]);
}

function markupOf(value) {
  if (value instanceof Markup) {
    return value.text;
  }
  if (Array.isArray(value)) {
    return value.map(markupOf).join("");
  }
  return escapeText(value);
}

function html(literals, ...values) {
  let text = literals[0];
  values.forEach((value, slot) => {
    text += markupOf(value) + literals[slot + 1];
  });
  return new Markup(text);
}

function renderInto(selector, markup) {
  select(selector).innerHTML = markupOf(markup);
}

/* ---------------- console state ----------------
   One object instead of loose globals, so every screen reads the same console from one place. */
const state = {
  screen: "graph",
  cytoscapeView: null,   // the rendering library's model, not the flow graph itself
  graph: null,           // the latest /flow/graph payload: nodes, start, active_node, flow_text
  retrievals: [],
  openFilePath: null,
};

/* ---------------- toast, pills, connection ---------------- */
let toastTimer = 0;

function showToast(message) {
  const toast = select("#toast");
  toast.textContent = message;
  toast.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add("hidden"), TOAST_MS);
}

function shortenCondition(condition) {
  // The edge label rides on the picture, so the leading "when" is dropped and the rest is clipped.
  const text = (condition || "").replace(/^when\s+/i, "");
  return text.length > CONDITION_LABEL_MAX ? text.slice(0, 24) + "…" : text;
}

function paintStatusPills(status) {
  if (!status) {
    return;
  }
  const runPill = select("#p-run");
  runPill.textContent = status.running ? "running" : (status.paused ? "paused" : "idle");
  runPill.className = "pill " + (status.running ? "run" : "stopped");
  select("#p-iter").textContent = status.iteration != null ? "it " + status.iteration : "";
  const gatePill = select("#p-valid");
  if (status.iteration != null) {
    gatePill.textContent = status.valid ? "gate ✓" : "gate ✗";
    gatePill.className = "pill " + (status.valid ? "ok" : "bad");
  } else {
    gatePill.textContent = "";
  }
  const bufferPill = select("#p-buf");
  bufferPill.textContent = status.unbuffered === true ? "unbuffered" : status.unbuffered === false ? "buffered" : "";
  select("#p-audit").textContent = "audit " + (status.audit_n ?? 0);
  select("#c-proj").textContent = status.dir || "";
}

function paintConnectionPill(live) {
  const pill = select("#p-conn");
  pill.textContent = live ? "● live" : "● offline";
  pill.className = "pill " + (live ? "on" : "off");
}

/* ---------------- live event stream ---------------- */
function followEventStream() {
  const stream = new EventSource(API_PREFIX + "/events");
  stream.onopen = () => paintConnectionPill(true);
  stream.onerror = () => paintConnectionPill(false);   // EventSource auto-reconnects
  stream.onmessage = message => {
    let event;
    try {
      event = JSON.parse(message.data);
    } catch {
      return;
    }
    if (event.type === "status") {
      paintStatusPills(event.status);
    } else if (event.type === "interactions") {
      loadRetrievals();
      if (state.screen === "audit") {
        loadAuditScreen();
      }
    } else if (event.type === "graph") {
      if (state.screen === "graph") {
        refreshActiveNode();
      }
    }
  };
}

/* ---------------- screens ---------------- */
const SCREEN_LOADERS = {
  graph: () => loadGraphScreen(true),
  files: () => loadFilesScreen(),
  audit: () => loadAuditScreen(),
  queue: () => loadQueueScreen(),
  flows: () => loadFlowsScreen(),
};

function showScreen(name) {
  state.screen = name;
  selectAll(".tab").forEach(tab => tab.classList.toggle("active", tab.dataset.v === name));
  selectAll(".view").forEach(view => view.classList.toggle("active", view.id === "v-" + name));
  const loader = SCREEN_LOADERS[name];
  if (loader) {
    loader();
  }
}

/* ---------------- graph screen (the command center) ---------------- */
const GRAPH_STYLE = [
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

function buildGraphElements(graph) {
  const elements = [];
  for (const [name, node] of Object.entries(graph.nodes || {})) {
    const classes = [];
    if (name === graph.start) {
      classes.push("start");
    }
    if (node.terminal) {
      classes.push("terminal");
    }
    elements.push({
      data: { id: name, label: name, instr: node.instruction || "" },
      classes: classes.join(" "),
    });
  }
  for (const [name, node] of Object.entries(graph.nodes || {})) {
    (node.edges || []).forEach((edge, edgeIndex) => elements.push({
      data: {
        id: name + "→" + edge.target + "#" + edgeIndex,
        source: name,
        target: edge.target,
        cond: edge.condition || "",
        label: shortenCondition(edge.condition),
      },
      classes: edge.tier,
    }));
  }
  return elements;
}

function sameNodeSet(graph, previous) {
  return Boolean(previous) && JSON.stringify(Object.keys(graph.nodes || {})) === JSON.stringify(Object.keys(previous.nodes || {}));
}

async function loadGraphScreen(relayout) {
  let graph;
  try {
    graph = await getJson("/flow/graph");
  } catch {
    return;
  }
  if (graph.error) {
    renderInto("#cy", html`<div class=muted style='padding:20px'>${graph.error}</div>`);
    return;
  }
  const sameShape = Boolean(state.cytoscapeView) && sameNodeSet(graph, state.graph);
  state.graph = graph;
  select("#g-name").textContent = graph.name || graph.flow_path || "flow";
  renderInto("#r-targets", Object.keys(graph.nodes || {}).map(name => html`<option>${name}</option>`));
  if (relayout || !sameShape) {
    state.cytoscapeView = cytoscape({
      container: select("#cy"),
      elements: buildGraphElements(graph),
      style: GRAPH_STYLE,
      wheelSensitivity: 0.2,
    });
    state.cytoscapeView.layout({
      name: "breadthfirst",
      directed: true,
      roots: state.cytoscapeView.getElementById(graph.start),
      spacingFactor: 1.35,
      padding: 24,
    }).run();
    state.cytoscapeView.on("tap", "node", event => showNodeDetail(event.target.id()));
  }
  paintActiveNode();
}

async function refreshActiveNode() {
  // The stream fires on every step, so the common case repaints one node rather than re-laying out.
  let graph;
  try {
    graph = await getJson("/flow/graph");
  } catch {
    return;
  }
  if (graph.error) {
    return;
  }
  const sameShape = sameNodeSet(graph, state.graph);
  state.graph = graph;
  if (!sameShape) {
    return loadGraphScreen(true);
  }
  paintActiveNode();
}

function paintActiveNode() {
  if (!state.cytoscapeView) {
    return;
  }
  state.cytoscapeView.nodes().removeClass("active");
  if (state.graph.active_node) {
    state.cytoscapeView.getElementById(state.graph.active_node).addClass("active");
  }
}

async function proveLevelM() {
  if (!state.graph || !state.graph.flow_text) {
    return;
  }
  const proof = await postJson("/prove/level-m", { flow: state.graph.flow_text });
  const chip = select("#g-levelm-chip");
  if (proof.error) {
    chip.textContent = proof.error.message || "error";
    chip.className = "chip bad";
    return;
  }
  state.cytoscapeView.edges().removeClass("nonm");
  (proof.non_member_edges || []).forEach(row => {
    state.cytoscapeView.edges()
      .filter(edge => edge.data("source") === row.node && edge.data("target") === row.target)
      .addClass("nonm");
  });
  if (proof.level_m) {
    chip.textContent = "Level M ✓ — compiles to a table";
    chip.className = "chip ok";
  } else {
    chip.textContent = (proof.non_member_edges || []).length + " edge(s) outside the fragment";
    chip.className = "chip bad";
  }
}

async function proveReachability() {
  if (!state.graph || !state.graph.flow_text) {
    return;
  }
  const targets = selectAll("#r-targets option").filter(option => option.selected).map(option => option.value);
  if (!targets.length) {
    showToast("select a target node");
    return;
  }
  const assume = select("#r-assume").value.trim();
  const proof = await postJson("/prove/reach", {
    flow: state.graph.flow_text,
    reach: targets,
    assume: assume || undefined,
  });
  if (proof.error) {
    renderInto("#r-verdicts", html`<div class=muted>${proof.error.message}</div>`);
    return;
  }
  state.cytoscapeView.nodes().removeClass("v-yes v-may v-no");
  renderInto("#r-verdicts", Object.entries(proof.verdicts).map(([name, verdict]) => {
    state.cytoscapeView.getElementById(name).addClass("v-" + verdict);
    return html`<div class="verdict"><span>${name}</span><span class="v-${verdict}">${verdict}</span></div>`;
  }));
}

function showNodeDetail(name) {
  const node = state.graph.nodes[name];
  if (!node) {
    return;
  }
  select("#nd-empty").classList.add("hidden");
  const body = select("#nd-body");
  body.classList.remove("hidden");
  const edges = (node.edges || []).map(edge =>
    html`<div class="edge"><b>→ ${edge.target}</b> <span class="muted">[${edge.tier}]</span><br>${edge.condition || "(default)"}</div>`);
  const nameQuery = name.toLowerCase();
  const hits = state.retrievals
    .filter(retrieval => (retrieval.query || "").toLowerCase().includes(nameQuery))
    .flatMap(retrieval => retrieval.hits || [])
    .slice(0, 6);
  const retrieved = hits.length
    ? [html`<label class=muted style="margin-top:8px;display:block">RAG docs pulled</label>`].concat(
        hits.map(hit => html`<div class="retr">[${(hit.score ?? 0).toFixed ? hit.score.toFixed(2) : hit.score}] ${hit.source}/${hit.path}</div>`))
    : html`<div class="retr" style="margin-top:8px">no matched retrievals</div>`;
  body.innerHTML = markupOf(html`<div style="color:#7fd1ff;font-weight:600">${name}</div>
    <div class="instr">${node.instruction || ""}</div>${edges}${retrieved}`);
}

async function loadRetrievals() {
  try {
    const payload = await getJson("/retrievals");
    state.retrievals = payload.retrievals || [];
  } catch {
    // Keep the last good list: a stale node detail panel beats an empty one.
  }
}

/* ---------------- files screen ---------------- */
async function loadFilesScreen() {
  const payload = await getJson("/files");
  renderInto("#filelist", (payload.files || []).map(file =>
    html`<div class="f" data-p="${file.path}"><span>${file.path}</span><span class="sz">${file.size}</span></div>`));
  selectAll("#filelist .f").forEach(row => {
    row.onclick = () => openFile(row.dataset.p, row);
  });
}

async function openFile(path, row) {
  selectAll("#filelist .f").forEach(other => other.classList.remove("sel"));
  if (row) {
    row.classList.add("sel");
  }
  const payload = await getJson("/file?path=" + encodeURIComponent(path));
  if (payload.error) {
    showToast(payload.error.message || "error");
    return;
  }
  state.openFilePath = path;
  select("#ed-path").textContent = path;
  select("#ed-body").value = payload.content;
  select("#ed-save").disabled = false;
}

async function saveOpenFile() {
  if (!state.openFilePath) {
    return;
  }
  const result = await postJson("/file", { path: state.openFilePath, content: select("#ed-body").value });
  showToast(result.error ? (result.error.message || "error") : "saved " + state.openFilePath);
}

/* ---------------- audit screen ---------------- */
async function loadAuditScreen() {
  const payload = await getJson("/audit");
  const chip = select("#a-verify");
  chip.textContent = payload.verify ? "verified ✓" : "TAMPERED ✗";
  chip.className = "chip " + (payload.verify ? "ok" : "bad");
  select("#a-meta").textContent = `root ${(payload.root || "").slice(0, 20)} · ${payload.n} events`;
  renderInto("#a-events", (payload.events || []).slice().reverse().map(event => {
    const who = html`<span class="a">${event.actor || ""}·${event.action || ""}</span>`;
    const when = html`<span class="muted">${event.ts ? new Date(event.ts * 1000).toLocaleTimeString() : ""}</span>`;
    const data = html`<span class="muted">${JSON.stringify(event.data || {}).slice(0, 120)}</span>`;
    return html`<div class="row">${who}${when}${data}</div>`;
  }));
}

/* ---------------- queue screen (the human decisions) ---------------- */
function queueItemId(item, position) {
  return item.id || item.path || String(position);
}

async function loadQueueScreen() {
  const payload = await getJson("/queue");
  const items = payload.items || [];
  renderInto("#q-items", items.length
    ? items.map((item, position) => {
        const itemId = queueItemId(item, position);
        return html`<div class="q-item"><div class="a">${itemId}</div>
      <div class="muted">${JSON.stringify(item).slice(0, 240)}</div>
      <div class="opts"><input placeholder="edge / choice" data-id="${itemId}">
      <button class="btn go" data-decide="${itemId}">Decide</button></div></div>`;
      })
    : html`<div class=muted>nothing awaiting a decision.</div>`);
  selectAll("[data-decide]").forEach(button => {
    button.onclick = () => decideQueueItem(button.dataset.decide);
  });
}

async function decideQueueItem(itemId) {
  const choose = select(`input[data-id="${CSS.escape(itemId)}"]`).value.trim();
  if (!choose) {
    showToast("enter a choice");
    return;
  }
  const result = await postJson("/queue/decide", { id: itemId, choose });
  showToast(result.error ? (result.error.message || "error") : "recorded");
  loadQueueScreen();
}

/* ---------------- flows screen (fan-outs) ---------------- */
async function loadFlowsScreen() {
  const payload = await getJson("/fanouts");
  renderInto("#f-tree", payload.fanouts && payload.fanouts.length
    ? html`<pre class="tree">${JSON.stringify(payload.fanouts, null, 2)}</pre>`
    : html`<div class=muted>no fan-out compositions.</div>`);
}

/* ---------------- sprint control ---------------- */
async function startSprint(submitEvent) {
  submitEvent.preventDefault();
  const form = submitEvent.target;
  const config = {
    proj: form.proj.value.trim() || undefined,
    gate: form.gate.value.trim() || undefined,
    nudge_file: form.nudge_file.value.trim() || undefined,
    model: form.model.value.trim() || undefined,
    rag: form.rag.checked,
    lessons: form.lessons.checked,
    fresh: form.fresh.checked,
    unbuffered: form.unbuffered.checked,
  };
  const result = await postJson("/sprint/start", config);
  showToast(result.error
    ? (result.error.message || "error")
    : (result.ok ? `launched (${result.unbuffered ? "unbuffered" : "buffered"}) pid ${result.pid}` : result.error));
}

async function sendSprintAction(action) {
  const result = await postJson("/sprint/" + action, {});
  showToast(result.error ? result.error.message : (action + " ok"));
}

/* ---------------- wire up ---------------- */
function wireControls() {
  select("#tabs").onclick = event => {
    if (event.target.dataset.v) {
      showScreen(event.target.dataset.v);
    }
  };
  select("#g-refresh").onclick = () => loadGraphScreen(true);
  select("#g-levelm").onclick = proveLevelM;
  select("#r-go").onclick = proveReachability;
  select("#ed-save").onclick = saveOpenFile;
  select("#c-start-toggle").onclick = () => select("#startform").classList.toggle("hidden");
  select("#startform").onsubmit = startSprint;
  selectAll("[data-act]").forEach(button => {
    button.onclick = () => sendSprintAction(button.dataset.act);
  });
}

wireControls();
loadRetrievals();
followEventStream();
showScreen("graph");
