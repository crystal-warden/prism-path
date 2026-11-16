// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The Graph screen of the authoring interface: the followed flow drawn with its edges coloured by
// tier, the live active node, and the two proofs (Level M and reachability) painted onto it. The
// drawing library is the vendored Cytoscape, loaded by index.html before the modules.
import { IDS } from "./ids.mjs";
import { html } from "./markup.mjs";
import { PATHS } from "./paths.mjs";
import { state } from "./state.mjs";
import { byId, renderInto, showToast } from "./dom.mjs";
import { getJson, postJson } from "./transport.mjs";

export const CONDITION_LABEL_MAX = 26;

export const GRAPH_STYLE = [
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

const VERDICTS = new Set(["yes", "may", "no"]);

export function shortenCondition(condition) {
  // The edge label rides on the picture, so the leading "when" is dropped and the rest is clipped.
  const text = (condition || "").replace(/^when\s+/i, "");
  return text.length > CONDITION_LABEL_MAX ? text.slice(0, CONDITION_LABEL_MAX - 2) + "…" : text;
}

// The drawing library's elements for a /flow/graph payload. Cytoscape sets labels as text, not markup.
export function buildGraphElements(graph) {
  const nodes = Object.entries(graph.nodes || {});
  const elements = nodes.map(([name, node]) => ({
    data: { id: name, label: name, instr: node.instruction || "" },
    classes: [name === graph.start ? "start" : "", node.terminal ? "terminal" : ""].filter(Boolean).join(" "),
  }));
  for (const [name, node] of nodes) {
    (node.edges || []).forEach((edge, edgeIndex) => elements.push({
      data: {
        id: name + "→" + edge.target + "#" + edgeIndex,
        source: name,
        target: edge.target,
        cond: edge.condition || "",
        label: shortenCondition(edge.condition),
      },
      classes: edge.tier || "",
    }));
  }
  return elements;
}

export function renderTargetOptions(graph) {
  return Object.keys((graph && graph.nodes) || {}).map(name => html`<option>${name}</option>`);
}

// The verdict class names a known verdict only, so a server string never becomes a class of its own.
function verdictClass(verdict) {
  return VERDICTS.has(verdict) ? "v-" + verdict : "v-unknown";
}

export function renderReachVerdicts(verdicts) {
  return Object.entries(verdicts || {}).map(([name, verdict]) =>
    html`<div class="verdict"><span>${name}</span><span class="${verdictClass(verdict)}">${verdict}</span></div>`);
}

export function renderGraphError(message) {
  return html`<div class="muted graph-message">${message}</div>`;
}

function scoreText(score) {
  return typeof score === "number" ? score.toFixed(2) : String(score ?? 0);
}

// The node panel: the node's instruction, its edges, and the retrievals whose query names it.
export function renderNodeDetail(name, node, retrievals) {
  const edges = (node.edges || []).map(edge =>
    html`<div class="edge"><b>→ ${edge.target}</b> <span class="muted">[${edge.tier}]</span><br>${edge.condition || "(default)"}</div>`);
  const nameQuery = name.toLowerCase();
  const hits = (retrievals || [])
    .filter(retrieval => (retrieval.query || "").toLowerCase().includes(nameQuery))
    .flatMap(retrieval => retrieval.hits || [])
    .slice(0, 6);
  const retrieved = hits.length
    ? [html`<label class="muted nd-label">RAG docs pulled</label>`].concat(
        hits.map(hit => html`<div class="retr">[${scoreText(hit.score)}] ${hit.source}/${hit.path}</div>`))
    : html`<div class="retr nd-label">no matched retrievals</div>`;
  return html`<div class="nd-title">${name}</div>
    <div class="instr">${node.instruction || ""}</div>${edges}${retrieved}`;
}

function sameNodeSet(graph, previous) {
  return Boolean(previous) && JSON.stringify(Object.keys(graph.nodes || {})) === JSON.stringify(Object.keys(previous.nodes || {}));
}

function disposeGraphView() {
  if (state.cytoscapeView) {
    state.cytoscapeView.destroy();
    state.cytoscapeView = null;
  }
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

function showNodeDetail(name) {
  const node = state.graph && state.graph.nodes[name];
  if (!node) {
    return;
  }
  byId(IDS.nodeEmpty).classList.add("hidden");
  byId(IDS.nodeBody).classList.remove("hidden");
  renderInto(IDS.nodeBody, renderNodeDetail(name, node, state.retrievals));
}

export async function loadGraphScreen(relayout = true) {
  let graph;
  try {
    graph = await getJson(PATHS.flowGraph);
  } catch {
    return;
  }
  if (graph.error) {
    // The message replaces the container's contents, which tears the drawing library's canvas out
    // from under it. Dropping the handle too is what lets the graph come back: a live handle here
    // reads as "already laid out", so the next good load would skip the rebuild.
    disposeGraphView();
    renderInto(IDS.graphCanvas, renderGraphError(graph.error.message || graph.error));
    return;
  }
  const sameShape = Boolean(state.cytoscapeView) && sameNodeSet(graph, state.graph);
  state.graph = graph;
  byId(IDS.graphName).textContent = graph.name || graph.flow_path || "flow";
  renderInto(IDS.reachTargets, renderTargetOptions(graph));
  if (relayout || !sameShape) {
    disposeGraphView();
    byId(IDS.graphCanvas).textContent = "";
    state.cytoscapeView = globalThis.cytoscape({
      container: byId(IDS.graphCanvas),
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

export async function refreshActiveNode() {
  // The stream fires on every step, so the common case repaints one node rather than re-laying out.
  let graph;
  try {
    graph = await getJson(PATHS.flowGraph);
  } catch {
    return;
  }
  if (graph.error) {
    return;
  }
  const sameShape = sameNodeSet(graph, state.graph);
  state.graph = graph;
  if (!sameShape || !state.cytoscapeView) {
    return loadGraphScreen(true);
  }
  paintActiveNode();
}

async function proveLevelM() {
  // Both proofs paint their verdict onto the drawn graph, so both need a graph and a live view.
  if (!state.graph || !state.graph.flow_text || !state.cytoscapeView) {
    return;
  }
  const proof = await postJson(PATHS.proveLevelM, { flow: state.graph.flow_text });
  const chip = byId(IDS.levelMChip);
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
  if (!state.graph || !state.graph.flow_text || !state.cytoscapeView) {
    return;
  }
  const targets = [...byId(IDS.reachTargets).options].filter(option => option.selected).map(option => option.value);
  if (!targets.length) {
    showToast("select a target node");
    return;
  }
  const assume = byId(IDS.reachAssume).value.trim();
  const proof = await postJson(PATHS.proveReach, { flow: state.graph.flow_text, reach: targets, assume: assume || undefined });
  if (proof.error) {
    renderInto(IDS.reachVerdicts, html`<div class="muted">${proof.error.message}</div>`);
    return;
  }
  state.cytoscapeView.nodes().removeClass("v-yes v-may v-no");
  Object.entries(proof.verdicts || {}).forEach(([name, verdict]) => {
    if (VERDICTS.has(verdict)) {
      state.cytoscapeView.getElementById(name).addClass("v-" + verdict);
    }
  });
  renderInto(IDS.reachVerdicts, renderReachVerdicts(proof.verdicts));
}

export function wireGraph() {
  byId(IDS.graphRefresh).onclick = () => loadGraphScreen(true);
  byId(IDS.proveLevelM).onclick = proveLevelM;
  byId(IDS.reachGo).onclick = proveReachability;
}
