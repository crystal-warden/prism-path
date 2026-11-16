// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The authoring interface (the process owner). The Graph screen lives in graph.mjs; this module holds
// the Files screen with its editor and the open flow's change status line, the Inspect checks with their
// verdicts, the Prove screen (text in, so an unsaved edit can be proven before it is saved), the Change
// status screen and the New flow scaffold.
//
// The console edits flow documents and their fixtures and nothing else, and it never signs, packs, swaps
// or attests: a change reaches a running policy only through the signed path, run off the console by
// the people who hold the keys, and the change status shows where a flow stands on that path and the
// commands that take it further. In the read only posture every write control is disabled and says why.
import { IDS } from "./ids.mjs";
import { attr, html } from "./markup.mjs";
import { PATHS, POSTURE_READ_ONLY, routeAvailable } from "./paths.mjs";
import { activeFlow, state } from "./state.mjs";
import { bindAction, byId, inputValue, renderInto, showToast, UNAVAILABLE_TITLE } from "./dom.mjs";
import { getJson, postJson } from "./transport.mjs";
import { populatePickers, prefillFlowInputs } from "./panels.mjs";
import { renderWitness } from "./graph.mjs";

const EDITABLE_KINDS = new Set(["flow", "fixture"]);
const KIND_LABEL = { flow: "flow", fixture: "fixture", other: "read only" };
const OK_STATUSES = new Set(["signed", "this-text"]);
const BAD_STATUSES = new Set(["invalid", "stale", "other-text"]);
const VERDICTS = new Set(["yes", "may", "no"]);
export const READ_ONLY_REASON = "read-only posture: the console mounts no write routes, so saving is unavailable";
export const OTHER_KIND_REASON = "the console edits flow documents and their fixtures only; this file opens for reading";
const SCAFFOLD_READ_ONLY = "read-only posture: the console mounts no write routes, so a new flow cannot be written";
const RUNS_TEXT = {
  "this-text": "deployment runs a pack built from this text",
  "other-text": "deployment runs another text",
  "unknown": "deployment runs a pack that does not say which text",
  "nothing-active": "deployment runs nothing",
};

// ── small renders ───────────────────────────────────────────────────────────────────────────────
function chip(status, whose = "console") {
  const shown = status == null || status === "" ? "no verdict" : String(status);
  const tone = OK_STATUSES.has(shown) ? "ok" : BAD_STATUSES.has(shown) ? "bad" : "warn";
  return html`<span class=${attr("chip " + tone)}>${whose}: ${shown}</span>`;
}

function okChip(ok, yes, no) {
  return html`<span class=${attr(ok ? "chip ok" : "chip bad")}>console: ${ok ? yes : no}</span>`;
}

function kv(label, value) {
  return html`<div class="kv"><span class="k">${label}</span><span class="v">${value == null ? "" : value}</span></div>`;
}

function command(label, line) {
  return line ? html`<div class="cmd"><span class="k">${label}</span><pre class="cmdline">${line}</pre></div>` : "";
}

function refusal(result) {
  const error = (result && result.error) || {};
  return html`<div class="refusal">${error.message || "error"}</div>`;
}

export function splitList(text) {
  return String(text || "").split(",").map(part => part.trim()).filter(Boolean);
}

// ── Files: the list and the editor ──────────────────────────────────────────────────────────────
export function isEditable(kind) {
  return EDITABLE_KINDS.has(kind);
}

// Why a save of a file of this kind is unavailable in this posture, or "" when it is offered.
export function saveBlocked(posture, kind) {
  if (!routeAvailable(posture, "POST", PATHS.file)) {
    return READ_ONLY_REASON;
  }
  return isEditable(kind) ? "" : OTHER_KIND_REASON;
}

export function renderFileList(files, selectedPath = null) {
  return (files || []).map(file => {
    const kind = EDITABLE_KINDS.has(file.kind) ? file.kind : "other";
    const cls = (file.path === selectedPath ? "f sel" : "f") + " kind-" + kind;
    return html`<div class=${attr(cls)} data-p=${attr(file.path)} data-kind=${attr(kind)}><span>${file.path}</span><span class="sz"><span class=${attr("kind " + kind)}>${KIND_LABEL[kind]}</span> ${file.size}</span></div>`;
  });
}

export async function loadFilesScreen() {
  const payload = await getJson(PATHS.files);
  if (payload.error) {
    renderInto(IDS.fileList, html`<div class="muted graph-message">${payload.error.message}</div>`);
    return;
  }
  renderInto(IDS.fileList, renderFileList(payload.files, state.openFilePath));
  byId(IDS.fileList).querySelectorAll(".f").forEach(row => {
    row.onclick = () => openFile(row.dataset.p, row.dataset.kind, row);
  });
}

function paintSaveControl() {
  const save = byId(IDS.editorSave);
  const note = byId(IDS.editorNote);
  const reason = state.openFilePath ? saveBlocked(state.posture, state.openFileKind)
    : (state.posture === POSTURE_READ_ONLY ? READ_ONLY_REASON : "");
  save.disabled = !state.openFilePath || Boolean(reason);
  save.title = reason;
  byId(IDS.editorBody).readOnly = Boolean(reason);
  note.textContent = reason;
  note.classList.toggle("hidden", !reason);
}

async function openFile(path, kind, row) {
  byId(IDS.fileList).querySelectorAll(".f").forEach(other => other.classList.toggle("sel", other === row));
  const payload = await getJson(PATHS.file, { path });
  if (payload.error) {
    showToast(payload.error.message || "error");
    return;
  }
  state.openFilePath = path;
  state.openFileKind = kind || "other";
  byId(IDS.editorPath).textContent = path;
  byId(IDS.editorBody).value = payload.content;
  paintSaveControl();
  refreshEditorStatus();
}

async function refreshEditorStatus() {
  const line = byId(IDS.editorStatus);
  if (state.openFileKind !== "flow") {
    line.textContent = "";
    return;
  }
  const request = statusRequest(state.openFilePath, inputValue(IDS.statusPins), inputValue(IDS.statusState));
  try {
    line.textContent = changeStatusLine(await postJson(request.path, request.body));
  } catch (error) {
    line.textContent = "change status unavailable: " + error;
  }
}

async function saveOpenFile() {
  if (!state.openFilePath || saveBlocked(state.posture, state.openFileKind)) {
    return;
  }
  const result = await postJson(PATHS.file, { path: state.openFilePath, content: byId(IDS.editorBody).value });
  if (result.error) {
    showToast(result.error.message || "error");
    return;
  }
  showToast("saved " + state.openFilePath + ", recorded in the console's audit log");
  refreshEditorStatus();
}

// ── Inspect: the process owner's loop from the terminal, with its verdicts ─────────────────────
const INSPECT_ROUTES = {
  validate: PATHS.inspectValidate,
  lint: PATHS.inspectLint,
  contract: PATHS.inspectContract,
  portable: PATHS.inspectPortable,
  test: PATHS.inspectTest,
  graph: PATHS.inspectGraph,
};

export function inspectRequest(action, flowPath) {
  const body = { flow_md: flowPath };
  if (action === "graph") {
    body.direction = "TD";
  }
  return { path: INSPECT_ROUTES[action], body };
}

function findingRows(findings) {
  return (findings || []).map(finding =>
    html`<div class="ev-row"><span class=${attr(finding.severity === "error" ? "bad" : "muted")}>${finding.severity}</span><span class="a">${finding.code}</span><span>${finding.message}</span><span class="muted">${finding.node || ""}</span></div>`);
}

function renderFindings(result, yes, no) {
  return html`<div class="verdict-line">${okChip(result.ok, yes, no)}
    <span class="count">${result.errors ?? 0} error(s)</span><span class="count">${result.warnings ?? 0} warning(s)</span></div>
    <div class="muted">the console's verdict, the same library call as the command line</div>
    <div class="table">${findingRows(result.findings)}</div>`;
}

function renderTestCases(result) {
  const rows = (result.cases || []).map(row =>
    html`<tr class=${attr(row.ok ? "" : "bad")}><td>${row.node}</td><td>${row.outcome}</td><td>${row.routed}</td><td>${row.expected}</td><td>${row.via || ""}</td></tr>`);
  return html`<div class="verdict-line">${okChip(result.ok, "every case routes as written", "a case routes elsewhere")}
    <span class="count">${result.passed ?? 0} passed</span><span class="count">${result.failed ?? 0} failed</span></div>
    <div class="muted">the console's verdict: the fixture table, run with no model</div>
    <table class="cases"><tr><th>node</th><th>outcome</th><th>routed</th><th>expected</th><th>via</th></tr>${rows}</table>`;
}

function renderContract(result) {
  const schemas = Object.entries(result.schemas || {}).map(([node, schema]) =>
    kv(node, Object.entries((schema && schema.properties) || {}).map(([field, spec]) => field + ": " + ((spec && spec.type) || "any")).join(", ")));
  const conflicts = (result.conflicts || []).map(row => html`<li>${row.node} · ${row.field}: ${row.detail}</li>`);
  return html`<div class="verdict-line">${okChip(result.ok, "no field is used two ways", "a field is used two ways")}</div>
    ${schemas}${conflicts.length ? html`<ul class="findings">${conflicts}</ul>` : ""}`;
}

function renderPortable(result) {
  const flows = Object.entries(result.flows || {}).map(([path, flow]) => html`<div class="sub-card"><h4>${path} · ${flow.tier}</h4>
    ${(flow.semantic_edges || []).length ? html`<ul class="findings">${flow.semantic_edges.map(edge => html`<li>${edge.node} → ${edge.target}: ${edge.condition}</li>`)}</ul>` : html`<div class="muted">no semantic edge</div>`}
    ${(flow.unlocked || []).length ? kv("unlocked", flow.unlocked.join(", ")) : ""}</div>`);
  return html`<div class="verdict-line">${okChip(result.portable, "P0, the ML free subset", "tier " + (result.tier || "?"))}</div>${flows}`;
}

export function renderInspectResult(action, result) {
  if (!result || result.error) {
    return refusal(result);
  }
  if (action === "validate") {
    return renderFindings(result, "compiles", "does not compile");
  }
  if (action === "lint") {
    return renderFindings(result, "lint finds no error", "lint finds errors");
  }
  if (action === "test") {
    return renderTestCases(result);
  }
  if (action === "contract") {
    return renderContract(result);
  }
  if (action === "portable") {
    return renderPortable(result);
  }
  return html`<pre class="cmdline">${result.mermaid || ""}</pre>`;
}

async function runInspect(action) {
  const flow = inputValue(IDS.inspectFlow) || activeFlow();
  const request = inspectRequest(action, flow);
  renderInto(IDS.inspectOut, html`<div class="muted">running ${action} on ${flow}</div>`);
  try {
    renderInto(IDS.inspectOut, renderInspectResult(action, await postJson(request.path, request.body)));
  } catch (error) {
    renderInto(IDS.inspectOut, html`<div class="refusal">${String(error)}</div>`);
  }
}

// ── Prove: text in ──────────────────────────────────────────────────────────────────────────────
export function levelMRequest(flowText) {
  return { path: PATHS.proveLevelM, body: { flow: flowText } };
}

export function reachRequest(flowText, reach, forbid, assume) {
  const body = { flow: flowText, reach: splitList(reach), forbid: splitList(forbid) };
  if (String(assume || "").trim()) {
    body.assume = String(assume).trim();
  }
  return { path: PATHS.proveReach, body };
}

export function renderLevelM(result) {
  if (!result || result.error) {
    return refusal(result);
  }
  const edges = (result.non_member_edges || []).map(edge => html`<li>${edge.node} → ${edge.target}: ${edge.condition || ""}</li>`);
  return html`<div class="verdict-line">${okChip(result.level_m, "Level M, compiles to a match-action table", edges.length + " edge(s) outside Level M")}</div>
    ${edges.length ? html`<ul class="findings">${edges}</ul>` : ""}`;
}

function verdictClass(verdict) {
  return VERDICTS.has(verdict) ? "v-" + verdict : "v-unknown";
}

export function renderReach(result) {
  if (!result || result.error) {
    return refusal(result);
  }
  const results = result.results || {};
  const rows = Object.entries(result.verdicts || {}).map(([name, verdict]) => {
    const detail = results[name] || {};
    const proven = verdict === "no" ? (detail.proven ? "proven unreachable" : "not reached within the bound") : "";
    return html`<div class="verdict"><span>${name}</span><span class=${attr(verdictClass(verdict))}>${verdict}</span><span class="muted">${proven}</span></div>`;
  });
  return html`<div class="muted">the console's verdicts, bounded model checking over the text sent</div>
    <div class="verdicts">${rows}</div>${renderWitness(results)}`;
}

function proveText() {
  return byId(IDS.proveText).value;
}

async function proveLevelMText() {
  const request = levelMRequest(proveText());
  renderInto(IDS.proveOut, renderLevelM(await postJson(request.path, request.body)));
}

async function proveReachText() {
  const request = reachRequest(proveText(), inputValue(IDS.proveReach), inputValue(IDS.proveForbid), inputValue(IDS.proveAssume));
  renderInto(IDS.proveOut, renderReach(await postJson(request.path, request.body)));
}

export function loadProveScreen() {
  if (!proveText() && state.graph && state.graph.flow_text) {
    byId(IDS.proveText).value = state.graph.flow_text;
  }
}

// ── Change status ───────────────────────────────────────────────────────────────────────────────
export function statusRequest(flowPath, pins, stateDir) {
  const body = { flow_md: flowPath, pins: splitList(pins) };
  if (String(stateDir || "").trim()) {
    body.state_dir = String(stateDir).trim();
  }
  return { path: PATHS.authorStatus, body };
}

// One line for the editor bar: the hash, the manifest's verdict and what the deployment runs.
export function changeStatusLine(status) {
  if (!status || status.error) {
    return "change status: " + (((status || {}).error || {}).message || "unavailable");
  }
  const manifest = status.manifest || {};
  const deployment = status.deployment;
  let running = "no deployment followed";
  if (deployment) {
    running = RUNS_TEXT[deployment.runs] || "deployment " + deployment.runs;
    if (deployment.attestation && deployment.attestation.names_active) {
      running += ", attested";
    } else if (deployment.active) {
      running += ", not attested since";
    }
  }
  return "sha256 " + String(status.flow_sha256 || "").slice(0, 12) + " · manifest " + (manifest.status || "?") + " · " + running;
}

function renderDeployment(deployment) {
  if (!deployment) {
    return html`<div class="muted">No policy host state directory named: name one under the project or an evidence root to see what the deployment runs.</div>`;
  }
  const pack = deployment.pack || {};
  const attestation = deployment.attestation;
  const packSha = pack.flow_sha256
    ? pack.flow_sha256 + (pack.flow_sha256_checked ? "" : " (the pack is not verified under a pinned key)")
    : "not recorded";
  const attested = attestation
    ? (attestation.ts || "") + (attestation.names_active ? " · names the active image" : " · names another image")
    : "none since the active policy";
  return html`<div class="sub-card"><h4>deployment ${deployment.state_dir}</h4>
    <div class="verdict-line">${chip(deployment.runs, deployment.verdict_of || "console")}${deployment.pack ? chip(pack.status) : ""}</div>
    <div class="muted">${RUNS_TEXT[deployment.runs] || ""}</div>
    ${kv("active image", deployment.active || "none")}
    ${kv("version", deployment.version)}
    ${kv("pack flow sha256", packSha)}
    ${kv("last attestation", attested)}
    ${command("swap (the operator's, off the console)", (deployment.commands || {}).swap)}
    ${command("attest (the operator's, off the console)", (deployment.commands || {}).attest)}</div>`;
}

export function renderChangeStatus(status) {
  if (!status || status.error) {
    return refusal(status);
  }
  const manifest = status.manifest || {};
  const commands = status.commands || {};
  const causes = (manifest.causes || []).map(cause => html`<li>${cause.label || cause.name} · ${cause.description || ""}</li>`);
  return html`<div class="verdict-line">${chip(manifest.status, manifest.verdict_of || "console")}</div>
    ${kv("flow", status.flow_md)}
    ${kv("flow sha256", status.flow_sha256)}
    ${kv("manifest names", manifest.manifest_flow_sha256 || "no manifest")}
    ${kv("manifest version", manifest.version)}
    ${kv("signer", manifest.key || "none")}
    <div class="muted">${manifest.pinned ? "checked against the pinned authority key files; the console's verdict" : "no authority key pinned: name the public key file to check the manifest"}</div>
    ${causes.length ? html`<ul class="findings">${causes}</ul>` : ""}
    ${renderDeployment(status.deployment)}
    <div class="sub-card"><h4>the signed path</h4>
    <div class="muted">${status.note || "the console never signs, packs, swaps or attests"}</div>
    ${command("sign (the authority key's holder)", commands.sign)}
    ${command("verify (anyone)", commands.verify)}
    ${command("pack a Level M image (the authority key's holder)", commands.pack)}</div>`;
}

async function runStatus() {
  const flow = inputValue(IDS.statusFlow) || activeFlow();
  const request = statusRequest(flow, inputValue(IDS.statusPins), inputValue(IDS.statusState));
  renderInto(IDS.statusOut, renderChangeStatus(await postJson(request.path, request.body)));
}

export function loadStatusScreen() {
  const input = byId(IDS.statusFlow);
  if (!input.value) {
    input.value = state.openFileKind === "flow" ? state.openFilePath : activeFlow();
  }
  prefillFlowInputs();
  populatePickers();
}

// ── New flow: the scaffold ──────────────────────────────────────────────────────────────────────
export function scaffoldRequest(name, template) {
  return { path: PATHS.authorScaffold, body: { name: String(name || "").trim(), template } };
}

export function renderTemplateOptions(templates, selected) {
  return (templates || []).map(entry => entry.name === selected
    ? html`<option value=${attr(entry.name)} selected>${entry.name}</option>`
    : html`<option value=${attr(entry.name)}>${entry.name}</option>`);
}

export function scaffoldPreview(template, name) {
  if (!template) {
    return "";
  }
  const shown = String(name || "").trim() || "<name>";
  const files = (template.files || []).map(file => html`<li>${file.split("<name>").join(shown)}</li>`);
  return html`<div class="muted">${template.about || ""}</div><div class="muted">writes these files, and never over an existing one</div><ul class="findings">${files}</ul>`;
}

export function renderScaffoldResult(result) {
  if (!result || result.error) {
    return refusal(result);
  }
  return html`<div class="verdict-line"><span class="chip ok">written</span></div>
    <ul class="findings">${(result.files || []).map(file => html`<li>${file}</li>`)}</ul>
    <div class="muted">recorded in the console's audit log as author.scaffold, with each file's sha256. Open ${result.flow} in Files, or run Inspect on it.</div>`;
}

function selectedTemplate() {
  const name = byId(IDS.scaffoldTemplate).value;
  return (state.templates || []).find(entry => entry.name === name);
}

function paintScaffoldPreview() {
  renderInto(IDS.scaffoldPreview, scaffoldPreview(selectedTemplate(), inputValue(IDS.scaffoldName)));
}

export async function loadNewScreen() {
  const payload = await getJson(PATHS.authorTemplates);
  if (payload.error) {
    renderInto(IDS.scaffoldPreview, refusal(payload));
    return;
  }
  state.templates = payload.templates || [];
  const current = byId(IDS.scaffoldTemplate).value || "starter";
  renderInto(IDS.scaffoldTemplate, renderTemplateOptions(state.templates, current));
  paintScaffoldPreview();
}

async function runScaffold() {
  const request = scaffoldRequest(inputValue(IDS.scaffoldName), byId(IDS.scaffoldTemplate).value);
  const result = await postJson(request.path, request.body);
  renderInto(IDS.scaffoldOut, renderScaffoldResult(result));
  if (!result.error) {
    populatePickers();
  }
}

// ── wiring ──────────────────────────────────────────────────────────────────────────────────────
export function wireAuthoring() {
  bindAction(byId(IDS.editorSave), "POST", PATHS.file, saveOpenFile);
  paintSaveControl();
  document.querySelectorAll("[data-inspect]").forEach(button => {
    button.onclick = () => runInspect(button.dataset.inspect);
  });
  byId(IDS.proveFollowed).onclick = () => {
    byId(IDS.proveText).value = (state.graph && state.graph.flow_text) || "";
  };
  byId(IDS.proveEditor).onclick = () => {
    byId(IDS.proveText).value = byId(IDS.editorBody).value;
  };
  byId(IDS.proveLevelMGo).onclick = proveLevelMText;
  byId(IDS.proveReachGo).onclick = proveReachText;
  byId(IDS.statusGo).onclick = runStatus;
  byId(IDS.scaffoldTemplate).onchange = paintScaffoldPreview;
  byId(IDS.scaffoldName).oninput = paintScaffoldPreview;
  if (!bindAction(byId(IDS.scaffoldGo), "POST", PATHS.authorScaffold, runScaffold)) {
    const note = byId(IDS.scaffoldNote);
    note.textContent = SCAFFOLD_READ_ONLY;
    note.classList.remove("hidden");
    byId(IDS.scaffoldName).disabled = true;
    byId(IDS.scaffoldName).title = UNAVAILABLE_TITLE;
  }
}
