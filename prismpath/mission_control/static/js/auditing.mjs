// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The auditing interface (the assessor). Trails under the evidence roots with their root statement
// chain status, one receipt with its inclusion path and its bundle to download, the raw bytes, an
// evidence run verified, change control and pack verify, an anchored record verified, the cause
// decoder, the pinned keys, the console's own audit log and the Proof panel. Every route here reads,
// so the interface is whole in the read only posture.
//
// Every verdict shown names whose it is. The console's verdict is unpinned unless the assessor names
// public key FILES under the evidence roots, and it is still the console's. The keys the assessor pins
// in the page are kept in this tab's session storage and are never sent: no request built here takes
// them. The page's own check against them (WP5) and the command each report prints are the checks
// that do not trust the console.
import { IDS } from "./ids.mjs";
import { attr, html } from "./markup.mjs";
import { PATHS } from "./paths.mjs";
import { bindAction, byId, inputValue, renderInto, showToast } from "./dom.mjs";
import { getJson, postJson } from "./transport.mjs";
import { runTool } from "./panels.mjs";

// ---------------------------------------------------------------- verdicts
const OK_STATUSES = new Set(["signed", "verified"]);
const BAD_STATUSES = new Set(["invalid", "stale", "refused"]);

// A verdict chip, naming whose verdict it is: the console's unless a caller says otherwise.
export function verdictChip(status, whose = "console") {
  const shown = status == null || status === "" ? "no verdict" : String(status);
  const tone = OK_STATUSES.has(shown) ? "ok" : BAD_STATUSES.has(shown) ? "bad" : "warn";
  return { text: whose + ": " + shown, cls: "chip " + tone };
}

function chip({ text, cls }) {
  return html`<span class=${attr(cls)}>${text}</span>`;
}

function claim(holds, yes, no, whose = "console") {
  if (holds === true) {
    return chip({ text: whose + ": " + yes, cls: "chip ok" });
  }
  if (holds === false) {
    return chip({ text: whose + ": " + no, cls: "chip bad" });
  }
  return chip({ text: whose + ": not checked", cls: "chip warn" });
}

function kv(label, value) {
  return html`<div class="kv"><span class="k">${label}</span><span class="v">${value == null ? "" : value}</span></div>`;
}

function command(label, line) {
  return line ? html`<div class="cmd"><span class="k">${label}</span><pre class="cmdline">${line}</pre></div>` : "";
}

function shown(value) {
  return typeof value === "object" && value !== null ? JSON.stringify(value) : String(value);
}

// The console's error envelope as a line: the status, the reason and the message.
export function renderRefusal(payload) {
  const error = (payload && payload.error) || {};
  return html`<div class="refusal">refused ${error.code ?? ""} ${error.reason || ""}: ${error.message || "no message"}</div>`;
}

// ---------------------------------------------------------------- request builders
function present(value) {
  return value !== undefined && value !== null && String(value).trim() !== "";
}

function number(value, fallback) {
  return present(value) ? Number(value) : fallback;
}

// Key FILES under the evidence roots, separated by spaces or commas. Never key material.
export function parsePinFiles(value) {
  return present(value) ? String(value).split(/[\s,]+/).filter(Boolean) : [];
}

function logTarget(inputs) {
  return inputs.console ? { console: true } : { path: inputs.path };
}

function withPins(body, pins) {
  const files = parsePinFiles(pins);
  return files.length ? { ...body, pins: files } : body;
}

export function trailRequest(inputs) {
  const body = logTarget(inputs);
  if (present(inputs.since)) {
    body.since = String(inputs.since).trim();
  }
  if (present(inputs.last)) {
    body.last = Number(inputs.last);
  }
  return [PATHS.evidenceTrail, withPins(body, inputs.pins)];
}

export function receiptRequest(inputs) {
  return [PATHS.evidenceReceipt, withPins({ ...logTarget(inputs), index: number(inputs.index, 0) }, inputs.pins)];
}

export function rawRequest(inputs) {
  const body = { ...logTarget(inputs), start: number(inputs.start, 0), count: number(inputs.count, 100) };
  if (inputs.statements === true) {
    body.statements = true;
  }
  return [PATHS.evidenceRaw, body];
}

export function runRequest(inputs) {
  const body = { path: inputs.path };
  const pins = {};
  if (present(inputs.authority)) {
    pins.authority = String(inputs.authority).trim();
  }
  if (present(inputs.instance)) {
    pins.instance = String(inputs.instance).trim();
  }
  if (Object.keys(pins).length) {
    body.pins = pins;
  }
  if (present(inputs.sample)) {
    body.sample = Number(inputs.sample);
  }
  return [PATHS.evidenceRun, body];
}

export function manifestRequest(inputs) {
  const body = withPins({ flow: inputs.flow }, inputs.pins);
  if (present(inputs.log)) {
    body.log = String(inputs.log).trim();
    body.index = number(inputs.index, 0);
  }
  return [PATHS.evidenceManifest, body];
}

export function packRequest(inputs) {
  return [PATHS.evidencePack, withPins({ ppt: inputs.ppt }, inputs.pins)];
}

export function anchorRequest(inputs) {
  const body = {};
  for (const name of ["leaf", "dir", "label", "root", "tsr", "cafile"]) {
    if (present(inputs[name])) {
      body[name] = String(inputs[name]).trim();
    }
  }
  return [PATHS.evidenceAnchor, body];
}

// ---------------------------------------------------------------- U1 trails
export function renderLogList(payload) {
  const roots = payload.roots || [];
  const consoleLog = payload.console;
  const rows = [];
  if (consoleLog) {
    const read = consoleLog.present === false ? html`<span class="muted">nothing yet</span>`
      : html`<button type="button" class="btn inline" data-console="1">Read</button>`;
    rows.push(html`<div class="ev-row">${read}
      <span class="a">the console's own log</span><span class="muted">${consoleLog.events ?? 0} events · ${consoleLog.path || ""}</span>
      ${claim(consoleLog.verifies, "Merkle root verifies", "Merkle root does not verify")}</div>`);
  }
  if (!roots.length) {
    rows.push(html`<div class="muted">No evidence root is named, so no evidence is readable: launch the console with MC_EVIDENCE set to the directory of evidence you were handed.</div>`);
  }
  for (const log of payload.logs || []) {
    rows.push(html`<div class="ev-row"><button type="button" class="btn inline" data-trail=${attr(log.path)} data-statements=${attr(log.statements || "")}>Read</button>
      <span class="a">${log.rel || log.path}</span><span class="muted">${log.size ?? 0} bytes · ${log.statements ? "statements beside it" : "no statements"}</span></div>`);
  }
  for (const run of payload.runs || []) {
    rows.push(html`<div class="ev-row"><button type="button" class="btn inline" data-run=${attr(run.path)}>Verify run</button>
      <span class="a">${run.rel || run.path}</span><span class="muted">evidence run · ${run.complete ? "complete" : "incomplete"}</span></div>`);
  }
  if (roots.length && !(payload.logs || []).length && !(payload.runs || []).length) {
    rows.push(html`<div class="muted">No audit log or evidence run under ${roots.join(", ")}.</div>`);
  }
  if (payload.truncated) {
    rows.push(html`<div class="muted">The listing was truncated at MC_MAX_TREE_ENTRIES entries.</div>`);
  }
  return rows;
}

function counts(map) {
  const entries = Object.entries(map || {});
  return entries.length ? entries.map(([name, count]) => html`<span class="count">${name} ${count}</span>`) : html`<span class="muted">none</span>`;
}

function finding(entry) {
  return html`<li>${shown(entry)}</li>`;
}

// The console's own actions, each intent paired with its result.
export function renderConsoleActions(actions) {
  if (!actions) {
    return html``;
  }
  const rows = Object.entries(actions.by_action || {}).map(([action, tally]) => html`<div class="ev-row">
    <span class="a">${action}</span><span>${tally.intents} asked · ${tally.done} done · ${tally.failed} failed</span>
    <span class=${attr(tally.unrecorded ? "bad" : "muted")}>${tally.unrecorded ? tally.unrecorded + " outcome not recorded" : "every outcome recorded"}</span></div>`);
  const unrecorded = (actions.unrecorded || []).map(entry => html`<li>#${entry.index} ${entry.action}: outcome not recorded</li>`);
  const orphans = (actions.orphans || []).map(entry => html`<li>#${entry.index} ${entry.action}: ${entry.why}</li>`);
  return html`<div class="sub-card"><h4>The console's own actions, each intent with its result</h4>${rows}
    ${kv("refusals", counts(actions.refusals))}
    ${unrecorded.length ? html`<ul class="findings">${unrecorded}</ul>` : ""}
    ${orphans.length ? html`<div class="muted">results that pair with no intent</div><ul class="findings">${orphans}</ul>` : ""}</div>`;
}

export function renderTrailReport(report) {
  const signing = report.signing || {};
  const log = report.log || {};
  const causeRows = (report.causes_decoded || []).map(cause => html`<div class="ev-row"><span class="a">${cause.label}</span>
    <span>${cause.class || ""}</span><span class="muted">${(report.causes || {})[cause.label] ?? ""} · ${cause.description || ""}</span></div>`);
  const skipped = (report.skipped || []).map(entry => html`<li>line ${entry.line}: ${entry.why}</li>`);
  return html`<div class="verdict-line">${chip(verdictChip(signing.status, report.verdict_of || "console"))}
      ${claim(log.verifies, "Merkle root verifies", "Merkle root does not verify")}</div>
    <div class="muted">${signing.pinned ? "pinned by key files under the evidence roots; still the console's verdict" : "not pinned: the console names the signer and does not vouch for it. Pin a key in the Keys screen for the page's own check, or run the command."}</div>
    ${kv("events", `${report.events ?? 0} in the window of ${log.total_events ?? 0}`)}
    ${kv("Merkle root", log.merkle_root)}
    ${kv("log sha256", report.sha256)}
    ${kv("statements", `${signing.statements ?? 0} · signer ${(signing.keys || []).join(", ") || "none"} · unsigned tail ${signing.unsigned_tail ?? 0}`)}
    ${(signing.findings || []).length ? html`<div class="muted">findings</div><ul class="findings">${signing.findings.map(finding)}</ul>` : ""}
    ${skipped.length ? html`<div class="muted">lines that did not read</div><ul class="findings">${skipped}</ul>` : ""}
    ${kv("by action", counts(report.by_action))}
    ${kv("outcomes", counts(report.outcomes))}
    <div class="table">${causeRows}</div>
    ${renderConsoleActions(report.console_actions)}
    ${command("check of record", report.command)}`;
}

// ---------------------------------------------------------------- U2 one receipt and the raw bytes
export function renderReceiptView(view) {
  const event = view.event || {};
  const statement = view.statement;
  const verdict = view.verdict;
  const steps = view.path_steps ?? (view.path || []).length;
  const policy = statement && statement.policy;
  const checks = verdict && verdict.checks ? Object.entries(verdict.checks).map(([name, holds]) => html`<span class="count">${name} ${holds === null ? "n/a" : holds ? "✓" : "✗"}</span>`) : "";
  return html`<div class="verdict-line">${chip(verdict ? verdictChip(verdict.status, verdict.verdict_of || "console") : verdictChip("no bundle"))}</div>
    ${view.uncovered ? html`<div class="muted">${view.uncovered}</div>` : ""}
    ${kv("receipt", `#${view.index} · ${event.actor || ""} · ${event.action || ""}`)}
    ${kv("cause", view.cause ? `${view.cause.label}${view.cause.class ? " · " + view.cause.class : ""}` : "")}
    ${kv("leaf", view.leaf)}
    ${kv("inclusion path", `${steps} ${steps === 1 ? "step" : "steps"} to a tree of ${view.tree_leaves ?? ""} leaves`)}
    ${(view.path || []).length ? html`<ol class="path">${view.path.map(step => html`<li>${shown(step)}</li>`)}</ol>` : ""}
    ${kv("root", view.root)}
    ${statement ? kv("covering statement", `seq ${statement.seq} · ${statement.leaves} leaves · signer ${String(statement.key_id || "").slice(0, 16)}`) : ""}
    ${policy ? kv("flow it names", `${policy.flow || ""} ${policy.flow_sha256 || ""}`) : ""}
    ${checks ? kv("checks", checks) : ""}
    ${kv("raw line", view.raw ? view.raw.text : "")}
    ${command("export", view.export)}
    ${command("check of record", view.command)}`;
}

// The bundle to save, written as `prismpath trail --bundle-out` writes it; null when no statement covers it.
export function bundleDownload(view) {
  if (!view || !view.bundle) {
    return null;
  }
  return { name: "bundle.json", text: JSON.stringify(view.bundle, null, 1) + "\n" };
}

export function renderRawLines(payload) {
  const lines = payload.lines || [];
  const first = payload.start ?? 0;
  const body = lines.map((line, offset) => `${first + offset} ${line.text}`).join("\n");
  return html`<div class="muted">lines ${first} to ${first + lines.length - 1} of ${payload.total ?? 0} · ${payload.size ?? 0} bytes · sha256 ${payload.sha256 || ""}</div>
    <pre class="raw">${body}</pre>`;
}

// ---------------------------------------------------------------- U5 evidence runs
const RUN_SHOWN = ["receipts", "replayed", "sample_cap", "images", "cases", "merkle_root", "root_statement", "problem"];

export function renderRunReport(report) {
  const rows = RUN_SHOWN.filter(name => report[name] !== undefined).map(name => kv(name.replace(/_/g, " "), shown(report[name])));
  return html`<div class="verdict-line">${chip(verdictChip(report.status, report.verdict_of || "console"))}
      ${claim(report.ok, "the run verifies", "the run does not verify")}</div>
    ${kv("run", report.run)}${rows}
    ${command("check of record (every receipt)", report.command)}`;
}

// ---------------------------------------------------------------- U6 change control, U7 pack verify
function causeList(found) {
  return (found || []).length ? html`<ul class="findings">${found.map(cause => html`<li>${cause.label}${cause.class ? " · " + cause.class : ""}</li>`)}</ul>` : "";
}

export function renderManifestStatus(report) {
  const receipt = report.receipt;
  let receiptLine = "";
  if (receipt) {
    const said = receipt.agrees === true ? "the receipt names the text of this flow"
      : receipt.agrees === false ? "the receipt names another text: " + receipt.flow_sha256
        : "no statement covering the receipt names a flow";
    receiptLine = kv("receipt #" + receipt.index, chip({ text: "console: " + said, cls: "chip " + (receipt.agrees === true ? "ok" : receipt.agrees === false ? "bad" : "warn") }));
  }
  return html`<div class="verdict-line">${chip(verdictChip(report.status, report.verdict_of || "console"))}</div>
    ${kv("flow", report.flow)}
    ${kv("flow sha256", report.flow_sha256)}
    ${kv("manifest names", report.manifest_flow_sha256 || "no manifest")}
    ${kv("version", report.version)}
    ${kv("authority key", report.key || "")}
    ${causeList(report.causes)}
    ${receiptLine}
    ${command("check of record", report.command)}`;
}

export function renderPackReport(report) {
  return html`<div class="verdict-line">${chip(verdictChip(report.status, report.verdict_of || "console"))}</div>
    ${kv("pack", report.ppt)}
    ${kv("authority key", report.key || "")}
    ${causeList(report.causes)}
    ${command("check of record", report.command)}`;
}

// ---------------------------------------------------------------- U4 anchors
export function renderAnchorReport(report) {
  const whose = report.verdict_of || "console";
  const lines = report.mode === "rfc3161"
    ? [claim(report.verified, "RFC 3161 timestamp verifies", "RFC 3161 timestamp does not verify", whose)]
    : [claim(report.merkle_ok, "Merkle path reaches the anchored root", "Merkle path does not reach the anchored root", whose),
       claim(report.ots_ok, "OpenTimestamps proof verifies", "OpenTimestamps proof does not verify", whose)];
  return html`<div class="verdict-line">${lines}</div>
    ${report.reason ? kv("reason", report.reason) : ""}
    ${report.root ? kv("anchored root", report.root) : ""}
    ${report.detail || report.ots_verify ? html`<pre class="raw">${report.detail || report.ots_verify}</pre>` : ""}
    ${command("check of record", report.command)}`;
}

// ---------------------------------------------------------------- the cause decoder
// A code (decimal or 0x hex) or a canonical name, decoded from the registry the console served.
export function decodeCause(registry, query) {
  const wanted = String(query ?? "").trim();
  const entries = (registry && registry.causes) || [];
  if (/^(\d+|0x[0-9a-f]+)$/i.test(wanted)) {
    const code = Number(wanted);
    if (code === 0) {
      return { code: 0, name: null, class: null, label: "0 clean", description: "the clean decision", registered: false, clean: true };
    }
    return entries.find(entry => entry.code === code) || { code, name: null, class: null, label: code + " unregistered", registered: false };
  }
  return entries.find(entry => entry.name === wanted) || { code: null, name: null, class: null, label: "unregistered", registered: false };
}

export function renderCause(entry) {
  return html`<div class="verdict-line">${chip({ text: entry.label, cls: "chip " + (entry.registered || entry.clean ? "ok" : "warn") })}</div>
    ${kv("class", entry.class || "")}${kv("description", entry.description || "")}`;
}

export function renderCauseTable(registry, filter) {
  const wanted = String(filter ?? "").trim().toLowerCase();
  const entries = ((registry && registry.causes) || []).filter(entry => !wanted
    || [entry.label, entry.class, entry.description].some(field => String(field || "").toLowerCase().includes(wanted)));
  return html`<div class="muted">registry sha256 ${(registry && registry.sha256) || ""}</div>${entries.map(entry => html`<div class="ev-row">
    <span class="a">${entry.label}</span><span>${entry.class || ""}</span><span class="muted">${entry.description || ""}</span></div>`)}`;
}

// ---------------------------------------------------------------- pinned keys (kept in the page)
export const PIN_STORE_KEY = "prismpath.pinned-keys";
const KEY_BYTES = 32;

function hexOf(bytes) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

function bytesOf(hex) {
  return Uint8Array.from(hex.match(/../g) || [], pair => parseInt(pair, 16));
}

// A public key from a dropped file's bytes: a raw 32 byte Ed25519 key, as `keygen` writes it, or its hex.
export function keyFromFile(bytes) {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (data.length === KEY_BYTES) {
    return hexOf(data);
  }
  const textForm = new TextDecoder("utf-8", { fatal: false }).decode(data).trim();
  if (/^[0-9a-f]{64}$/i.test(textForm)) {
    return textForm.toLowerCase();
  }
  throw new Error("a pinned key is a raw 32 byte Ed25519 public key, or the hex of one");
}

export function pinnedKeys(storage) {
  try {
    const held = JSON.parse(storage.getItem(PIN_STORE_KEY) || "[]");
    return Array.isArray(held) ? held.filter(key => key && /^[0-9a-f]{64}$/.test(key.hex) && typeof key.keyId === "string") : [];
  } catch {
    return [];
  }
}

function storeKeys(storage, keys) {
  try {
    storage.setItem(PIN_STORE_KEY, JSON.stringify(keys));
  } catch {
    // A storage that refuses a write (a private window) leaves the keys as they were.
  }
}

// Pin a key in the page. The key id is the sha256 of the raw key, as the log's statements name it.
export async function addPinnedKey(storage, { label, hex }) {
  const key = keyFromFile(new TextEncoder().encode(String(hex || "")));
  const keyId = hexOf(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytesOf(key))));
  const keys = pinnedKeys(storage).filter(held => held.keyId !== keyId);
  const added = { label: String(label || "").slice(0, 80), hex: key, keyId };
  storeKeys(storage, [...keys, added]);
  return added;
}

export function removePinnedKey(storage, keyId) {
  storeKeys(storage, pinnedKeys(storage).filter(held => held.keyId !== keyId));
}

export function renderPinnedKeys(keys) {
  const rows = keys.map(key => html`<div class="ev-row"><span class="a">${key.keyId.slice(0, 16)}</span>
    <span>${key.label || "unlabelled"}</span><button type="button" class="btn inline" data-key-id=${attr(key.keyId)}>Remove</button></div>`);
  return html`<div class="muted">Pinned keys are kept in this browser tab's session storage and are never sent to the console. ${keys.length ? "" : "None pinned yet."}</div>${rows}`;
}

// ---------------------------------------------------------------- the screens
function sessionStore() {
  try {
    return globalThis.sessionStorage;
  } catch {
    return null;
  }
}

const selection = { path: "", console: false, statements: "" };
let lastReceipt = null;
let causeRegistry = null;

// What the page last showed, for the in page verifier (WP5): the receipt view the console returned.
export function shownReceipt() {
  return lastReceipt;
}

async function show(outId, request, render) {
  const [path, body] = request;
  renderInto(outId, html`<div class="muted">reading</div>`);
  try {
    const answer = await postJson(path, body);
    renderInto(outId, answer && answer.error ? renderRefusal(answer) : render(answer));
    return answer && answer.error ? null : answer;
  } catch (error) {
    renderInto(outId, renderRefusal({ error: { message: String(error) } }));
    return null;
  }
}

function openScreen(name) {
  const tab = document.querySelector(`[data-screen="${name}"]`);
  if (tab) {
    tab.click();
  }
}

function selectLog(target) {
  selection.console = target.dataset.console === "1";
  selection.path = selection.console ? "" : target.dataset.trail;
  selection.statements = selection.console ? "" : target.dataset.statements || "";
  byId(IDS.trailSelected).textContent = selection.console ? "the console's own log" : selection.path;
}

function selected() {
  return { path: selection.path, console: selection.console };
}

function picked() {
  if (!selection.console && !selection.path) {
    showToast("pick a log first");
    return false;
  }
  return true;
}

async function readTrail() {
  if (!picked()) {
    return;
  }
  await show(IDS.trailOut, trailRequest({ ...selected(), since: inputValue(IDS.trailSince), last: inputValue(IDS.trailLast),
                                          pins: inputValue(IDS.trailPins) }), renderTrailReport);
}

async function openReceipt() {
  if (!picked()) {
    return;
  }
  lastReceipt = await show(IDS.receiptOut, receiptRequest({ ...selected(), index: inputValue(IDS.receiptIndex),
                                                            pins: inputValue(IDS.trailPins) }), renderReceiptView);
  byId(IDS.receiptDownload).disabled = !bundleDownload(lastReceipt);
}

function downloadBundle() {
  const file = bundleDownload(lastReceipt);
  if (!file) {
    return;
  }
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([file.text], { type: "application/json" }));
  link.download = file.name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

async function readRaw(statements) {
  if (!picked()) {
    return;
  }
  if (statements && !selection.console && !selection.statements) {
    showToast("this log has no statements file beside it");
    return;
  }
  const target = statements && !selection.console ? { path: selection.statements } : selected();
  await show(IDS.rawOut, rawRequest({ ...target, statements: statements && selection.console,
                                      start: inputValue(IDS.rawStart), count: inputValue(IDS.rawCount) }), renderRawLines);
}

export async function loadTrailsScreen() {
  try {
    const listing = await getJson(PATHS.evidenceLogs);
    renderInto(IDS.trailsList, listing.error ? renderRefusal(listing) : renderLogList(listing));
  } catch (error) {
    renderInto(IDS.trailsList, renderRefusal({ error: { message: String(error) } }));
  }
}

function onListClick(event) {
  const target = event.target.closest("[data-trail], [data-console], [data-run]");
  if (!target) {
    return;
  }
  if (target.dataset.run) {
    byId(IDS.runPath).value = target.dataset.run;
    openScreen("evidence");
    return;
  }
  selectLog(target);
  readTrail();
}

export async function loadCausesScreen() {
  if (!causeRegistry) {
    try {
      const registry = await getJson(PATHS.evidenceCauses);
      causeRegistry = registry.error ? null : registry;
    } catch {
      causeRegistry = null;
    }
  }
  paintCauses();
}

function paintCauses() {
  if (!causeRegistry) {
    renderInto(IDS.causeTable, html`<div class="muted">the cause registry could not be read</div>`);
    return;
  }
  const query = inputValue(IDS.causeQuery);
  renderInto(IDS.causeOut, query ? renderCause(decodeCause(causeRegistry, query)) : "");
  renderInto(IDS.causeTable, renderCauseTable(causeRegistry, /^(\d+|0x[0-9a-f]+)$/i.test(query) ? "" : query));
}

export function loadKeysScreen() {
  const storage = sessionStore();
  renderInto(IDS.keyList, renderPinnedKeys(storage ? pinnedKeys(storage) : []));
}

async function pinFromBytes(bytes, label) {
  const storage = sessionStore();
  const note = byId(IDS.keyNote);
  if (!storage) {
    note.textContent = "this browser keeps no session storage, so no key can be pinned here";
    return;
  }
  try {
    const added = await addPinnedKey(storage, { label, hex: keyFromFile(bytes) });
    note.textContent = "pinned " + added.keyId.slice(0, 16);
  } catch (error) {
    note.textContent = error.message || String(error);
  }
  loadKeysScreen();
}

async function pinFiles(files) {
  for (const file of Array.from(files || [])) {
    if (file.size > 4096) {
      byId(IDS.keyNote).textContent = file.name + " is too large to be a public key";
      continue;
    }
    await pinFromBytes(new Uint8Array(await file.arrayBuffer()), file.name);
  }
}

function wireKeys() {
  const drop = byId(IDS.keyDrop);
  drop.ondragover = event => {
    event.preventDefault();
    drop.classList.add("over");
  };
  drop.ondragleave = () => drop.classList.remove("over");
  drop.ondrop = event => {
    event.preventDefault();
    drop.classList.remove("over");
    pinFiles(event.dataTransfer && event.dataTransfer.files);
  };
  byId(IDS.keyFile).onchange = event => pinFiles(event.target.files);
  byId(IDS.keyAdd).onclick = () => pinFromBytes(new TextEncoder().encode(inputValue(IDS.keyHex)), inputValue(IDS.keyLabel));
  byId(IDS.keyList).onclick = event => {
    const target = event.target.closest("[data-key-id]");
    const storage = sessionStore();
    if (target && storage) {
      removePinnedKey(storage, target.dataset.keyId);
      loadKeysScreen();
    }
  };
}

// ---------------------------------------------------------------- the console's own log, the Proof panel
function eventTime(event) {
  if (event.ts_us) {
    return new Date(event.ts_us / 1000).toLocaleTimeString();
  }
  return event.ts ? new Date(event.ts * 1000).toLocaleTimeString() : "";
}

// The audit screen for an /audit payload: the console's verdict chip, the root line and the events,
// newest first.
export function renderAuditView(payload, timeOf = eventTime) {
  const verified = payload.verify === true;
  return {
    chip: { text: verified ? "console: verified ✓" : "console: does not verify ✗", cls: "chip " + (verified ? "ok" : "bad") },
    meta: `root ${(payload.root || "").slice(0, 20)} · ${payload.n ?? 0} events`,
    events: (payload.events || []).slice().reverse().map(event => {
      const who = html`<span class="a">${event.actor || ""}·${event.action || ""}</span>`;
      const when = html`<span class="muted">${timeOf(event)}</span>`;
      const data = html`<span class="muted">${JSON.stringify(event.data || {}).slice(0, 120)}</span>`;
      return html`<div class="row">${who}${when}${data}</div>`;
    }),
  };
}

export async function loadAuditScreen() {
  const payload = await getJson(PATHS.audit);
  const verdict = byId(IDS.auditVerify);
  if (payload.error) {
    verdict.textContent = "";
    byId(IDS.auditMeta).textContent = payload.error.message || "error";
    renderInto(IDS.auditEvents, []);
    return;
  }
  const view = renderAuditView(payload);
  verdict.textContent = view.chip.text;
  verdict.className = view.chip.cls;
  byId(IDS.auditMeta).textContent = view.meta;
  renderInto(IDS.auditEvents, view.events);
}

// The request each Proof button sends, as [path, body]. An empty optional input is left out.
export function proofRequest(action, inputs) {
  switch (action) {
    case "model-check": return [PATHS.attestModelCheck, { flow_md: inputs.flow }];
    case "trail": return [PATHS.attestTrail, { source: inputs.trail || undefined }];
    case "ledger-verify": return [PATHS.attestLedgerVerify, { leaf: inputs.leaf || undefined, root: inputs.root || undefined }];
    default: return null;
  }
}

export function wireAuditing() {
  document.querySelectorAll("[data-proof]").forEach(button => {
    const action = button.dataset.proof;
    button.onclick = () => {
      const [path, body] = proofRequest(action, {
        flow: inputValue(IDS.proofFlow), trail: inputValue(IDS.proofTrail),
        leaf: inputValue(IDS.proofLeaf), root: inputValue(IDS.proofRoot),
      });
      runTool(path, body, IDS.proofOut);
    };
  });
  byId(IDS.trailsList).onclick = onListClick;
  bindAction(byId(IDS.trailsRefresh), "GET", PATHS.evidenceLogs, loadTrailsScreen);
  bindAction(byId(IDS.trailGo), "POST", PATHS.evidenceTrail, readTrail);
  bindAction(byId(IDS.receiptGo), "POST", PATHS.evidenceReceipt, openReceipt);
  byId(IDS.receiptDownload).onclick = downloadBundle;
  bindAction(byId(IDS.rawLog), "POST", PATHS.evidenceRaw, () => readRaw(false));
  bindAction(byId(IDS.rawStatements), "POST", PATHS.evidenceRaw, () => readRaw(true));
  bindAction(byId(IDS.runGo), "POST", PATHS.evidenceRun, () => show(IDS.runOut, runRequest({
    path: inputValue(IDS.runPath), authority: inputValue(IDS.runAuthority), instance: inputValue(IDS.runInstance),
    sample: inputValue(IDS.runSample) }), renderRunReport));
  bindAction(byId(IDS.changeGo), "POST", PATHS.evidenceManifest, () => show(IDS.changeOut, manifestRequest({
    flow: inputValue(IDS.changeFlow), pins: inputValue(IDS.changePins), log: inputValue(IDS.changeLog),
    index: inputValue(IDS.changeIndex) }), renderManifestStatus));
  bindAction(byId(IDS.packGo), "POST", PATHS.evidencePack, () => show(IDS.packOut, packRequest({
    ppt: inputValue(IDS.packPath), pins: inputValue(IDS.packPins) }), renderPackReport));
  bindAction(byId(IDS.anchorGo), "POST", PATHS.evidenceAnchor, () => show(IDS.anchorOut, anchorRequest({
    leaf: inputValue(IDS.anchorLeaf), dir: inputValue(IDS.anchorDir), label: inputValue(IDS.anchorLabel) }), renderAnchorReport));
  bindAction(byId(IDS.anchorRfcGo), "POST", PATHS.evidenceAnchor, () => show(IDS.anchorOut, anchorRequest({
    root: inputValue(IDS.anchorRoot), tsr: inputValue(IDS.anchorTsr), cafile: inputValue(IDS.anchorCa) }), renderAnchorReport));
  byId(IDS.causeQuery).oninput = paintCauses;
  wireKeys();
}
