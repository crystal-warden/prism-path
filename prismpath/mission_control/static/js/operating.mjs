// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The operating interface (the operator and the engineer): the human queue, where a decision is made
// for a run suspended `needs_human` and an event is delivered to a run `waiting` (nested fan-out children
// by their relative ids); the policy host, what a deployment runs with its swap history and signing; the
// cause monitor over an audit log; the lens over the run's recorded calls; the fan-out trees; routing
// quality; and, below them as the owner placed it, the sprint loop with the discovered sprints.
//
// A decision, an event, following a sprint, the sprint controls and the routing lock write, so the read
// only posture shows them as unavailable, with the reason, instead of sending requests the console would
// refuse. Everything else here reads and stays available. Every verdict shown says it is the console's.
import { IDS } from "./ids.mjs";
import { attr, html } from "./markup.mjs";
import { PATHS } from "./paths.mjs";
import { available } from "./state.mjs";
import { bindAction, byId, inputValue, renderInto, showToast } from "./dom.mjs";
import { getJson, postJson } from "./transport.mjs";
import { runTool } from "./panels.mjs";

/* ---------------- runs: the sprint loop controls ---------------- */
// The top bar's run pills for a /status payload, as text and class per pill.
export function statusPills(status) {
  const pills = {
    run: { text: status.running ? "running" : (status.paused ? "paused" : "idle"), cls: "pill " + (status.running ? "run" : "stopped") },
    iteration: { text: status.iteration != null ? "it " + status.iteration : "", cls: "pill" },
    gate: { text: "", cls: "pill" },
    buffer: { text: status.unbuffered === true ? "unbuffered" : status.unbuffered === false ? "buffered" : "", cls: "pill" },
    audit: { text: "audit " + (status.audit_n ?? 0), cls: "pill" },
    project: { text: status.dir || "", cls: "proj" },
  };
  if (status.iteration != null) {
    pills.gate = { text: status.valid ? "gate ✓" : "gate ✗", cls: "pill " + (status.valid ? "ok" : "bad") };
  }
  return pills;
}

const PILL_IDS = { run: IDS.runPill, iteration: IDS.iterPill, gate: IDS.gatePill, buffer: IDS.bufferPill, audit: IDS.auditPill, project: IDS.project };

export function paintStatusPills(status) {
  if (!status) {
    return;
  }
  for (const [name, pill] of Object.entries(statusPills(status))) {
    const element = byId(PILL_IDS[name]);
    element.textContent = pill.text;
    element.className = pill.cls;
  }
}

export function startRequest(form) {
  return {
    proj: form.proj.value.trim() || undefined,
    gate: form.gate.value.trim() || undefined,
    nudge_file: form.nudge_file.value.trim() || undefined,
    model: form.model.value.trim() || undefined,
    rag: form.rag.checked,
    lessons: form.lessons.checked,
    fresh: form.fresh.checked,
    unbuffered: form.unbuffered.checked,
  };
}

async function startSprint(submitEvent) {
  submitEvent.preventDefault();
  const result = await postJson(PATHS.sprintStart, startRequest(submitEvent.target));
  showToast(result.error
    ? (result.error.message || "error")
    : `launched (${result.unbuffered ? "unbuffered" : "buffered"}) pid ${result.pid}`);
}

const SPRINT_ACTIONS = { pause: PATHS.sprintPause, resume: PATHS.sprintResume, stop: PATHS.sprintStop };

async function sendSprintAction(action) {
  const result = await postJson(SPRINT_ACTIONS[action], {});
  showToast(result.error ? (result.error.message || "error") : action + " ok");
}

function wireRuns() {
  const startOpen = available("POST", PATHS.sprintStart);
  const anyControl = startOpen || Object.values(SPRINT_ACTIONS).some(path => available("POST", path));
  byId(IDS.runsUnavailable).classList.toggle("hidden", anyControl);
  byId(IDS.runControls).classList.toggle("hidden", !anyControl);
  bindAction(byId(IDS.startToggle), "POST", PATHS.sprintStart, () => byId(IDS.startForm).classList.toggle("hidden"));
  if (startOpen) {
    byId(IDS.startForm).onsubmit = startSprint;
  }
  document.querySelectorAll("[data-act]").forEach(button => {
    const action = button.dataset.act;
    bindAction(button, "POST", SPRINT_ACTIONS[action], () => sendSprintAction(action));
  });
}

/* ---------------- runs: the discovered sprints ---------------- */
// A heartbeat age in seconds, as the operator reads it.
export function formatAge(seconds) {
  if (typeof seconds !== "number" || !Number.isFinite(seconds)) {
    return "?";
  }
  if (seconds < 60) {
    return seconds.toFixed(1) + " s";
  }
  if (seconds < 3600) {
    return Math.round(seconds / 60) + " min";
  }
  return (seconds / 3600).toFixed(1) + " h";
}

function gateVerdict(valid) {
  if (valid === true) {
    return html`<span class="v-yes">gate ✓</span>`;
  }
  if (valid === false) {
    return html`<span class="v-no">gate ✗</span>`;
  }
  return html`<span class="muted">no gate verdict</span>`;
}

function sprintState(sprint) {
  if (sprint.running) {
    return "running";
  }
  return sprint.done ? "done" : "stale";
}

// The sprints the console discovered by their status.json heartbeats (the /status `sprints` list),
// running first, with the followed one marked. Following another sprint writes (it is audited), so the
// read only posture offers no button and says why.
export function renderSprintList(sprints, followed, canSelect) {
  if (!sprints || !sprints.length) {
    return html`<div class="muted">no sprints discovered: a sprint announces itself with a status.json heartbeat.</div>`;
  }
  const note = canSelect
    ? html`<div class="toolrow"><button class="btn" data-auto="1">Follow the live sprint</button></div>`
    : html`<div class="muted unavailable-note">selecting a sprint is unavailable in the read-only posture</div>`;
  const rows = sprints.map(sprint => {
    const isFollowed = sprint.proj === followed;
    const action = isFollowed
      ? html`<span class="chip ok">following</span>`
      : (canSelect ? html`<button class="btn" data-select=${attr(sprint.proj)}>Follow</button>` : "");
    const iteration = sprint.iteration != null ? html`<span class="muted">it ${sprint.iteration}</span>` : "";
    return html`<div class="sprint${isFollowed ? " followed" : ""}"><span class="a">${sprint.name || sprint.proj}</span>
      <span class="muted">${sprint.proj}</span><span>${sprintState(sprint)}</span>${iteration}
      <span class="muted">heartbeat ${formatAge(sprint.age)}</span>${gateVerdict(sprint.valid)}${action}</div>`;
  });
  return [note, ...rows];
}

export async function loadRunsScreen() {
  const status = await getJson(PATHS.status);
  if (status.error) {
    renderInto(IDS.sprintList, html`<div class="muted">${status.error.message}</div>`);
    return;
  }
  renderInto(IDS.sprintList, renderSprintList(status.sprints, status.dir, available("POST", PATHS.sprintSelect)));
  const list = byId(IDS.sprintList);
  list.querySelectorAll("[data-select]").forEach(button => {
    button.onclick = () => followSprint(PATHS.sprintSelect, { proj: button.dataset.select });
  });
  list.querySelectorAll("[data-auto]").forEach(button => {
    button.onclick = () => followSprint(PATHS.sprintAuto, {});
  });
}

async function followSprint(path, body) {
  const result = await postJson(path, body);
  showToast(result.error ? (result.error.message || "error") : "following " + (result.proj || ""));
  loadRunsScreen();
}

/* ---------------- queue (the human decisions and the events to deliver) ---------------- */
export function queueItemId(item, position) {
  return item.id || item.path || String(position);
}

// The label of an event button: the timeout is named as the operator knows it.
export function eventLabel(event) {
  return event === "__timeout__" ? "timeout" : event;
}

function score(value) {
  return typeof value === "number" && Number.isFinite(value) ? value.toFixed(2) : "—";
}

function capabilitiesOf(capabilities) {
  // A bare boolean is the older call: one switch for every queue write.
  return typeof capabilities === "boolean"
    ? { canDecide: capabilities, canDeliver: capabilities }
    : { canDecide: Boolean(capabilities && capabilities.canDecide), canDeliver: Boolean(capabilities && capabilities.canDeliver) };
}

function decisionOptions(item, itemId, canDecide) {
  const candidates = item.candidates || [];
  const rows = candidates.map(candidate => html`<div class="cand"><span class="a">${candidate.target}</span>
    <span class="muted">${candidate.condition || ""}</span><span class="muted">score ${score(candidate.score)}</span></div>`);
  const wouldPick = item.would_pick ? html`<div class="muted">the router would pick ${item.would_pick}</div>` : "";
  let actions;
  if (!canDecide) {
    actions = html`<span class="muted unavailable-note">deciding is unavailable in the read-only posture</span>`;
  } else if (candidates.length) {
    actions = candidates.map(candidate =>
      html`<button class="btn go" data-decide=${attr(itemId)} data-choose=${attr(candidate.target)}>${candidate.target}</button>`);
  } else {
    actions = html`<input placeholder="edge / choice" data-id=${attr(itemId)}><button class="btn go" data-decide=${attr(itemId)}>Decide</button>`;
  }
  const decided = item.decision && item.decision.choose
    ? html`<div class="recorded">decided ${item.decision.choose} by ${item.decision.decided_by || "?"} · applied at the next resume</div>`
    : "";
  return html`${rows}${wouldPick}${decided}<div class="opts">${actions}</div>`;
}

function eventOptions(item, itemId, canDeliver) {
  const awaiting = item.awaiting || [];
  const timeout = item.timeout_s != null ? html`<div class="muted">timeout after ${item.timeout_s} s</div>` : "";
  const fanout = item.fanout ? html`<div class="muted">a fan-out parent: its join event arrives from its children</div>` : "";
  let actions;
  if (!awaiting.length) {
    actions = html`<span class="muted">no event edges: nothing can be delivered to this node</span>`;
  } else if (!canDeliver) {
    actions = html`<span class="muted unavailable-note">delivering an event is unavailable in the read-only posture</span>`;
  } else {
    actions = awaiting.map(event =>
      html`<button class="btn go" data-deliver=${attr(itemId)} data-event=${attr(event)}>${eventLabel(event)}</button>`);
  }
  const recorded = item.pending_event && item.pending_event.event
    ? html`<div class="recorded">event ${eventLabel(item.pending_event.event)} recorded by ${item.pending_event.decided_by || "?"} · applied at the next resume</div>`
    : "";
  return html`<div class="muted">awaiting ${awaiting.map(eventLabel).join(", ") || "nothing"}</div>${timeout}${fanout}${recorded}<div class="opts">${actions}</div>`;
}

// One card per run in the queue: its evidence packet (node, reason, candidate edges with the router's
// scores) and the choice to record, or, for a waiting run, the events its node awaits.
export function renderQueueItems(items, capabilities) {
  if (!items || !items.length) {
    return html`<div class="muted">nothing awaiting a decision or an event.</div>`;
  }
  const { canDecide, canDeliver } = capabilitiesOf(capabilities);
  return items.map((item, position) => {
    const itemId = queueItemId(item, position);
    const waiting = item.stopped === "waiting";
    const parent = item.child_of ? html`<span class="chip">child of ${item.child_of}</span>` : "";
    const where = html`<div class="muted">${item.flow || ""}${item.node ? " · node " + item.node : ""} · ${waiting ? "waiting for an event" : "needs a human"}</div>`;
    const reason = item.reason ? html`<div>${item.reason}</div>` : "";
    const body = waiting ? eventOptions(item, itemId, canDeliver) : decisionOptions(item, itemId, canDecide);
    return html`<div class="q-item${waiting ? " waiting" : ""}"><div class="q-head"><div class="a">${itemId}</div>${parent}</div>
      ${where}${reason}${body}</div>`;
  });
}

export async function loadQueueScreen() {
  const payload = await getJson(PATHS.queue);
  const capabilities = { canDecide: available("POST", PATHS.queueDecide), canDeliver: available("POST", PATHS.queueEvent) };
  renderInto(IDS.queueItems, payload.error
    ? html`<div class="muted">${payload.error.message}</div>`
    : renderQueueItems(payload.items, capabilities));
  byId(IDS.queueItems).querySelectorAll(".q-item").forEach(card => {
    card.querySelectorAll("[data-decide]").forEach(button => {
      const input = card.querySelector("input[data-id]");
      button.onclick = () => decideQueueItem(button.dataset.decide,
        button.dataset.choose !== undefined ? button.dataset.choose : (input ? input.value.trim() : ""));
    });
    card.querySelectorAll("[data-deliver]").forEach(button => {
      button.onclick = () => deliverEvent(button.dataset.deliver, button.dataset.event);
    });
  });
}

async function decideQueueItem(itemId, choose) {
  if (!choose) {
    showToast("enter a choice");
    return;
  }
  const result = await postJson(PATHS.queueDecide, { id: itemId, choose });
  showToast(result.error ? (result.error.message || "error") : "recorded");
  loadQueueScreen();
}

async function deliverEvent(itemId, event) {
  const result = await postJson(PATHS.queueEvent, { id: itemId, event });
  showToast(result.error ? (result.error.message || "error") : "event " + eventLabel(event) + " recorded");
  loadQueueScreen();
}

/* ---------------- the policy host ---------------- */
function short(digest) {
  return typeof digest === "string" ? digest.slice(0, 16) : "";
}

function whenOf(seconds) {
  return typeof seconds === "number" ? new Date(seconds * 1000).toISOString().replace(".000Z", "Z") : "";
}

function historyRow(event) {
  const seconds = typeof event.ts_us === "number" ? event.ts_us / 1_000_000 : undefined;
  const version = event.data && event.data.version != null ? "version " + event.data.version : "";
  return html`<div class="row"><span class="a">${event.action || "?"}</span><span>${event.actor || ""}</span><span class="muted">${version}</span><span class="muted">${whenOf(seconds)}</span></div>`;
}

// What a deployment runs, from its state directory (/policy/active): the active record, the console's
// check of its image, the swap history from swaps.log with the console's check of its root, and the
// root statement chain beside it. Signing and attesting stay on the command line.
export function renderPolicyHost(report) {
  const log = report.log || {};
  const head = report.active
    ? html`<div><span class="a">active ${short(report.active)}</span> <span>version ${report.version ?? "?"}</span>
        <span class="muted">${report.unsigned ? "unsigned image" : "signed image"}</span>
        <span class="muted">${report.envelope_id ? "envelope " + report.envelope_id : ""}</span>
        <span class="muted">${report.since != null ? "since " + (typeof report.since === "number" ? whenOf(report.since) : report.since) : ""}</span></div>
        ${report.overlay_of ? html`<div class="muted">overlay of ${short(report.overlay_of)}</div>` : ""}`
    : html`<div class="muted">no active policy (${report.reason || "no record"})</div>`;
  let image = "";
  if (report.image_ok === true) {
    image = html`<div class="chip ok">console: the image matches the record ✓</div>`;
  } else if (report.image_ok === false) {
    image = html`<div class="chip bad">console: the image does not match ✗</div> <span class="muted">${report.reason || ""}</span>`;
  }
  const pending = report.pending ? html`<div class="unavailable-note">a swap is pending</div>` : "";
  const logLine = log.present
    ? html`<div><span class="chip ${log.verifies ? "ok" : "bad"}">${log.verifies ? "console: swaps.log verifies ✓" : "console: swaps.log does not verify ✗"}</span>
        <span class="muted">${log.events ?? 0} events · root ${short(log.root)}</span></div>`
    : html`<div class="muted">no swaps.log in this state directory</div>`;
  const signing = report.signing
    ? html`<div class="muted">root statements: <span class="a">${report.signing.status || "?"}</span>${report.signing.statements != null ? " · " + report.signing.statements + " statements" : ""}${report.signing.reason ? " · " + report.signing.reason : ""}</div>`
    : "";
  const history = (report.history || []).slice().reverse().map(historyRow);
  return html`${head}${image}${pending}${logLine}${signing}<div class="table">${history}</div>`;
}

async function readPolicyHost() {
  const stateDir = inputValue(IDS.hostState);
  if (!stateDir) {
    showToast("name a state directory under an evidence root");
    return;
  }
  const report = await getJson(PATHS.policyActive, { state_dir: stateDir });
  renderInto(IDS.hostOut, report.error ? html`<div class="muted">${report.error.message}</div>` : renderPolicyHost(report));
}

/* ---------------- the cause monitor ---------------- */
function rowsOf(buckets, field, starts, decoded) {
  const index = new Map(starts.map((start, position) => [start, position]));
  const rows = new Map();
  for (const bucket of buckets) {
    for (const [key, count] of Object.entries(bucket[field] || {})) {
      if (!rows.has(key)) {
        const entry = decoded ? decoded[key] : undefined;
        rows.set(key, { key, label: entry ? entry.label : key, class: entry ? entry.class : undefined,
                        counts: new Array(starts.length).fill(0), total: 0 });
      }
      const row = rows.get(key);
      row.counts[index.get(bucket.start)] += count;
      row.total += count;
    }
  }
  return [...rows.values()].sort((a, b) => b.total - a.total || a.key.localeCompare(b.key));
}

// The sparse /trail/causes buckets filled to every bucket between the first and the last, so a cause
// that starts climbing shows as a climb and not as two neighbouring points.
export function fillSeries(series) {
  const buckets = series.buckets || [];
  const step = series.bucket_s || 1;
  const starts = [];
  if (buckets.length) {
    const first = Math.min(...buckets.map(bucket => bucket.start));
    const last = Math.max(...buckets.map(bucket => bucket.start));
    for (let start = first; start <= last; start += step) {
      starts.push(start);
    }
  }
  return { starts, causes: rowsOf(buckets, "by_cause", starts, series.causes || {}), actions: rowsOf(buckets, "by_action", starts, null) };
}

function coordinate(value) {
  return String(Math.round(value * 100) / 100);
}

// A sparkline drawn in SVG, scaled to the busiest bucket. No library, no inline style.
export function sparkline(counts, { width = 120, height = 18 } = {}) {
  const values = counts && counts.length ? counts : [0];
  const peak = Math.max(...values);
  const y = value => coordinate(peak > 0 ? height - (value / peak) * height : height);
  const points = values.length === 1
    ? [`0,${y(values[0])}`, `${coordinate(width)},${y(values[0])}`]
    : values.map((value, position) => `${coordinate((position * width) / (values.length - 1))},${y(value)}`);
  return html`<svg class="spark" viewBox=${attr(`0 0 ${width} ${height}`)} width=${attr(width)} height=${attr(height)} aria-hidden="true"><polyline points=${attr(points.join(" "))}></polyline></svg>`;
}

function seriesTable(title, rows, withClass) {
  const head = html`<tr><th>${title}</th>${withClass ? html`<th>class</th>` : ""}<th>total</th><th>latest</th><th>over the window</th></tr>`;
  const body = rows.map(row => html`<tr><td>${row.label}</td>${withClass ? html`<td>${row.class || ""}</td>` : ""}<td>${row.total}</td><td>${row.counts[row.counts.length - 1] ?? 0}</td><td>${sparkline(row.counts)}</td></tr>`);
  return html`<table class="series"><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

// Counts by cause and by action over an audit log, windowed by time: a plain table with a sparkline
// per row. The counts are the console's, read by the same reader the auditing interface uses.
export function renderCauseMonitor(series) {
  const summary = html`<div class="muted">console: ${series.events ?? 0} events · ${series.bucket_s} s buckets · ${series.untimed ?? 0} untimed · ${series.path || ""}</div>`;
  if (!series.events || !(series.buckets || []).length) {
    return html`${summary}<div class="muted">no events in the window.</div>`;
  }
  const filled = fillSeries(series);
  const causes = filled.causes.length ? seriesTable("cause", filled.causes, true) : html`<div class="muted">no decisions in the window.</div>`;
  return html`${summary}${causes}${seriesTable("action", filled.actions, false)}`;
}

// The /trail/causes query for the monitor's inputs; a blank log is the console's own.
export function causesQuery(inputs) {
  const query = { bucket_s: (inputs.bucket || "").trim() || "3600" };
  for (const [field, value] of [["path", inputs.path], ["since", inputs.since], ["last", inputs.last]]) {
    if (value && value.trim()) {
      query[field] = value.trim();
    }
  }
  return query;
}

export async function loadMonitorScreen() {
  const query = causesQuery({ path: inputValue(IDS.monitorPath), bucket: inputValue(IDS.monitorBucket),
                              since: inputValue(IDS.monitorSince), last: inputValue(IDS.monitorLast) });
  const series = await getJson(PATHS.trailCauses, query);
  renderInto(IDS.monitorOut, series.error ? html`<div class="muted">${series.error.message}</div>` : renderCauseMonitor(series));
}

/* ---------------- the lens ---------------- */
function duration(ms) {
  if (typeof ms !== "number" || !ms) {
    return "";
  }
  return ms < 1000 ? ms + " ms" : (ms / 1000).toFixed(1) + " s";
}

// Who said what to which worker, newest first. The labels are the records' own (`model` or `worker`
// as the producer wrote them), never names the console supplies.
export function renderLens(payload) {
  const events = (payload && payload.events) || [];
  if (!events.length) {
    return html`<div class="muted">no recorded interactions in the followed project.</div>`;
  }
  return events.slice().reverse().map(event => html`<div class="lens-row"><div><span class="a">${event.from} → ${event.to}</span>
    <span class="muted">${[event.substage, event.kind, duration(event.dur_ms)].filter(Boolean).join(" · ")}</span></div>
    <div class="muted lens-text">${String(event.prompt || "").slice(0, 400)}</div><div class="lens-text">${String(event.output || "").slice(0, 400)}</div></div>`);
}

export async function loadLensScreen() {
  const payload = await getJson(PATHS.interactions);
  renderInto(IDS.lensEvents, payload.error ? html`<div class="muted">${payload.error.message}</div>` : renderLens(payload));
}

/* ---------------- fan-outs ---------------- */
function baseName(path) {
  return typeof path === "string" ? path.split(/[\\/]/).pop() : "";
}

function renderFanout(fanout) {
  const progress = fanout.progress || {};
  const children = (fanout.children || []).map(child => html`<li><span class="a">${child.item_id}</span> <span>${child.stopped || "?"}</span>
    ${child.done ? html`<span class="v-yes">done</span>` : ""}${child.node ? html` <span class="muted">at ${child.node}</span>` : ""}
    ${child.child_error ? html` <span class="v-no">${child.child_error}</span>` : ""}${child.fanout ? renderFanout(child.fanout) : ""}</li>`);
  return html`<div class="fanout"><div><span class="a">${baseName(fanout.flow)}</span> <span class="muted">node ${fanout.node || "?"} · ${fanout.stopped || "?"} · join ${fanout.join || "?"} · ${progress.done ?? 0}/${progress.n ?? 0} done${fanout.joined ? " · joined" : ""}</span></div>
    <ul>${children}</ul></div>`;
}

// Every fan-out composition as a nested tree with each child's stop state.
export function renderFanouts(fanouts) {
  return fanouts && fanouts.length
    ? html`<div class="tree">${fanouts.map(renderFanout)}</div>`
    : html`<div class="muted">no fan-out compositions.</div>`;
}

export async function loadFlowsScreen() {
  const payload = await getJson(PATHS.fanouts);
  renderInto(IDS.fanoutTree, payload.error ? html`<div class="muted">${payload.error.message}</div>` : renderFanouts(payload.fanouts));
}

/* ---------------- quality and policy panels ---------------- */
// The request each Quality button sends, as [path, body].
export function qualityRequest(action, inputs) {
  switch (action) {
    case "lock": return [PATHS.qualityLock, { flow_md: inputs.flow }];
    case "lock-check": return [PATHS.qualityLockCheck, { flow_md: inputs.flow }];
    case "calibrate": return [PATHS.qualityCalibrate, { labels_path: inputs.labels }];
    case "centroids": return [PATHS.qualityCentroids, { benchmark_path: inputs.bench }];
    case "kappa": return [PATHS.qualityKappa, { a_path: inputs.a, b_path: inputs.b }];
    default: return null;
  }
}

export function policyRequest(action, inputs) {
  switch (action) {
    case "pack-verify": return [PATHS.policyPackVerify, { ppt_path: inputs.pack, pub: inputs.pub.split(/\s+/).filter(Boolean) }];
    case "pack-active": return [PATHS.policyPackActive, { state_dir: inputs.state }];
    case "facet-decode": return [PATHS.policyFacetDecode, { flow_md: inputs.flow, payload_hex: inputs.hex }];
    case "facet-encode": return [PATHS.policyFacetEncode, { flow_md: inputs.flow, reading_json: inputs.json }];
    default: return null;
  }
}

function qualityInputs() {
  return { flow: inputValue(IDS.qualityFlow), labels: inputValue(IDS.qualityLabels), bench: inputValue(IDS.qualityBench),
           a: inputValue(IDS.qualityA), b: inputValue(IDS.qualityB) };
}

function policyInputs() {
  return { pack: inputValue(IDS.policyPack), pub: inputValue(IDS.policyPub), state: inputValue(IDS.policyState),
           flow: inputValue(IDS.policyFlow), hex: inputValue(IDS.policyHex), json: inputValue(IDS.policyJson) };
}

// Wire each button of a panel to its route. The route a button sends to does not depend on the
// inputs, so it is read once from the empty inputs to decide whether the posture mounts it.
function wirePanel(selector, key, requestFor, readInputs, emptyInputs, outId) {
  document.querySelectorAll(selector).forEach(button => {
    const action = button.dataset[key];
    const [path] = requestFor(action, emptyInputs);
    bindAction(button, "POST", path, () => {
      const [requestPath, body] = requestFor(action, readInputs());
      runTool(requestPath, body, outId);
    });
  });
}

const EMPTY_QUALITY = { flow: "", labels: "", bench: "", a: "", b: "" };
const EMPTY_POLICY = { pack: "", pub: "", state: "", flow: "", hex: "", json: "" };

export function wireOperating() {
  wireRuns();
  byId(IDS.hostRead).onclick = readPolicyHost;
  byId(IDS.monitorGo).onclick = loadMonitorScreen;
  wirePanel("[data-quality]", "quality", qualityRequest, qualityInputs, EMPTY_QUALITY, IDS.qualityOut);
  wirePanel("[data-policy]", "policy", policyRequest, policyInputs, EMPTY_POLICY, IDS.policyOut);
}
