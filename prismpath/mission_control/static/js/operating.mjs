// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The operating interface (the operator and the engineer): the sprint loop controls, the human
// decision queue, the policy host checks, routing quality and the fan-out compositions. The sprint
// controls, a queue decision and the routing lock write are writes, so the read only
// posture shows them as unavailable instead of sending requests the console would refuse. Checking the
// lock and reading the deployment's active policy are reads and stay available.
import { IDS } from "./ids.mjs";
import { attr, html } from "./markup.mjs";
import { PATHS } from "./paths.mjs";
import { available } from "./state.mjs";
import { bindAction, byId, inputValue, renderInto, showToast } from "./dom.mjs";
import { getJson, postJson } from "./transport.mjs";
import { runTool } from "./panels.mjs";

/* ---------------- runs ---------------- */
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

/* ---------------- queue (the human decisions) ---------------- */
export function queueItemId(item, position) {
  return item.id || item.path || String(position);
}

export function renderQueueItems(items, canDecide) {
  if (!items || !items.length) {
    return html`<div class="muted">nothing awaiting a decision.</div>`;
  }
  return items.map((item, position) => {
    const itemId = queueItemId(item, position);
    const decide = canDecide
      ? html`<input placeholder="edge / choice" data-id=${attr(itemId)}><button class="btn go" data-decide=${attr(itemId)}>Decide</button>`
      : html`<span class="muted unavailable-note">deciding is unavailable in the read-only posture</span>`;
    return html`<div class="q-item"><div class="a">${itemId}</div>
      <div class="muted">${JSON.stringify(item).slice(0, 240)}</div>
      <div class="opts">${decide}</div></div>`;
  });
}

export async function loadQueueScreen() {
  const payload = await getJson(PATHS.queue);
  const canDecide = available("POST", PATHS.queueDecide);
  renderInto(IDS.queueItems, payload.error
    ? html`<div class="muted">${payload.error.message}</div>`
    : renderQueueItems(payload.items, canDecide));
  byId(IDS.queueItems).querySelectorAll(".q-item").forEach(card => {
    const button = card.querySelector("[data-decide]");
    const input = card.querySelector("input[data-id]");
    if (button && input) {
      button.onclick = () => decideQueueItem(button.dataset.decide, input.value.trim());
    }
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

/* ---------------- fan-outs ---------------- */
export function renderFanouts(fanouts) {
  return fanouts && fanouts.length
    ? html`<pre class="tree">${JSON.stringify(fanouts, null, 2)}</pre>`
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
  wirePanel("[data-quality]", "quality", qualityRequest, qualityInputs, EMPTY_QUALITY, IDS.qualityOut);
  wirePanel("[data-policy]", "policy", policyRequest, policyInputs, EMPTY_POLICY, IDS.policyOut);
}
