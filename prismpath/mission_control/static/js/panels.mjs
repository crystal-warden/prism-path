// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The tool panels the three interfaces share (Inspect, Quality, Proof, Policy). Each runs one route
// in process on the console and prints its answer, and each offers the followed project's files in
// its inputs' pickers.
import { IDS } from "./ids.mjs";
import { attr, html } from "./markup.mjs";
import { PATHS } from "./paths.mjs";
import { activeFlow } from "./state.mjs";
import { byId, renderInto } from "./dom.mjs";
import { getJson, postJson } from "./transport.mjs";

// The text a panel prints for a route's answer.
export function formatToolResult(result) {
  if (result && result.error) {
    return "error: " + (result.error.message || JSON.stringify(result.error));
  }
  return JSON.stringify(result, null, 2);
}

export async function runTool(path, body, outId) {
  const out = byId(outId);
  out.textContent = "running";
  try {
    out.textContent = formatToolResult(await postJson(path, body));
  } catch (error) {
    out.textContent = "error: " + error;
  }
}

const FLOW_INPUTS = [IDS.inspectFlow, IDS.qualityFlow, IDS.proofFlow, IDS.policyFlow];

// Seed the flow inputs with the followed flow, without running anything.
export function prefillFlowInputs() {
  const flow = activeFlow();
  FLOW_INPUTS.forEach(id => {
    const input = byId(id);
    if (input && !input.value) {
      input.value = flow;
    }
  });
}

// The <option>s of one picker: the project paths `keep` accepts.
export function renderPickerOptions(paths, keep) {
  return (paths || []).filter(keep).map(path => html`<option value=${attr(path)}></option>`);
}

const PICKERS = [
  [IDS.pickFlows, path => path.endsWith(".md")],
  [IDS.pickJsonl, path => path.endsWith(".jsonl")],
  [IDS.pickPacks, path => path.endsWith(".ppt")],
  [IDS.pickFiles, () => true],
];

export async function populatePickers() {
  let paths = [];
  try {
    paths = (await getJson(PATHS.pick)).files || [];
  } catch {
    paths = [];
  }
  PICKERS.forEach(([id, keep]) => renderInto(id, renderPickerOptions(paths, keep)));
}

export function loadPanelScreen() {
  prefillFlowInputs();
  populatePickers();
}
