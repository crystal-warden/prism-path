// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The auditing interface (the assessor): the console's own audit log and the Proof panel (model
// check, the sealed receipt trail, an anchored record's verification). Every route here reads, so
// the interface is whole in the read only posture. The verdicts shown are the console's.
import { IDS } from "./ids.mjs";
import { html } from "./markup.mjs";
import { PATHS } from "./paths.mjs";
import { byId, inputValue, renderInto } from "./dom.mjs";
import { getJson } from "./transport.mjs";
import { runTool } from "./panels.mjs";

function eventTime(event) {
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
  const chip = byId(IDS.auditVerify);
  if (payload.error) {
    chip.textContent = "";
    byId(IDS.auditMeta).textContent = payload.error.message || "error";
    renderInto(IDS.auditEvents, []);
    return;
  }
  const view = renderAuditView(payload);
  chip.textContent = view.chip.text;
  chip.className = view.chip.cls;
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
}
