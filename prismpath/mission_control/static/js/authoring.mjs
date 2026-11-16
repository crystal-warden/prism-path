// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The authoring interface (the process owner). The Graph screen lives in graph.mjs; this module holds
// the Files screen with its editor and the Inspect panel. Saving a file is a write, so in the read
// only posture the editor opens files and says why it cannot save them.
import { IDS } from "./ids.mjs";
import { attr, html } from "./markup.mjs";
import { PATHS } from "./paths.mjs";
import { available, state } from "./state.mjs";
import { bindAction, byId, renderInto, showToast } from "./dom.mjs";
import { getJson, postJson } from "./transport.mjs";
import { runTool } from "./panels.mjs";

export function renderFileList(files, selectedPath = null) {
  return (files || []).map(file =>
    html`<div class="${file.path === selectedPath ? "f sel" : "f"}" data-p=${attr(file.path)}><span>${file.path}</span><span class="sz">${file.size}</span></div>`);
}

export async function loadFilesScreen() {
  const payload = await getJson(PATHS.files);
  if (payload.error) {
    renderInto(IDS.fileList, html`<div class="muted graph-message">${payload.error.message}</div>`);
    return;
  }
  renderInto(IDS.fileList, renderFileList(payload.files, state.openFilePath));
  byId(IDS.fileList).querySelectorAll(".f").forEach(row => {
    row.onclick = () => openFile(row.dataset.p, row);
  });
}

async function openFile(path, row) {
  byId(IDS.fileList).querySelectorAll(".f").forEach(other => other.classList.toggle("sel", other === row));
  const payload = await getJson(PATHS.file, { path });
  if (payload.error) {
    showToast(payload.error.message || "error");
    return;
  }
  state.openFilePath = path;
  byId(IDS.editorPath).textContent = path;
  byId(IDS.editorBody).value = payload.content;
  byId(IDS.editorSave).disabled = !available("POST", PATHS.file);
}

async function saveOpenFile() {
  if (!state.openFilePath) {
    return;
  }
  const result = await postJson(PATHS.file, { path: state.openFilePath, content: byId(IDS.editorBody).value });
  showToast(result.error ? (result.error.message || "error") : "saved " + state.openFilePath);
}

// Each Inspect button's route; the Mermaid export also takes a direction.
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

export function wireAuthoring() {
  const save = byId(IDS.editorSave);
  if (!bindAction(save, "POST", PATHS.file, saveOpenFile)) {
    byId(IDS.editorNote).textContent = "read-only posture: files open for reading, saving is unavailable";
    byId(IDS.editorNote).classList.remove("hidden");
    byId(IDS.editorBody).readOnly = true;
  }
  document.querySelectorAll("[data-inspect]").forEach(button => {
    const action = button.dataset.inspect;
    button.onclick = () => {
      const request = inspectRequest(action, byId(IDS.inspectFlow).value.trim());
      runTool(request.path, request.body, IDS.inspectOut);
    };
  });
}
