// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// Mission Control, the browser half. It reads the console's API under /api/v1, follows the live event
// stream, and lays the screens out under three interfaces: authoring (the process owner), operating
// (the operator and the engineer) and auditing (the assessor). The page carries two facts from the
// server in its meta tags, this launch's session token and the console's posture.
import { IDS } from "./ids.mjs";
import { PATHS, POSTURE_FULL, POSTURE_READ_ONLY } from "./paths.mjs";
import { state } from "./state.mjs";
import { byId } from "./dom.mjs";
import { configureTransport, getJson } from "./transport.mjs";
import { followEventStream } from "./events.mjs";
import { loadGraphScreen, refreshActiveNode, wireGraph } from "./graph.mjs";
import { loadFilesScreen, wireAuthoring } from "./authoring.mjs";
import { loadFlowsScreen, loadQueueScreen, paintStatusPills, wireOperating } from "./operating.mjs";
import { loadAuditScreen, loadCausesScreen, loadKeysScreen, loadTrailsScreen, wireAuditing } from "./auditing.mjs";
import { loadPanelScreen } from "./panels.mjs";

// Each screen, the interface it sits under, its view and what opening it loads. The first screen of
// an interface is the one its tab opens. The sprint loop controls (Runs) sit below the human queue and
// the policy host, as the owner placed them.
export const SCREENS = Object.freeze([
  { screen: "graph", interface: "authoring", view: IDS.viewGraph, load: () => loadGraphScreen(true) },
  { screen: "files", interface: "authoring", view: IDS.viewFiles, load: loadFilesScreen },
  { screen: "inspect", interface: "authoring", view: IDS.viewInspect, load: loadPanelScreen },
  { screen: "queue", interface: "operating", view: IDS.viewQueue, load: loadQueueScreen },
  { screen: "policy", interface: "operating", view: IDS.viewPolicy, load: loadPanelScreen },
  { screen: "runs", interface: "operating", view: IDS.viewRuns, load: () => {} },
  { screen: "quality", interface: "operating", view: IDS.viewQuality, load: loadPanelScreen },
  { screen: "flows", interface: "operating", view: IDS.viewFlows, load: loadFlowsScreen },
  { screen: "trails", interface: "auditing", view: IDS.viewTrails, load: loadTrailsScreen },
  { screen: "evidence", interface: "auditing", view: IDS.viewEvidence, load: () => {} },
  { screen: "change", interface: "auditing", view: IDS.viewChange, load: () => {} },
  { screen: "anchors", interface: "auditing", view: IDS.viewAnchors, load: () => {} },
  { screen: "causes", interface: "auditing", view: IDS.viewCauses, load: loadCausesScreen },
  { screen: "keys", interface: "auditing", view: IDS.viewKeys, load: loadKeysScreen },
  { screen: "audit", interface: "auditing", view: IDS.viewAudit, load: loadAuditScreen },
  { screen: "proof", interface: "auditing", view: IDS.viewProof, load: loadPanelScreen },
]);

function metaContent(name) {
  const meta = document.querySelector(`meta[name="${name}"]`);
  return meta ? meta.content : "";
}

function paintConnectionPill(live) {
  const pill = byId(IDS.connPill);
  pill.textContent = live ? "● live" : "● offline";
  pill.className = "pill " + (live ? "on" : "off");
}

function paintPosture() {
  const pill = byId(IDS.posturePill);
  const readOnly = state.posture === POSTURE_READ_ONLY;
  pill.textContent = readOnly ? "read-only" : "full";
  pill.className = "pill " + (readOnly ? "posture-ro" : "posture-full");
  pill.title = readOnly
    ? "the console mounts no write routes: controls that write show as unavailable"
    : "the console mounts every route";
  document.body.classList.toggle("read-only", readOnly);
}

function screensOf(name) {
  return SCREENS.filter(entry => entry.interface === name);
}

function showScreen(name) {
  const entry = SCREENS.find(candidate => candidate.screen === name);
  if (!entry) {
    return;
  }
  state.screen = name;
  state.interface = entry.interface;
  byId(IDS.interfaceTabs).querySelectorAll("[data-interface]").forEach(tab => {
    const active = tab.dataset.interface === entry.interface;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  byId(IDS.screenTabs).querySelectorAll("[data-screen]").forEach(tab => {
    tab.classList.toggle("hidden", tab.dataset.interface !== entry.interface);
    tab.classList.toggle("active", tab.dataset.screen === name);
    tab.setAttribute("aria-selected", String(tab.dataset.screen === name));
  });
  SCREENS.forEach(candidate => byId(candidate.view).classList.toggle("active", candidate.screen === name));
  entry.load();
}

function onStreamEvent(event) {
  if (event.type === "status") {
    paintStatusPills(event.status);
  } else if (event.type === "interactions") {
    loadRetrievals();
    if (state.screen === "audit") {
      loadAuditScreen();
    }
  } else if (event.type === "graph" && state.screen === "graph") {
    refreshActiveNode();
  }
}

async function loadRetrievals() {
  try {
    const payload = await getJson(PATHS.retrievals);
    if (!payload.error) {
      state.retrievals = payload.retrievals || [];
    }
  } catch {
    // Keep the last good list: a stale node detail panel beats an empty one.
  }
}

function wireTabs() {
  byId(IDS.interfaceTabs).querySelectorAll("[data-interface]").forEach(tab => {
    tab.onclick = () => showScreen(screensOf(tab.dataset.interface)[0].screen);
  });
  byId(IDS.screenTabs).querySelectorAll("[data-screen]").forEach(tab => {
    tab.onclick = () => showScreen(tab.dataset.screen);
  });
}

function start() {
  configureTransport({ token: metaContent("prismpath-session") });
  // Anything but the server's explicit "full" is treated as read only, so a page that lost its
  // posture never offers a write.
  state.posture = metaContent("prismpath-posture") === POSTURE_FULL ? POSTURE_FULL : POSTURE_READ_ONLY;
  paintPosture();
  wireTabs();
  wireGraph();
  wireAuthoring();
  wireOperating();
  wireAuditing();
  loadRetrievals();
  followEventStream({ onEvent: onStreamEvent, onConnection: paintConnectionPill });
  showScreen("graph");
}

start();
