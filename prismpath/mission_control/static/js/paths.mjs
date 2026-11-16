// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// Every API path the client requests, relative to API_PREFIX, and the routes among them that write.
// prismpath/tests/test_mission_control_client.py checks each path against the app's OpenAPI document
// and checks WRITE_ROUTES against the capability each route declares there, so the read only posture
// below disables exactly the controls whose routes that posture does not mount. Modules request only
// through this table. Keep each entry on one line (the contract test reads this file as text).

export const API_PREFIX = "/api/v1";

export const PATHS = Object.freeze({
  status: "/status",
  events: "/events",
  flowGraph: "/flow/graph",
  retrievals: "/retrievals",
  files: "/files",
  file: "/file",
  pick: "/pick",
  audit: "/audit",
  queue: "/queue",
  queueDecide: "/queue/decide",
  queueEvent: "/queue/event",
  interactions: "/interactions",
  policyActive: "/policy/active",
  trailCauses: "/trail/causes",
  feedLive: "/feed/live",
  feedCauses: "/feed/causes",
  sprintSelect: "/sprint/select",
  sprintAuto: "/sprint/auto",
  fanouts: "/fanouts",
  sprintStart: "/sprint/start",
  sprintStop: "/sprint/stop",
  sprintPause: "/sprint/pause",
  sprintResume: "/sprint/resume",
  proveLevelM: "/prove/level-m",
  proveReach: "/prove/reach",
  inspectValidate: "/inspect/validate",
  inspectLint: "/inspect/lint",
  inspectContract: "/inspect/contract",
  inspectPortable: "/inspect/portable",
  inspectTest: "/inspect/test",
  inspectGraph: "/inspect/graph",
  authorTemplates: "/author/templates",
  authorScaffold: "/author/scaffold",
  authorStatus: "/author/status",
  qualityLock: "/quality/lock",
  qualityLockCheck: "/quality/lock-check",
  qualityCalibrate: "/quality/calibrate",
  qualityCentroids: "/quality/centroids",
  qualityKappa: "/quality/kappa",
  attestModelCheck: "/attest/model-check",
  attestTrail: "/attest/trail",
  attestLedgerVerify: "/attest/ledger-verify",
  evidenceLogs: "/evidence/logs",
  evidenceTrail: "/evidence/trail",
  evidenceReceipt: "/evidence/receipt",
  evidenceRaw: "/evidence/raw",
  evidenceRun: "/evidence/run",
  evidenceManifest: "/evidence/manifest",
  evidencePack: "/evidence/pack",
  evidenceAnchor: "/evidence/anchor",
  evidenceCauses: "/evidence/causes",
  evidenceFeed: "/evidence/feed",
  policyPackVerify: "/policy/pack-verify",
  policyPackActive: "/policy/pack-active",
  policyFacetDecode: "/policy/facet-decode",
  policyFacetEncode: "/policy/facet-encode",
});

// "METHOD path" for every route above whose capability is `write`.
export const WRITE_ROUTES = Object.freeze([
  "POST /file",
  "POST /author/scaffold",
  "POST /queue/decide",
  "POST /queue/event",
  "POST /sprint/select",
  "POST /sprint/auto",
  "POST /sprint/start",
  "POST /sprint/stop",
  "POST /sprint/pause",
  "POST /sprint/resume",
  "POST /quality/lock",
]);

export const POSTURE_FULL = "full";
export const POSTURE_READ_ONLY = "read-only";

// Whether the console in this posture mounts the route. The read only posture mounts no write route.
export function routeAvailable(posture, method, path) {
  return posture !== POSTURE_READ_ONLY || !WRITE_ROUTES.includes(method + " " + path);
}
