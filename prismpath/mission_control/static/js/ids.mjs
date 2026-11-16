// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// Every element id the modules address, in one place. index.html declares each of them, and
// prismpath/tests/test_mission_control_client.py checks that it does, so a renamed element fails a
// test instead of a screen. Modules address elements only through this table, never by a literal.
// Keep each entry on one line as `name: "id",` (the contract test reads this file as text).

export const IDS = Object.freeze({
  // top bar
  connPill: "p-conn",
  runPill: "p-run",
  iterPill: "p-iter",
  gatePill: "p-valid",
  bufferPill: "p-buf",
  auditPill: "p-audit",
  posturePill: "p-posture",
  // the interface tabs and the screen tabs under them
  interfaceTabs: "interfaces",
  screenTabs: "screens",
  // the screens
  viewGraph: "v-graph",
  viewFiles: "v-files",
  viewInspect: "v-inspect",
  viewRuns: "v-runs",
  viewQueue: "v-queue",
  viewPolicy: "v-policy",
  viewQuality: "v-quality",
  viewFlows: "v-flows",
  viewAudit: "v-audit",
  viewProof: "v-proof",
  // runs (the sprint loop controls)
  runControls: "run-controls",
  runsUnavailable: "runs-unavailable",
  startToggle: "c-start-toggle",
  startForm: "startform",
  project: "c-proj",
  // graph and its two proofs
  graphName: "g-name",
  graphRefresh: "g-refresh",
  proveLevelM: "g-levelm",
  levelMChip: "g-levelm-chip",
  graphCanvas: "cy",
  reachTargets: "r-targets",
  reachAssume: "r-assume",
  reachGo: "r-go",
  reachVerdicts: "r-verdicts",
  nodeEmpty: "nd-empty",
  nodeBody: "nd-body",
  // files and the editor
  fileList: "filelist",
  editorPath: "ed-path",
  editorSave: "ed-save",
  editorBody: "ed-body",
  editorNote: "ed-note",
  // audit
  auditVerify: "a-verify",
  auditMeta: "a-meta",
  auditEvents: "a-events",
  // queue and fan-outs
  queueItems: "q-items",
  fanoutTree: "f-tree",
  // inspect
  inspectFlow: "ins-flow",
  inspectOut: "ins-out",
  // quality
  qualityFlow: "q-flow",
  qualityLabels: "q-labels",
  qualityBench: "q-bench",
  qualityA: "q-a",
  qualityB: "q-b",
  qualityOut: "q-out",
  // proof
  proofFlow: "pf-flow",
  proofTrail: "pf-trail",
  proofLeaf: "pf-leaf",
  proofRoot: "pf-root",
  proofOut: "pf-out",
  // policy
  policyPack: "pol-ppt",
  policyPub: "pol-pub",
  policyState: "pol-state",
  policyFlow: "pol-flow",
  policyHex: "pol-hex",
  policyJson: "pol-json",
  policyOut: "pol-out",
  // the file pickers the panels' inputs offer
  pickFlows: "dl-flows",
  pickJsonl: "dl-jsonl",
  pickPacks: "dl-ppt",
  pickFiles: "dl-files",
  toast: "toast",
});
