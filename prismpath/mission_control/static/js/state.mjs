// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// Console state. One object instead of loose globals, so every screen reads the same console from
// one place. The posture is the server's: main.mjs reads it from the page's meta tag at start.
import { POSTURE_READ_ONLY, routeAvailable } from "./paths.mjs";

export const state = {
  posture: POSTURE_READ_ONLY,
  interface: "authoring",
  screen: "graph",
  cytoscapeView: null,   // the rendering library's model, not the flow graph itself
  graph: null,           // the latest /flow/graph payload: nodes, start, active_node, flow_text
  retrievals: [],
  openFilePath: null,
  openFileKind: null,    // the open file's kind from /files: flow, fixture or other
  templates: [],         // the scaffold's templates from /author/templates
};

export function available(method, path) {
  return routeAvailable(state.posture, method, path);
}

// The followed flow, which the panels' flow inputs start from.
export function activeFlow() {
  return (state.graph && state.graph.flow_path) || "";
}
