// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// Every render function and request builder of the client, given fixture JSON shaped like the
// console's answers. None of them touches the document, so they run here without a browser.
import { test } from "node:test";
import assert from "node:assert/strict";

import { markupOf } from "../markup.mjs";
import { PATHS, POSTURE_FULL, POSTURE_READ_ONLY, routeAvailable, WRITE_ROUTES } from "../paths.mjs";
import { buildGraphElements, renderGraphError, renderNodeDetail, renderReachVerdicts,
         renderTargetOptions, shortenCondition } from "../graph.mjs";
import { inspectRequest, renderFileList } from "../authoring.mjs";
import { policyRequest, qualityRequest, renderFanouts, renderQueueItems, startRequest,
         statusPills } from "../operating.mjs";
import { proofRequest, renderAuditView } from "../auditing.mjs";
import { formatToolResult, renderPickerOptions } from "../panels.mjs";
import { parseEvent, splitFrames } from "../events.mjs";
import { apiUrl, configureTransport, getJson, postJson, SESSION_HEADER } from "../transport.mjs";

const text = markup => markupOf(markup);

// A /flow/graph answer for the triage flow the Python suite uses.
const GRAPH = {
  name: "triage", start: "intake", active_node: "classify", flow_path: "flows/triage.md", flow_text: "---\n",
  nodes: {
    intake: { instruction: "Collect.", terminal: false, edges: [
      { target: "classify", tier: "deterministic", condition: "when priority > threshold" },
      { target: "triage", tier: "deterministic", condition: "else" }] },
    classify: { instruction: "Assess.", terminal: false, edges: [
      { target: "escalate", tier: "semantic", condition: "needs a human" },
      { target: "intake", tier: "error", condition: "on error" }] },
    triage: { instruction: "Routine.", terminal: false, edges: [] },
    escalate: { instruction: "Wait.", terminal: true, edges: [] },
  },
};

test("buildGraphElements draws every node and every edge with its tier", () => {
  const elements = buildGraphElements(GRAPH);
  const nodes = elements.filter(element => !element.data.source);
  const edges = elements.filter(element => element.data.source);
  assert.deepEqual(nodes.map(node => node.data.id), ["intake", "classify", "triage", "escalate"]);
  assert.equal(nodes[0].classes, "start");
  assert.equal(nodes[3].classes, "terminal");
  assert.equal(edges.length, 4);
  assert.deepEqual(edges.map(edge => edge.classes), ["deterministic", "deterministic", "semantic", "error"]);
  assert.equal(edges[0].data.label, "priority > threshold");
  assert.equal(new Set(elements.map(element => element.data.id)).size, elements.length, "element ids collide");
});

test("shortenCondition drops the leading when and clips a long condition", () => {
  assert.equal(shortenCondition("when a > 1"), "a > 1");
  assert.equal(shortenCondition(undefined), "");
  const long = shortenCondition("when " + "x".repeat(40));
  assert.equal(long.length, 25);
  assert.ok(long.endsWith("…"));
});

test("the target picker lists every node and the verdicts carry a known class only", () => {
  assert.equal(text(renderTargetOptions(GRAPH)), "<option>intake</option><option>classify</option><option>triage</option><option>escalate</option>");
  const verdicts = text(renderReachVerdicts({ escalate: "yes", triage: "may", intake: "no", other: "x\" onclick=\"1" }));
  assert.ok(verdicts.includes('<span class="v-yes">yes</span>'));
  assert.ok(verdicts.includes('<span class="v-may">may</span>'));
  assert.ok(verdicts.includes('<span class="v-no">no</span>'));
  assert.ok(verdicts.includes('<span class="v-unknown">x&quot; onclick=&quot;1</span>'));
  assert.equal(text(renderGraphError("no flow")), '<div class="muted graph-message">no flow</div>');
});

test("the node panel shows the instruction, the edges and the retrievals that name the node", () => {
  const retrievals = [{ query: "classify severity", hits: [{ source: "runbook", path: "sev.md", score: 0.8 }] },
                      { query: "unrelated", hits: [{ source: "other", path: "x.md", score: 0.1 }] }];
  const panel = text(renderNodeDetail("classify", GRAPH.nodes.classify, retrievals));
  assert.ok(panel.includes('<div class="nd-title">classify</div>'));
  assert.ok(panel.includes("Assess."));
  assert.ok(panel.includes("→ escalate"));
  assert.ok(panel.includes("[0.80] runbook/sev.md"));
  assert.ok(!panel.includes("other/x.md"));
  assert.ok(text(renderNodeDetail("triage", GRAPH.nodes.triage, retrievals)).includes("no matched retrievals"));
});

test("the file list marks the open file and carries each path in its row", () => {
  const rows = text(renderFileList([{ path: "flows/triage.md", size: 210, kind: "flow" }, { path: "notes.json", size: 4, kind: "other" }], "notes.json"));
  assert.equal(rows, '<div class="f kind-flow" data-p="flows/triage.md" data-kind="flow"><span>flows/triage.md</span><span class="sz"><span class="kind flow">flow</span> 210</span></div>'
    + '<div class="f sel kind-other" data-p="notes.json" data-kind="other"><span>notes.json</span><span class="sz"><span class="kind other">read only</span> 4</span></div>');
  // a kind the client does not know is shown as other, never as a class of its own
  assert.ok(text(renderFileList([{ path: "x", size: 1, kind: "x\" onclick=\"1" }])).includes('data-kind="other"'));
  assert.equal(text(renderFileList(undefined)), "");
});

test("the audit view says the verdict is the console's and lists the newest event first", () => {
  const payload = { root: "ab".repeat(32), n: 2, verify: true, events: [
    { actor: "operator", action: "sprint.stop", ts: 1, data: { a: 1 } },
    { actor: "operator", action: "file.edit", ts: 2, data: { path: "flows/triage.md" } }] };
  const view = renderAuditView(payload, event => "t" + event.ts);
  assert.deepEqual(view.chip, { text: "console: verified ✓", cls: "chip ok" });
  assert.equal(view.meta, "root " + "ab".repeat(10) + " · 2 events");
  const rows = text(view.events);
  assert.ok(rows.indexOf("file.edit") < rows.indexOf("sprint.stop"));
  assert.ok(rows.includes("t2"));
  assert.equal(renderAuditView({ verify: false }).chip.cls, "chip bad");
});

test("the queue offers a decision in the full posture and says why not in the read only one", () => {
  const items = [{ id: "run-1", node: "escalate", reason: "needs_human" }, { path: "/q/run-2.json" }];
  const full = text(renderQueueItems(items, true));
  assert.ok(full.includes('data-decide="run-1"') && full.includes('data-id="/q/run-2.json"'));
  const readOnly = text(renderQueueItems(items, false));
  assert.ok(!readOnly.includes("data-decide") && readOnly.includes("unavailable in the read-only posture"));
  assert.ok(text(renderQueueItems([], true)).includes("nothing awaiting a decision"));
});

test("fan-outs render as a tree or say there are none", () => {
  assert.ok(text(renderFanouts([{ id: "f", children: [{ item_id: "c", stopped: "terminal" }] }])).startsWith('<div class="tree">'));
  assert.ok(text(renderFanouts([])).includes("no fan-out compositions"));
});

test("the status pills read a /status answer", () => {
  const pills = statusPills({ running: true, iteration: 3, valid: false, unbuffered: true, audit_n: 5, dir: "/p" });
  assert.deepEqual(pills.run, { text: "running", cls: "pill run" });
  assert.deepEqual(pills.gate, { text: "gate ✗", cls: "pill bad" });
  assert.equal(pills.iteration.text, "it 3");
  assert.equal(pills.buffer.text, "unbuffered");
  assert.equal(pills.audit.text, "audit 5");
  assert.equal(pills.project.text, "/p");
  assert.equal(statusPills({ paused: true }).run.text, "paused");
  assert.equal(statusPills({}).gate.text, "");
});

test("the start form becomes the sprint start request", () => {
  const field = value => ({ value });
  const box = checked => ({ checked });
  const request = startRequest({ proj: field(" "), gate: field("browser"), nudge_file: field(""), model: field("m"),
                                 rag: box(true), lessons: box(false), fresh: box(false), unbuffered: box(true) });
  assert.deepEqual(request, { proj: undefined, gate: "browser", nudge_file: undefined, model: "m",
                              rag: true, lessons: false, fresh: false, unbuffered: true });
});

test("every panel button sends to a path the client knows", () => {
  const known = new Set(Object.values(PATHS));
  const inputs = { flow: "f.md", labels: "l.jsonl", bench: "b.jsonl", a: "a", b: "b", pack: "p.ppt", pub: "k1 k2",
                   state: "s", hex: "00", json: "{}", trail: "", leaf: "", root: "" };
  const requests = [
    ...["validate", "lint", "contract", "portable", "test", "graph"].map(action => {
      const request = inspectRequest(action, "f.md");
      return [request.path, request.body];
    }),
    ...["lock", "lock-check", "calibrate", "centroids", "kappa"].map(action => qualityRequest(action, inputs)),
    ...["pack-verify", "pack-active", "facet-decode", "facet-encode"].map(action => policyRequest(action, inputs)),
    ...["model-check", "trail", "ledger-verify"].map(action => proofRequest(action, inputs)),
  ];
  for (const [path] of requests) {
    assert.ok(known.has(path), path);
  }
  assert.deepEqual(inspectRequest("graph", "f.md").body, { flow_md: "f.md", direction: "TD" });
  assert.deepEqual(qualityRequest("lock-check", inputs), [PATHS.qualityLockCheck, { flow_md: "f.md" }]);
  assert.deepEqual(policyRequest("pack-active", inputs), [PATHS.policyPackActive, { state_dir: "s" }]);
  assert.deepEqual(policyRequest("pack-verify", inputs)[1].pub, ["k1", "k2"]);
  assert.deepEqual(proofRequest("trail", inputs)[1], { source: undefined });
  assert.equal(qualityRequest("nothing", inputs), null);
});

test("a tool panel prints the answer or the error message", () => {
  assert.equal(formatToolResult({ ok: true }), '{\n  "ok": true\n}');
  assert.equal(formatToolResult({ error: { code: 400, message: "bad" } }), "error: bad");
  assert.equal(text(renderPickerOptions(["a.md", "b.jsonl"], path => path.endsWith(".md"))), '<option value="a.md"></option>');
});

test("the read only posture leaves out exactly the write routes", () => {
  for (const route of WRITE_ROUTES) {
    const [method, path] = route.split(" ");
    assert.equal(routeAvailable(POSTURE_READ_ONLY, method, path), false, route);
    assert.equal(routeAvailable(POSTURE_FULL, method, path), true, route);
  }
  assert.equal(routeAvailable(POSTURE_READ_ONLY, "GET", PATHS.file), true);
  assert.equal(routeAvailable(POSTURE_READ_ONLY, "POST", PATHS.proveReach), true);
  assert.equal(routeAvailable(POSTURE_READ_ONLY, "POST", PATHS.qualityLockCheck), true);
  assert.equal(routeAvailable(POSTURE_READ_ONLY, "POST", PATHS.policyPackActive), true);
});

test("the event stream splits into frames and keeps an unfinished tail", () => {
  const { messages, rest } = splitFrames('data: {"type":"status"}\r\n\r\n: ping\n\ndata: {"a":\ndata: 1}\n\ndata: {"type"');
  assert.deepEqual(messages, ['{"type":"status"}', '{"a":\n1}']);
  assert.equal(rest, 'data: {"type"');
  assert.deepEqual(parseEvent(messages[0]), { type: "status" });
  assert.equal(parseEvent("not json"), null);
  assert.equal(parseEvent("3"), null);
});

test("every request carries the session token and a body that is not JSON comes back as an error", async () => {
  const seen = [];
  configureTransport({
    token: "tok",
    fetch: async (url, init) => {
      seen.push({ url, init });
      return url.includes("broken")
        ? { status: 502, json: async () => { throw new SyntaxError("no"); } }
        : { status: 200, json: async () => ({ ok: true }) };
    },
  });
  assert.deepEqual(await getJson(PATHS.file, { path: "a b&c.md" }), { ok: true });
  assert.deepEqual(await postJson(PATHS.proveReach, { reach: ["x"] }), { ok: true });
  assert.equal((await getJson("/broken")).error.code, 502);
  assert.equal(seen[0].url, "/api/v1/file?path=a+b%26c.md");
  assert.equal(seen[0].init.headers[SESSION_HEADER], "tok");
  assert.equal(seen[1].init.method, "POST");
  assert.equal(seen[1].init.headers["Content-Type"], "application/json");
  assert.equal(seen[1].init.headers[SESSION_HEADER], "tok");
  assert.equal(seen[1].init.body, '{"reach":["x"]}');
  assert.equal(apiUrl(PATHS.status), "/api/v1/status");
});
