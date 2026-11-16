// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The auditing interface's render functions, request builders and pinned key store, given fixture JSON
// shaped like the /evidence routes' answers. Every verdict a render shows names whose it is, every
// server string is escaped, and a key the assessor pins stays in the page: no request the interface
// builds carries it, which the transport mock below checks for every route.
import { test } from "node:test";
import assert from "node:assert/strict";

import { markupOf } from "../markup.mjs";
import { PATHS, POSTURE_READ_ONLY, routeAvailable } from "../paths.mjs";
import { addPinnedKey, anchorRequest, bundleDownload, decodeCause, keyFromFile, manifestRequest, packRequest,
         parsePinFiles, pinnedKeys, PIN_STORE_KEY, rawRequest, receiptRequest, removePinnedKey, renderAnchorReport,
         renderCauseTable, renderConsoleActions, renderLogList, renderManifestStatus, renderPackReport,
         renderPinnedKeys, renderRawLines, renderReceiptView, renderRefusal, renderRunReport, renderTrailReport,
         runRequest, trailRequest, verdictChip } from "../auditing.mjs";
import { configureTransport, getJson, postJson } from "../transport.mjs";

const text = markup => markupOf(markup);
const HOSTILE = "<img src=x onerror=alert(1)>\"'";

const TRAIL = {
  events: 3, decisions: 3, by_action: { decision: 3 }, outcomes: { refuse: 1, route: 1, escalate: 1 },
  log: { path: "/ev/run.audit.jsonl", total_events: 3, merkle_root: "ab".repeat(32), verifies: true },
  signing: { status: "signed-unpinned", statements: 3, keys: ["b4905f8d6c3d470c"], pinned: false, findings: [] },
  verdict_of: "console", sha256: "cd".repeat(32), size: 303, skipped: [],
  causes_decoded: [{ code: 0, label: "0 clean", clean: true, registered: false, class: null, description: "the clean decision" },
                   { code: 2, name: "sig:invalid", label: "2 sig:invalid", class: "authority", registered: true, clean: false,
                     description: "signature fails verification" }],
  causes: { "2 sig:invalid": 1, "0 clean": 2 },
  command: "prismpath trail /ev/run.audit.jsonl", console_actions: null,
};

const RECEIPT = {
  log: "/ev/run.audit.jsonl", index: 0, event: { action: "decision", actor: "engine", idx: 0, data: { cause: 2 } },
  raw: { b64: "e30=", text: "{}" }, cause: TRAIL.causes_decoded[1], leaf: "11".repeat(32), path_steps: 2,
  path: ["22".repeat(32), "33".repeat(32)], root: "44".repeat(32), tree_leaves: 3,
  statement: { seq: 2, leaves: 3, root: "44".repeat(32), key_id: "b4905f8d6c3d470c" + "0".repeat(48), policy: { flow: "f", flow_sha256: "55".repeat(32) } },
  bundle: { receipt: { idx: 0 }, index: 0, leaf: "11".repeat(32), path: [], statement: { seq: 2 } },
  uncovered: null, verdict: { ok: true, status: "signed-unpinned", verdict_of: "console", checks: { leaf: true, signature: true } },
  export: "prismpath trail /ev/run.audit.jsonl --receipt 0 --bundle-out bundle.json",
  command: "prismpath trail --verify-bundle bundle.json --pub <instance.pub>",
};

test("every verdict chip names whose verdict it is", () => {
  assert.deepEqual(verdictChip("signed"), { text: "console: signed", cls: "chip ok" });
  assert.deepEqual(verdictChip("signed-unpinned"), { text: "console: signed-unpinned", cls: "chip warn" });
  assert.deepEqual(verdictChip("invalid"), { text: "console: invalid", cls: "chip bad" });
  assert.deepEqual(verdictChip("unsigned"), { text: "console: unsigned", cls: "chip warn" });
  assert.equal(verdictChip(undefined).text, "console: no verdict");
  assert.equal(verdictChip("signed", "page").text, "page: signed");
});

test("the log list shows every trail with its statements, every run and the console's own log", () => {
  const listing = text(renderLogList({
    roots: ["/ev"], truncated: true,
    logs: [{ path: "/ev/run.audit.jsonl", rel: "run.audit.jsonl", size: 303, statements: "/ev/run.audit.roots.jsonl" },
           { path: "/ev/" + HOSTILE, rel: HOSTILE, size: 1, statements: null }],
    runs: [{ path: "/ev/runs/one", rel: "runs/one", complete: true }],
    console: { path: "/state/mission_audit.log", events: 4, verifies: true },
  }));
  assert.ok(listing.includes('data-trail="/ev/run.audit.jsonl"'));
  assert.ok(listing.includes("statements"));
  assert.ok(listing.includes('data-run="/ev/runs/one"'));
  assert.ok(listing.includes('data-console="1"'));
  assert.ok(listing.includes("truncated"));
  assert.ok(!listing.includes("<img"), "a file name is markup");
  assert.ok(listing.includes("&lt;img"));
  assert.ok(text(renderLogList({ roots: [], logs: [], runs: [] })).includes("MC_EVIDENCE"));
  const fresh = text(renderLogList({ roots: [], logs: [], runs: [], console: { path: "/state/mission_audit.log", present: false, events: 0 } }));
  assert.ok(!fresh.includes("data-console"), "a console log not written yet offers nothing to read");
});

test("a trail report shows the chain status as the console's, the root, the causes and the command", () => {
  const report = text(renderTrailReport(TRAIL));
  assert.ok(report.includes("console: signed-unpinned"));
  assert.ok(report.includes("console: Merkle root verifies"));
  assert.ok(report.includes("2 sig:invalid") && report.includes("authority"));
  assert.ok(report.includes("prismpath trail /ev/run.audit.jsonl"));
  assert.ok(report.includes("not pinned"));
  const tampered = text(renderTrailReport({ ...TRAIL, log: { ...TRAIL.log, verifies: false },
    signing: { status: "invalid", findings: [{ seq: 1, cause: HOSTILE }] }, skipped: [{ line: 2, why: "bad_format" }] }));
  assert.ok(tampered.includes("console: invalid") && tampered.includes("console: Merkle root does not verify"));
  assert.ok(tampered.includes("line 2") && tampered.includes("bad_format"));
  assert.ok(!tampered.includes("<img"));
});

test("the console's own actions are counted in pairs and an intent with no result is named", () => {
  const actions = text(renderConsoleActions({
    by_action: { "sprint.stop": { intents: 2, done: 1, failed: 0, unrecorded: 1 } }, refusals: { "sprint.refused": 1 },
    unrecorded: [{ index: 4, action: "sprint.stop" }], orphans: [{ index: 6, action: "queue.decide.result", why: "names no intent" }],
  }));
  assert.ok(actions.includes("sprint.stop") && actions.includes("outcome not recorded"));
  assert.ok(actions.includes("#4") && actions.includes("#6") && actions.includes("names no intent"));
  assert.ok(actions.includes("sprint.refused"));
  assert.equal(text(renderConsoleActions(null)), "");
});

test("a receipt shows its fields, cause, leaf, inclusion path, statement and both commands", () => {
  const view = text(renderReceiptView(RECEIPT));
  assert.ok(view.includes("console: signed-unpinned"));
  assert.ok(view.includes("2 sig:invalid"));
  assert.ok(view.includes("11".repeat(32)) && view.includes("33".repeat(32)) && view.includes("44".repeat(32)));
  assert.ok(view.includes("2 steps"));
  assert.ok(view.includes("--receipt 0 --bundle-out bundle.json"));
  assert.ok(view.includes("prismpath trail --verify-bundle bundle.json"));
  assert.ok(view.includes("55".repeat(32)), "the flow hash the covering statement names");
  const uncovered = text(renderReceiptView({ ...RECEIPT, bundle: null, statement: null, verdict: null, uncovered: "no root statement covers it" }));
  assert.ok(uncovered.includes("no root statement covers it") && uncovered.includes("console: no bundle"));
});

test("the bundle download is the bundle as the command line writes it", () => {
  const file = bundleDownload(RECEIPT);
  assert.equal(file.name, "bundle.json");
  assert.deepEqual(JSON.parse(file.text), RECEIPT.bundle);
  assert.ok(file.text.endsWith("\n"));
  assert.equal(bundleDownload({ ...RECEIPT, bundle: null }), null);
});

test("raw lines show each line's number and text escaped", () => {
  const raw = text(renderRawLines({ path: "/ev/x", start: 3, count: 2, total: 9, size: 10, sha256: "aa".repeat(32),
    lines: [{ b64: "", text: HOSTILE }, { b64: "e30=", text: "{}" }] }));
  assert.ok(raw.includes("3 ") && raw.includes("4 ") && raw.includes("of 9"));
  assert.ok(!raw.includes("<img") && raw.includes("&lt;img"));
  assert.ok(raw.includes("aa".repeat(32)));
});

test("a run report says whose verdict it is and prints the command of record", () => {
  const ok = text(renderRunReport({ ok: true, status: "signed", verdict_of: "console", receipts: 12, replayed: 3,
    sample_cap: 200, command: "prismpath evidence verify /ev/run --sample all --pin-authority a --pin-instance i" }));
  assert.ok(ok.includes("console: signed") && ok.includes("prismpath evidence verify"));
  const bad = text(renderRunReport({ ok: false, status: "invalid", verdict_of: "console", problem: HOSTILE, command: "c" }));
  assert.ok(bad.includes("console: invalid") && !bad.includes("<img"));
});

test("change control and pack verify name their status, their causes and the command", () => {
  const manifest = text(renderManifestStatus({ status: "stale", flow_sha256: "aa".repeat(32), manifest_flow_sha256: "bb".repeat(32),
    causes: [{ label: "flow:sha256-mismatch", class: "authority" }], key: "b4905f8d6c3d470c", version: 1,
    verdict_of: "console", command: "prismpath authorize verify /ev/f.md --pub /ev/a.pub",
    receipt: { index: 0, flow_sha256: "aa".repeat(32), agrees: true } }));
  assert.ok(manifest.includes("console: stale") && manifest.includes("flow:sha256-mismatch"));
  assert.ok(manifest.includes("prismpath authorize verify") && manifest.includes("the receipt names the text of this flow"));
  const pack = text(renderPackReport({ status: "invalid", causes: [{ label: "image:sha256-mismatch" }], verdict_of: "console",
    command: "prismpath swap verify --ppt /ev/v1.ppt --pub /ev/a.pub" }));
  assert.ok(pack.includes("console: invalid") && pack.includes("image:sha256-mismatch") && pack.includes("swap verify"));
  const anchor = text(renderAnchorReport({ mode: "ots", merkle_ok: false, reason: "output-hash not in this anchor batch",
    verdict_of: "console", command: "prismpath ledger verify --out /ev/proofs --leaf 11" }));
  assert.ok(anchor.includes("console: Merkle path does not reach the anchored root") && anchor.includes("ledger verify"));
});

test("the cause decoder reads only the registry the console serves", () => {
  const registry = { sha256: "ff", causes: [{ code: 2, name: "sig:invalid", class: "authority", label: "2 sig:invalid", registered: true },
                                            { code: 34, name: "route:human", class: "routing", label: "34 route:human", registered: true }] };
  assert.equal(decodeCause(registry, "2").name, "sig:invalid");
  assert.equal(decodeCause(registry, "0x22").name, "route:human");
  assert.equal(decodeCause(registry, "route:human").code, 34);
  assert.equal(decodeCause(registry, "0").label, "0 clean");
  assert.equal(decodeCause(registry, HOSTILE).label, "unregistered");
  assert.equal(decodeCause(registry, "999").label, "999 unregistered");
  const table = text(renderCauseTable(registry, "sig"));
  assert.ok(table.includes("sig:invalid") && !table.includes("route:human"));
  assert.ok(text(renderCauseTable(registry, "")).includes("route:human"));
});

test("a refusal shows its status and reason", () => {
  const refusal = text(renderRefusal({ error: { code: 403, reason: "outside-roots", message: HOSTILE } }));
  assert.ok(refusal.includes("403") && refusal.includes("outside-roots") && !refusal.includes("<img"));
});

test("the request builders name key files, never keys, and leave empty inputs out", () => {
  assert.deepEqual(parsePinFiles(" a.pub  b.pub,c.pub "), ["a.pub", "b.pub", "c.pub"]);
  assert.deepEqual(trailRequest({ path: "/ev/x", pins: "" }), [PATHS.evidenceTrail, { path: "/ev/x" }]);
  assert.deepEqual(trailRequest({ console: true, since: "2026-11-01", last: "5", pins: "k.pub" }),
                   [PATHS.evidenceTrail, { console: true, since: "2026-11-01", last: 5, pins: ["k.pub"] }]);
  assert.deepEqual(receiptRequest({ path: "/ev/x", index: "2" }), [PATHS.evidenceReceipt, { path: "/ev/x", index: 2 }]);
  assert.deepEqual(rawRequest({ console: true, start: "", count: "" }), [PATHS.evidenceRaw, { console: true, start: 0, count: 100 }]);
  assert.deepEqual(runRequest({ path: "/ev/run", authority: "a.pub", instance: "", sample: "3" }),
                   [PATHS.evidenceRun, { path: "/ev/run", pins: { authority: "a.pub" }, sample: 3 }]);
  assert.deepEqual(manifestRequest({ flow: "f.md", pins: "a.pub", log: "/ev/x", index: "0" }),
                   [PATHS.evidenceManifest, { flow: "f.md", pins: ["a.pub"], log: "/ev/x", index: 0 }]);
  assert.deepEqual(packRequest({ ppt: "v1.ppt", pins: "a.pub" }), [PATHS.evidencePack, { ppt: "v1.ppt", pins: ["a.pub"] }]);
  assert.deepEqual(anchorRequest({ leaf: "11", dir: "proofs", label: "" }), [PATHS.evidenceAnchor, { leaf: "11", dir: "proofs" }]);
  assert.deepEqual(anchorRequest({ root: "r", tsr: "t", cafile: "c" }), [PATHS.evidenceAnchor, { root: "r", tsr: "t", cafile: "c" }]);
});

test("every auditing route is available in the read only posture", () => {
  for (const path of [PATHS.evidenceLogs, PATHS.evidenceCauses]) {
    assert.ok(routeAvailable(POSTURE_READ_ONLY, "GET", path), path);
  }
  for (const path of [PATHS.evidenceTrail, PATHS.evidenceReceipt, PATHS.evidenceRaw, PATHS.evidenceRun,
                      PATHS.evidenceManifest, PATHS.evidencePack, PATHS.evidenceAnchor]) {
    assert.ok(routeAvailable(POSTURE_READ_ONLY, "POST", path), path);
  }
});

function memoryStorage() {
  const held = new Map();
  return { getItem: key => (held.has(key) ? held.get(key) : null), setItem: (key, value) => held.set(key, String(value)),
           removeItem: key => held.delete(key), held };
}

// A key shaped value made at run time, so no key like literal sits in the source.
const KEY_HEX = Array.from({ length: 32 }, (_, at) => ((at * 37 + 11) & 255).toString(16).padStart(2, "0")).join("");

test("a pinned key is read from a raw 32 byte file or its hex, and anything else is refused", () => {
  const raw = Uint8Array.from(KEY_HEX.match(/../g).map(pair => parseInt(pair, 16)));
  assert.equal(keyFromFile(raw), KEY_HEX);
  assert.equal(keyFromFile(new TextEncoder().encode(KEY_HEX.toUpperCase() + "\n")), KEY_HEX);
  assert.throws(() => keyFromFile(new Uint8Array(31)), /32 byte/);
  assert.throws(() => keyFromFile(new TextEncoder().encode("zz".repeat(32))), /32 byte/);
});

test("pinned keys live in session storage, are listed by key id and can be removed", async () => {
  const storage = memoryStorage();
  assert.deepEqual(pinnedKeys(storage), []);
  const added = await addPinnedKey(storage, { label: HOSTILE, hex: KEY_HEX });
  assert.equal(added.keyId.length, 64);
  await addPinnedKey(storage, { label: "again", hex: KEY_HEX });          // the same key once
  assert.equal(pinnedKeys(storage).length, 1);
  assert.ok(storage.held.has(PIN_STORE_KEY));
  const listing = text(renderPinnedKeys(pinnedKeys(storage)));
  assert.ok(listing.includes(added.keyId.slice(0, 16)) && !listing.includes("<img"));
  assert.ok(listing.includes("kept in this browser tab"));
  removePinnedKey(storage, added.keyId);
  assert.deepEqual(pinnedKeys(storage), []);
  storage.setItem(PIN_STORE_KEY, "not json");
  assert.deepEqual(pinnedKeys(storage), [], "a store that does not read is empty, not a crash");
});

test("no request the auditing interface sends carries a pinned key", async () => {
  const storage = memoryStorage();
  await addPinnedKey(storage, { label: "instance", hex: KEY_HEX });
  const sent = [];
  configureTransport({ token: "t", fetch: async (url, init = {}) => {
    sent.push(String(url) + " " + (init.body || "") + " " + JSON.stringify(init.headers || {}));
    return { status: 200, json: async () => ({}) };
  } });
  const inputs = { path: "/ev/x", console: false, index: "0", pins: "pins/instance.pub", authority: "pins/a.pub",
                   instance: "pins/i.pub", flow: "f.md", log: "/ev/x", ppt: "v1.ppt", leaf: "11", dir: "proofs",
                   start: "0", count: "5", sample: "2" };
  for (const build of [trailRequest, receiptRequest, rawRequest, runRequest, manifestRequest, packRequest, anchorRequest]) {
    const [path, body] = build(inputs);
    await postJson(path, body);
  }
  await getJson(PATHS.evidenceLogs);
  await getJson(PATHS.evidenceCauses);
  assert.equal(sent.length, 9);
  for (const request of sent) {
    assert.ok(!request.toLowerCase().includes(KEY_HEX), request);
    assert.ok(!request.includes(Buffer.from(KEY_HEX, "hex").toString("base64")), request);
  }
});
