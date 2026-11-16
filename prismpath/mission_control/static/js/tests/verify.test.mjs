// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The page's own verifier (U3). verifyReceiptBundle is held to every bundle case of receipts.json, which
// the Python reference wrote, verdict for verdict. pageVerdict checks the receipt the console showed from
// the bytes it returned, with the key the assessor pinned in the page: a good receipt is signed, a
// tampered one, one under a key that is not pinned and one whose statement was edited are invalid, a page
// with no pinned key says so, and a browser without Ed25519 says it cannot check the signature. The
// statement's own key is never the one a signature is checked under, and nothing is sent.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { canon2Write } from "../../../../portable/canon2.mjs";
import { toHex } from "../../../../portable/merkle.mjs";
import { JsonFloat, pageVerdict, readJson, verifyReceiptBundle } from "../verify.mjs";
import { pageVerdictChip, renderReceiptView } from "../auditing.mjs";
import { markupOf } from "../markup.mjs";
import { configureTransport } from "../transport.mjs";

const RECEIPTS = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "portable", "conformance", "receipts.json");
const vectors = readJson(readFileSync(RECEIPTS, "utf-8"));
const bundleCases = vectors.cases.filter(entry => entry.kind === "bundle");
const unhex = hex => Uint8Array.from(hex.match(/../g) || [], pair => parseInt(pair, 16));
const clone = value => readJson(JSON.stringify(value));
const keyId = async hex => toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", unhex(hex))));
const b64 = bytes => btoa(String.fromCharCode(...bytes));
const text = markup => markupOf(markup);

// Python's verdict as the corpus writes it, from the JavaScript one.
function asWritten(verdict) {
  return JSON.parse(JSON.stringify(verdict, (key, value) => (value instanceof JsonFloat ? value.value : value)));
}

test("the lossless reader keeps a float spelling apart from an integer", () => {
  const read = readJson('{"a": 4.0, "b": 4, "c": 1e-07, "d": [2.5], "e": 9007199254740993}');
  assert.ok(read.a instanceof JsonFloat && read.a.value === 4);
  assert.equal(read.b, 4);
  assert.ok(read.c instanceof JsonFloat);
  assert.ok(read.d[0] instanceof JsonFloat);
  assert.equal(read.e, 9007199254740993n);
});

test("verifyReceiptBundle gives the Python reference's verdict on every bundle case of receipts.json", async () => {
  assert.equal(bundleCases.length, 70);
  const wrong = [];
  for (const entry of bundleCases) {
    const pinned = (entry.pinned || []).map(unhex);
    let got;
    try {
      got = asWritten(await verifyReceiptBundle(entry.bundle, pinned));
    } catch {
      got = { error: true };
    }
    try {
      assert.deepEqual(got, entry.expect);
    } catch {
      wrong.push(`${entry.name}\n  want ${JSON.stringify(entry.expect)}\n  got  ${JSON.stringify(got)}`);
    }
  }
  assert.deepEqual(wrong, []);
  assert.equal(bundleCases.filter(entry => entry.expect.status === "signed").length, 11);
  assert.equal(bundleCases.filter(entry => entry.expect.error).length, 4, "the four key id cases the reference raises on");
});

// ------------------------------------------------------------------ the page's verdict on a shown receipt
const VALID = bundleCases.find(entry => entry.name === "valid_pinned");
const INSTANCE = { hex: vectors.instance_pub_hex, keyId: vectors.instance_key_id, label: "instance" };
const AUTHORITY = { hex: vectors.authority_pub_hex, keyId: vectors.authority_key_id, label: "authority" };

// A receipt view shaped as /evidence/receipt answers it, from the corpus' valid bundle: the line's bytes
// are the canon/2 bytes of the receipt, as the audit log writes them.
function shownView(edit = view => view) {
  const bundle = clone(VALID.bundle);
  const line = canon2Write(bundle.receipt);
  return edit({
    log: "/ev/run.audit.jsonl", index: bundle.index, event: clone(bundle.receipt),
    raw: { b64: b64(line), text: new TextDecoder().decode(line) }, leaf: bundle.leaf, path: bundle.path,
    path_steps: bundle.path.length, root: bundle.statement.root, tree_leaves: bundle.statement.leaves,
    statement: clone(bundle.statement), bundle, uncovered: null,
    verdict: { ok: true, status: "signed", verdict_of: "console", checks: {} },
    export: "prismpath trail /ev/run.audit.jsonl --receipt 4 --bundle-out bundle.json",
    command: "prismpath trail --verify-bundle bundle.json --pub instance.pub",
  });
}

function editedLine(view, from, to) {
  const line = view.raw.text.replace(from, to);
  assert.notEqual(line, view.raw.text);
  view.raw = { b64: b64(new TextEncoder().encode(line)), text: line };
  return view;
}

test("the corpus keys hash to the ids the corpus names", async () => {
  assert.equal(await keyId(INSTANCE.hex), INSTANCE.keyId);
  assert.equal(await keyId(AUTHORITY.hex), AUTHORITY.keyId);
});

test("a good receipt under the pinned instance key is page: signed", async () => {
  const verdict = await pageVerdict(shownView(), [INSTANCE]);
  assert.equal(verdict.status, "signed", JSON.stringify(verdict));
  assert.equal(verdict.reason, null);
  assert.equal(verdict.key, INSTANCE.keyId.slice(0, 16));
  assert.ok(Object.values(verdict.checks).every(Boolean), JSON.stringify(verdict.checks));
  assert.deepEqual(pageVerdictChip(verdict), { text: "page: signed", cls: "chip ok" });
});

test("a receipt whose bytes were edited is page: invalid, whatever the console says", async () => {
  const view = editedLine(shownView(), '"seq":4', '"seq":5');
  assert.equal(view.verdict.status, "signed", "the console still claims signed");
  const verdict = await pageVerdict(view, [INSTANCE]);
  assert.equal(verdict.status, "invalid");
  assert.match(verdict.reason, /receipt shown|leaf/);
  assert.equal(pageVerdictChip(verdict).cls, "chip bad");
  assert.match(pageVerdictChip(verdict).text, /^page: invalid \(.+\)$/);
});

test("bytes edited and the shown event edited to match still fail on the leaf", async () => {
  const view = editedLine(shownView(), '"seq":4', '"seq":5');
  view.event.data.seq = 5;
  const verdict = await pageVerdict(view, [INSTANCE]);
  assert.equal(verdict.status, "invalid");
  assert.equal(verdict.checks.leaf, false);
  assert.match(verdict.reason, /leaf/);
});

test("bytes that are not canon/2 are refused before anything is hashed", async () => {
  const view = editedLine(shownView(), '{"action"', '{ "action"');
  const verdict = await pageVerdict(view, [INSTANCE]);
  assert.equal(verdict.status, "invalid");
  assert.match(verdict.reason, /canon\/2/);
});

test("the shown event that is not the line's receipt is invalid even when the line verifies", async () => {
  const view = shownView(shown => ({ ...shown, event: { ...shown.event, actor: "someone else" } }));
  const verdict = await pageVerdict(view, [INSTANCE]);
  assert.equal(verdict.status, "invalid");
  assert.match(verdict.reason, /shown/);
});

test("a statement whose root or signature was edited is invalid", async () => {
  const rooted = shownView(view => { view.bundle.statement.root = "00".repeat(32); return view; });
  assert.equal((await pageVerdict(rooted, [INSTANCE])).status, "invalid");
  const unsigned = shownView(view => { view.bundle.statement.sig = "00".repeat(64); return view; });
  const verdict = await pageVerdict(unsigned, [INSTANCE]);
  assert.equal(verdict.status, "invalid");
  assert.equal(verdict.checks.signature, false);
  assert.match(verdict.reason, /signature/);
  const pathed = shownView(view => { view.bundle.path = [["R", view.bundle.path[0][1]]]; return view; });
  assert.equal((await pageVerdict(pathed, [INSTANCE])).checks.inclusion, false);
});

test("a receipt under a key the assessor did not pin is invalid", async () => {
  const verdict = await pageVerdict(shownView(), [AUTHORITY]);
  assert.equal(verdict.status, "invalid");
  assert.equal(verdict.checks.pinned, false);
  assert.match(verdict.reason, /not a pinned key/);
});

test("with no key pinned the page checks the leaf and the path and says unpinned", async () => {
  const verdict = await pageVerdict(shownView(), []);
  assert.equal(verdict.status, "unpinned");
  assert.equal(verdict.checks.signature, null);
  assert.equal(verdict.checks.leaf, true);
  assert.deepEqual(pageVerdictChip(verdict), { text: "page: unpinned", cls: "chip warn" });
  const tampered = await pageVerdict(editedLine(shownView(), '"seq":4', '"seq":5'), []);
  assert.equal(tampered.status, "invalid", "a broken leaf is invalid with or without a key");
});

test("the signature is checked under the pinned key, never the key the statement carries", async () => {
  const imported = [];
  const spy = {
    importKey: async (format, keyData, algorithm, extractable, usages) => {
      imported.push(toHex(new Uint8Array(keyData)));
      return crypto.subtle.importKey(format, keyData, algorithm, extractable, usages);
    },
    verify: (...args) => crypto.subtle.verify(...args),
    digest: (...args) => crypto.subtle.digest(...args),
  };
  const view = shownView(shown => { shown.bundle.statement.public_key = AUTHORITY.hex; return shown; });
  const verdict = await pageVerdict(view, [INSTANCE], { subtle: spy });
  assert.equal(verdict.status, "invalid", "a statement naming a key that is not its key id's is refused");
  assert.ok(!imported.includes(AUTHORITY.hex), "the carried key was never imported");
  imported.length = 0;
  assert.equal((await pageVerdict(shownView(), [INSTANCE], { subtle: spy })).status, "signed");
  assert.deepEqual(imported, [INSTANCE.hex]);
});

test("a browser without Ed25519 says it cannot check the signature", async () => {
  const noEd25519 = {
    importKey: async () => { throw new DOMException("Unrecognized name.", "NotSupportedError"); },
    verify: async () => { throw new Error("not reached"); },
    digest: (...args) => crypto.subtle.digest(...args),
  };
  const verdict = await pageVerdict(shownView(), [INSTANCE], { subtle: noEd25519 });
  assert.equal(verdict.status, "unchecked");
  assert.equal(verdict.checks.signature, null);
  assert.match(verdict.reason, /cannot check the signature/);
  assert.deepEqual(pageVerdictChip(verdict), { text: "page: cannot check the signature", cls: "chip warn" });
  const tampered = await pageVerdict(editedLine(shownView(), '"seq":4', '"seq":5'), [INSTANCE], { subtle: noEd25519 });
  assert.equal(tampered.status, "invalid", "the leaf is still checked without Ed25519");
});

test("a receipt no statement covers has no page verdict to give", async () => {
  const verdict = await pageVerdict(shownView(view => ({ ...view, bundle: null, statement: null, verdict: null,
                                                          uncovered: "no root statement covers receipt 4 yet" })), [INSTANCE]);
  assert.equal(verdict.status, "unsigned");
  assert.match(pageVerdictChip(verdict).text, /^page: unsigned/);
});

test("the page's check sends nothing", async () => {
  const sent = [];
  const spy = async (url, init) => { sent.push([url, init]); throw new Error("no network"); };
  const held = globalThis.fetch;
  globalThis.fetch = spy;
  configureTransport({ fetch: spy });
  try {
    await pageVerdict(shownView(), [INSTANCE]);
    await pageVerdict(shownView(), []);
  } finally {
    globalThis.fetch = held;
    configureTransport({ fetch: (...args) => globalThis.fetch(...args) });
  }
  assert.deepEqual(sent, []);
});

// ------------------------------------------------------------------ the receipt card
test("the receipt card shows the page's verdict beside the console's", async () => {
  const view = shownView();
  const checking = text(renderReceiptView(view));
  assert.match(checking, /console: signed/);
  assert.match(checking, /page: checking/);
  const signed = text(renderReceiptView(view, await pageVerdict(view, [INSTANCE])));
  assert.match(signed, /<span class="chip ok">console: signed<\/span>/);
  assert.match(signed, /<span class="chip ok">page: signed<\/span>/);
  const tampered = editedLine(shownView(), '"seq":4', '"seq":5');
  const invalid = text(renderReceiptView(tampered, await pageVerdict(tampered, [INSTANCE])));
  assert.match(invalid, /console: signed/);
  assert.match(invalid, /<span class="chip bad">page: invalid \(/);
});

test("the card says what an unpinned or unchecked page verdict leaves to the command", async () => {
  const view = shownView();
  const unpinned = text(renderReceiptView(view, await pageVerdict(view, [])));
  assert.match(unpinned, /page: unpinned/);
  assert.match(unpinned, /Pin the instance key/);
  const unchecked = text(renderReceiptView(view, { status: "unchecked", reason: "this browser cannot check the signature", checks: {} }));
  assert.match(unchecked, /this browser cannot check the signature/i);
  assert.match(unchecked, /prismpath trail --verify-bundle bundle\.json/);
});

test("a hostile reason is text on the card", () => {
  const card = text(renderReceiptView(shownView(), { status: "invalid", reason: "<img src=x onerror=alert(1)>", checks: {} }));
  assert.ok(!card.includes("<img"));
  assert.match(card, /&lt;img/);
});
