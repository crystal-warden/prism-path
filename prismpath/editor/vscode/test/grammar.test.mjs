// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// The grammar's tier classification IS the editor's claim about the format — pin it.
// Each edge line must be captured by exactly the intended tier rule (rule ORDER in the grammar
// resolves overlaps: error/event/deterministic/always before the semantic catch-all).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const grammar = JSON.parse(readFileSync(join(here, "..", "syntaxes", "prismpath.injection.json"), "utf8"));
const rule = (name) => new RegExp(grammar.repository[name].match);
const ORDER = ["edge-error", "edge-event", "edge-deterministic", "edge-always", "edge-semantic"];
const firstMatch = (line) => ORDER.find((r) => rule(r).test(line));

test("tier classification matches the format's tiers", () => {
  assert.equal(firstMatch("-> done: when tests_pass"), "edge-deterministic");
  assert.equal(firstMatch('-> handle_bug: when kind == "bug" and count < 3'), "edge-deterministic");
  assert.equal(firstMatch("-> retry: on error when error_count < 3"), "edge-error");
  assert.equal(firstMatch("-> escalate: on error"), "edge-error");
  assert.equal(firstMatch("-> resume_work: on event payment_confirmed"), "edge-event");
  assert.equal(firstMatch("-> escalate: on timeout"), "edge-event");
  assert.equal(firstMatch("-> done: always"), "edge-always");
  assert.equal(firstMatch("-> escalate: the report is urgent or describes an outage"), "edge-semantic");
  assert.equal(firstMatch("  -> indented: when x"), "edge-deterministic");
});

test("non-edge lines stay untouched", () => {
  for (const line of ["## classify", "plain prose about -> arrows mid-sentence",
                      "- a markdown list item", "-> ", "->missing_colon_target"]) {
    assert.equal(firstMatch(line), undefined, line);
  }
});

test("annotations match, prose with @ does not", () => {
  const anno = rule("annotation");
  for (const line of ["@worker(council.roll)", "@state_bound(transcript=200)",
                      "@spawn(child=review.md, over=files, item_id=path, join=all_done)",
                      "  @checkpoint(unit=alert.id)"]) {
    assert.ok(anno.test(line), line);
  }
  assert.ok(!anno.test("email me @ example.com"));
  assert.ok(!anno.test("@handle on social media"));
});

test("grammar wiring: injection + rule order includes semantic LAST", () => {
  assert.equal(grammar.injectionSelector, "L:text.html.markdown");
  const listed = grammar.patterns.map((p) => p.include.slice(1));
  assert.deepEqual(listed.slice(0, 5), ORDER);   // catch-all last, so tiers win
});
