// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The markup helper: every interpolation escaped for the context it lands in.
import { test } from "node:test";
import assert from "node:assert/strict";

import { attr, escapeText, html, Markup, markupOf } from "../markup.mjs";
import { renderFileList } from "../authoring.mjs";
import { renderNodeDetail } from "../graph.mjs";
import { renderPickerOptions } from "../panels.mjs";

// The attributes of the first start tag in `text`, the way an HTML parser splits them.
function attributesOf(text) {
  const tag = text.match(/^<[a-zA-Z]+((?:\s+[^\s=>]+(?:=(?:"[^"]*"|'[^']*'|[^\s>"']+))?)*)\s*\/?>/);
  assert.ok(tag, "no well formed start tag in " + text);
  const attributes = {};
  for (const match of tag[1].matchAll(/\s+([^\s=>]+)(?:=("[^"]*"|'[^']*'|[^\s>"']+))?/g)) {
    const raw = match[2] || "";
    attributes[match[1]] = raw.replace(/^["']|["']$/g, "");
  }
  return attributes;
}

function decoded(text) {
  return text.replace(/&quot;/g, "\"").replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

const HOSTILE = "x\" onmouseover=\"alert(1)\" data-q='y' <b>";

test("escapeText escapes the five characters that can change markup", () => {
  assert.equal(escapeText("&<>\"'"), "&amp;&lt;&gt;&quot;&#39;");
  assert.equal(escapeText(null), "");
  assert.equal(escapeText(7), "7");
});

test("an attribute value holding a quote stays one inert attribute", () => {
  for (const markup of [html`<div data-p="${HOSTILE}"></div>`, html`<div data-p=${attr(HOSTILE)}></div>`,
                        html`<div data-p='${HOSTILE}'></div>`]) {
    const attributes = attributesOf(markup.text);
    assert.deepEqual(Object.keys(attributes), ["data-p"], markup.text);
    assert.equal(decoded(attributes["data-p"]), HOSTILE);
  }
});

test("attr() quotes the value, so a template that left the quotes out is still safe", () => {
  const markup = html`<option value=${attr("a b\" onclick=x")}></option>`;
  assert.equal(markup.text, "<option value=\"a b&quot; onclick=x\"></option>");
  assert.deepEqual(Object.keys(attributesOf(markup.text)), ["value"]);
});

test("a file name with a quote cannot break out of the file row's data attribute", () => {
  const [row] = renderFileList([{ path: HOSTILE, size: 3, kind: HOSTILE }]);
  const attributes = attributesOf(row.text);
  assert.deepEqual(Object.keys(attributes).sort(), ["class", "data-kind", "data-p"]);
  assert.equal(attributes["data-kind"], "other");
  assert.equal(decoded(attributes["data-p"]), HOSTILE);
});

test("a picker path with a quote cannot break out of its option value", () => {
  const [option] = renderPickerOptions([HOSTILE + ".md"], () => true);
  assert.deepEqual(Object.keys(attributesOf(option.text)), ["value"]);
});

test("a <script> in a node instruction is text, not an element", () => {
  const node = { instruction: "<script>alert(1)</script>", edges: [{ target: "<img src=x onerror=alert(1)>", tier: "semantic", condition: "<b>" }] };
  const text = markupOf(renderNodeDetail("<i>n</i>", node, []));
  assert.ok(!/<script|<img|<i>/i.test(text), text);
  assert.ok(text.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
  assert.ok(text.includes("<br>&lt;b&gt;</div>"), text);
});

test("arrays join and only markup the helper produced passes through raw", () => {
  const inner = html`<b>${"<x>"}</b>`;
  assert.ok(inner instanceof Markup);
  assert.equal(html`<p>${[inner, "&"]}</p>`.text, "<p><b>&lt;x&gt;</b>&amp;</p>");
  assert.equal(html`${{ text: "<raw>" }}`.text, "[object Object]");
});

test("no render writes an inline style, which the content security policy refuses", () => {
  const node = { instruction: "i", edges: [] };
  const hits = [{ query: "n", hits: [{ score: 0.5, source: "s", path: "p" }] }];
  for (const markup of [renderNodeDetail("n", node, []), renderNodeDetail("n", node, hits)]) {
    assert.ok(!/style=/.test(markupOf(markup)), markupOf(markup));
  }
});
