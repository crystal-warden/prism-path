// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The authoring interface's render functions and request builders, given fixture JSON shaped like the
// /files, /inspect, /prove and /author answers. Only flows and fixtures offer a save, the read only
// posture offers none and says why, every verdict says whose it is, the change status names the
// commands of the signed path and never claims the console ran them, and every server string is escaped.
import { test } from "node:test";
import assert from "node:assert/strict";

import { markupOf } from "../markup.mjs";
import { PATHS, POSTURE_FULL, POSTURE_READ_ONLY, routeAvailable, WRITE_ROUTES } from "../paths.mjs";
import { changeStatusLine, inspectRequest, isEditable, levelMRequest, reachRequest, renderChangeStatus,
         renderFileList, renderInspectResult, renderLevelM, renderReach, renderScaffoldResult,
         renderTemplateOptions, saveBlocked, scaffoldPreview, scaffoldRequest, splitList,
         statusRequest } from "../authoring.mjs";
import { renderWitness, witnessPath } from "../graph.mjs";

const text = markup => markupOf(markup);
const HOSTILE = "<img src=x onerror=alert(1)>\"'";

const FILES = [
  { path: "flows/f.md", size: 90, kind: "flow" },
  { path: "flows/f.tests.md", size: 40, kind: "fixture" },
  { path: "flows/f.md.manifest.json", size: 300, kind: "other" },
  { path: HOSTILE + ".md", size: 1, kind: "flow" },
];

test("the file list marks each entry's kind and only flows and fixtures as editable", () => {
  const listed = text(renderFileList(FILES, "flows/f.md"));
  assert.ok(listed.includes('class="f sel kind-flow"'));
  assert.ok(listed.includes('data-kind="fixture"'));
  assert.ok(listed.includes('<span class="kind other">read only</span>'));
  assert.ok(!listed.includes("<img"), "a file name became markup");
  assert.ok(listed.includes("&lt;img src=x onerror=alert(1)&gt;&quot;&#39;.md"));
  assert.equal(isEditable("flow"), true);
  assert.equal(isEditable("fixture"), true);
  assert.equal(isEditable("other"), false);
  assert.equal(isEditable(undefined), false);
});

test("a save is offered for a flow or a fixture in the full posture and refused with the reason otherwise", () => {
  assert.equal(saveBlocked(POSTURE_FULL, "flow"), "");
  assert.equal(saveBlocked(POSTURE_FULL, "fixture"), "");
  assert.match(saveBlocked(POSTURE_FULL, "other"), /flow documents and their fixtures/);
  assert.match(saveBlocked(POSTURE_READ_ONLY, "flow"), /read-only/);
  assert.match(saveBlocked(POSTURE_READ_ONLY, "other"), /read-only/);
});

test("the authoring write routes are the file save and the scaffold, and the read only posture mounts neither", () => {
  assert.ok(WRITE_ROUTES.includes("POST " + PATHS.file));
  assert.ok(WRITE_ROUTES.includes("POST " + PATHS.authorScaffold));
  assert.ok(!WRITE_ROUTES.includes("POST " + PATHS.authorStatus));
  assert.ok(!WRITE_ROUTES.includes("GET " + PATHS.authorTemplates));
  assert.equal(routeAvailable(POSTURE_READ_ONLY, "POST", PATHS.authorScaffold), false);
  assert.equal(routeAvailable(POSTURE_READ_ONLY, "POST", PATHS.authorStatus), true);
  assert.equal(routeAvailable(POSTURE_FULL, "POST", PATHS.authorScaffold), true);
});

test("the inspect requests name the flow and each check's route", () => {
  assert.deepEqual(inspectRequest("validate", "flows/f.md"), { path: PATHS.inspectValidate, body: { flow_md: "flows/f.md" } });
  assert.deepEqual(inspectRequest("graph", "flows/f.md"), { path: PATHS.inspectGraph, body: { flow_md: "flows/f.md", direction: "TD" } });
  for (const action of ["lint", "contract", "portable", "test"]) {
    assert.equal(inspectRequest(action, "x.md").path, PATHS["inspect" + action[0].toUpperCase() + action.slice(1)]);
  }
});

test("each inspect check renders its verdict, the console's, with the findings escaped", () => {
  const validate = text(renderInspectResult("validate", { ok: false, errors: 1, warnings: 1, findings: [
    { severity: "error", code: "E001", node: "a", message: HOSTILE },
    { severity: "warning", code: "W010", node: null, message: "unreachable" }] }));
  assert.ok(validate.includes("console&#39;s verdict") || validate.includes("console's verdict") || validate.includes("console’s verdict"));
  assert.ok(validate.includes('class="chip bad"') && validate.includes("does not compile"));
  assert.ok(validate.includes("E001") && validate.includes("W010") && !validate.includes("<img"));
  assert.ok(text(renderInspectResult("lint", { ok: true, errors: 0, warnings: 0, findings: [] })).includes('class="chip ok"'));
  const tested = text(renderInspectResult("test", { ok: false, passed: 1, failed: 1, cases: [
    { node: "a", outcome: "x", routed: "b", expected: "b", ok: true, via: "deterministic" },
    { node: "a", outcome: "y", routed: "c", expected: "b", ok: false, via: "deterministic" }] }));
  assert.ok(tested.includes("1 passed") && tested.includes("1 failed"));
  assert.ok(tested.includes("<td>c</td>") && tested.includes("<td>b</td>"));
  const contract = text(renderInspectResult("contract", { ok: false, schemas: { a: { properties: { score: { type: "number" } } } },
    conflicts: [{ node: "a", field: "score", detail: "number and string" }] }));
  assert.ok(contract.includes("score") && contract.includes("number and string"));
  const portable = text(renderInspectResult("portable", { tier: "P1", portable: false, flows: {
    "flows/f.md": { tier: "P1", semantic_edges: [{ node: "a", target: "b", condition: "needs a human" }], unlocked: [], lock: true } } }));
  assert.ok(portable.includes("P1") && portable.includes("needs a human"));
  assert.ok(text(renderInspectResult("graph", { mermaid: "graph TD\n a-->b", direction: "TD" })).includes("a--&gt;b"));
  const refused = text(renderInspectResult("test", { error: { code: 404, message: "no fixture found: " + HOSTILE } }));
  assert.ok(refused.includes("no fixture found") && !refused.includes("<img"));
});

test("the proofs are text in: the request carries the text, never a path", () => {
  assert.deepEqual(levelMRequest("---\n"), { path: PATHS.proveLevelM, body: { flow: "---\n" } });
  assert.deepEqual(reachRequest("---\n", "b, c", "", "amount <= 500"),
                   { path: PATHS.proveReach, body: { flow: "---\n", reach: ["b", "c"], forbid: [], assume: "amount <= 500" } });
  assert.deepEqual(reachRequest("t", "", " d ", "").body, { flow: "t", reach: [], forbid: ["d"] });
  assert.deepEqual(splitList(" a, ,b ,"), ["a", "b"]);
});

const REACH = {
  verdicts: { danger: "yes", safe: "no" },
  results: {
    danger: { node: "danger", reachable: "yes", proven: false, depth: 1, witness: [
      { node: "gate", target: "danger", condition: "when amount > 500", via: "deterministic", certainty: "yes", example: { amount: 501 } }] },
    safe: { node: "safe", reachable: "no", proven: true, depth: null, witness: [] },
  },
};

test("Level M and reachability render with the witness path and the console's name on the verdict", () => {
  const member = text(renderLevelM({ level_m: true, non_member_edges: [] }));
  assert.ok(member.includes('class="chip ok"') && member.includes("Level M"));
  const outside = text(renderLevelM({ level_m: false, non_member_edges: [{ node: "a", target: HOSTILE, condition: "x == y" }] }));
  assert.ok(outside.includes('class="chip bad"') && outside.includes("x == y") && !outside.includes("<img"));
  const reach = text(renderReach(REACH));
  assert.ok(reach.includes('class="v-yes"') && reach.includes('class="v-no"'));
  assert.ok(reach.includes("gate") && reach.includes("when amount &gt; 500"));
  assert.ok(reach.includes("proven unreachable"));
  assert.ok(reach.includes("console"));
  assert.ok(!text(renderReach({ verdicts: { x: HOSTILE }, results: {} })).includes("<img"));
});

test("the witness path is the nodes and edges the graph paints", () => {
  const path = witnessPath(REACH.results);
  assert.deepEqual(path.nodes, ["gate", "danger"]);
  assert.deepEqual(path.edges, [["gate", "danger"]]);
  assert.deepEqual(witnessPath({}), { nodes: [], edges: [] });
  const listed = text(renderWitness(REACH.results));
  assert.ok(listed.includes("gate") && listed.includes("danger") && listed.includes("amount &gt; 500"));
});

const STATUS = {
  flow_md: "flows/f.md", flow: "/p/flows/f.md", flow_sha256: "ab".repeat(32), writes: false, verdict_of: "console",
  note: "the console never signs, packs, swaps or attests",
  manifest: { status: "stale", flow_sha256: "ab".repeat(32), manifest_flow_sha256: "cd".repeat(32), version: 3,
              key: "b4905f8d6c3d470c", pinned: true, verdict_of: "console",
              causes: [{ name: "flow:sha256-mismatch", label: "74 flow:sha256-mismatch", class: "authority", description: HOSTILE }],
              command: "prismpath authorize verify /p/flows/f.md --pub /p/keys/authority.pub" },
  deployment: { state_dir: "state", active: "ef".repeat(32), version: 1, runs: "other-text", verdict_of: "console",
                attestation: { idx: 2, ts: "2026-11-16T00:00:00+00:00", active: "ef".repeat(32), names_active: true },
                pack: { status: "signed", flow_sha256: "99".repeat(32), image_is_active: true },
                commands: { swap: "prismpath swap swap --out /p/state --pub k --envelope <envelope> --ppt <new.ppt>",
                            attest: "prismpath swap attest --out /p/state --pub k --envelope <envelope>" } },
  commands: { sign: "prismpath authorize sign /p/flows/f.md --priv <authority.key> --pub k --version 4",
              verify: "prismpath authorize verify /p/flows/f.md --pub k",
              pack: "prismpath swap pack --ppt <image.ppt> --flow /p/flows/f.md --version <N>" },
};

test("the change status line names the hash, the manifest verdict and what the deployment runs", () => {
  const line = changeStatusLine(STATUS);
  assert.ok(line.startsWith("sha256 abababababab"));
  assert.ok(line.includes("manifest stale"));
  assert.ok(line.includes("deployment runs another text"));
  assert.equal(changeStatusLine({ ...STATUS, deployment: null, manifest: { ...STATUS.manifest, status: "unsigned" } }),
               "sha256 abababababab · manifest unsigned · no deployment followed");
  assert.match(changeStatusLine({ error: { message: "refused: outside" } }), /refused: outside/);
});

test("the change status shows the signed path's commands and says the console runs none of them", () => {
  const shown = text(renderChangeStatus(STATUS));
  assert.ok(shown.includes("prismpath authorize sign") && shown.includes("prismpath swap attest"));
  assert.ok(shown.includes("&lt;authority.key&gt;"), "a placeholder became markup");
  assert.ok(shown.includes("never signs"));
  assert.ok(shown.includes("console"));
  assert.ok(shown.includes('class="chip warn"') || shown.includes('class="chip bad"'));
  assert.ok(shown.includes("flow:sha256-mismatch") && !shown.includes("<img"));
  assert.ok(text(renderChangeStatus({ ...STATUS, manifest: { ...STATUS.manifest, status: "signed" } })).includes('class="chip ok"'));
  assert.ok(text(renderChangeStatus({ error: { code: 403, message: "refused: " + HOSTILE } })).includes("refused: &lt;img"));
});

test("the change status request names key files and the state directory, never key material", () => {
  assert.deepEqual(statusRequest("flows/f.md", "keys/a.pub, keys/b.pub", ""),
                   { path: PATHS.authorStatus, body: { flow_md: "flows/f.md", pins: ["keys/a.pub", "keys/b.pub"] } });
  assert.deepEqual(statusRequest("flows/f.md", "", "state").body, { flow_md: "flows/f.md", pins: [], state_dir: "state" });
});

const TEMPLATES = { templates: [
  { name: "starter", files: ["<name>.md", "<name>.tests.md"], flow: "<name>.md", about: "a triage flow" },
  { name: "fanout_review", files: ["<name>/fanout_review.md", "<name>/review_one.md"], flow: "<name>/fanout_review.md", about: HOSTILE },
] };

test("the scaffold offers every template, previews its files and requests one by name", () => {
  const options = text(renderTemplateOptions(TEMPLATES.templates, "fanout_review"));
  assert.ok(options.includes('<option value="starter">starter</option>'));
  assert.ok(options.includes('<option value="fanout_review" selected>fanout_review</option>'));
  const preview = text(scaffoldPreview(TEMPLATES.templates[1], "review"));
  assert.ok(preview.includes("review/fanout_review.md") && preview.includes("review/review_one.md"));
  assert.ok(!preview.includes("<img"));
  assert.ok(text(scaffoldPreview(TEMPLATES.templates[0], "")).includes("&lt;name&gt;.md"));
  assert.deepEqual(scaffoldRequest(" demo ", "starter"), { path: PATHS.authorScaffold, body: { name: "demo", template: "starter" } });
  const done = text(renderScaffoldResult({ ok: true, template: "starter", files: ["demo.md", "demo.tests.md"], flow: "demo.md" }));
  assert.ok(done.includes("demo.md") && done.includes("demo.tests.md") && done.includes("audit"));
  assert.ok(text(renderScaffoldResult({ error: { code: 409, message: "refused: demo.md already exists" } })).includes("already exists"));
});
