// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The collector's feed in the page: the live view under Operating (decisions as they arrive, the
// enforcer's counters, what the feed dropped) and a kept session under Auditing (its chain status, the
// holes the console's copy has, the findings). The server reads the feed and checks it; this module
// only shows what /feed/live and /evidence/feed answer.
//
// Every verdict here is the console's over the collector's seals, which the collector does not sign:
// the page says so beside every chain status ("collector seal, unsigned"). A signed root statement over
// a seal is the operator's step, off the console.
import { IDS } from "./ids.mjs";
import { attr, html } from "./markup.mjs";
import { PATHS } from "./paths.mjs";
import { bindAction, byId, inputValue, renderInto, showToast } from "./dom.mjs";
import { getJson, postJson } from "./transport.mjs";

const CHAIN_TONE = { intact: "ok", pending: "warn", holes: "warn", broken: "bad", empty: "warn" };
const CHAIN_SAYS = {
  intact: "every leaf received is under a seal whose root the console recomputed",
  pending: "every seal so far holds; the newest leaves await the next seal",
  holes: "every check held, and the console's copy misses leaves the collector sealed",
  broken: "a check failed: see the findings",
  empty: "no seal received yet",
};

function chip(text, tone) {
  return html`<span class=${attr("chip " + tone)}>${text}</span>`;
}

function short(hex) {
  return typeof hex === "string" ? hex.slice(0, 16) : "";
}

function kv(label, value) {
  return html`<div class="kv"><span class="k">${label}</span><span class="v">${value == null ? "" : value}</span></div>`;
}

function span(entry) {
  return `${entry.from} to ${entry.to - 1} (${entry.leaves} leaves)`;
}

// The chain's state, the console's verdict over the collector's unsigned seals, with the holes, the spans
// held but unchecked, the findings and the collector's own error records.
export function renderFeedChain(chain) {
  if (!chain) {
    return html`<div class="muted">no session yet</div>`;
  }
  const status = chain.status || "empty";
  const whose = (chain.verdict_of || "console") + ": " + status;
  const seals = chain.seals || {};
  const last = seals.last || {};
  const head = html`<div class="verdict-line">${chip(whose, CHAIN_TONE[status] || "warn")}
      ${chip(chain.statement || "collector seal, unsigned", "warn")}
      <span class="muted">${CHAIN_SAYS[status] || ""}</span></div>`;
  const facts = [
    kv("session", chain.session || ""),
    kv("leaves", `${chain.received ?? 0} received of ${chain.count ?? 0} · joined at ${chain.joined_at ?? "?"}${chain.unframed ? ` · ${chain.unframed} without a frame` : ""}`),
    kv("seals", `${seals.checked ?? 0} checked · ${seals.adopted ?? 0} taken up after a hole · last ${last.trigger || "?"} at ${last.count ?? "?"} leaves, root ${short(last.root)}`),
  ];
  const holes = (chain.holes || []).length
    ? html`<div class="feed-holes"><div class="k">holes (${chain.holes_total} · ${chain.missing ?? 0} leaves the console does not hold)</div>
        <ul class="findings">${chain.holes.map(hole => html`<li>leaves ${span(hole)} · ${hole.why === "gap" ? "dropped by the collector for this client (gap)" : "sent while the console was not connected"}${hole.segment != null ? " · segment " + hole.segment : ""}</li>`)}</ul></div>`
    : "";
  const unchecked = (chain.unchecked || []).length
    ? html`<div class="k">held but unchecked (no root over them could be computed after a hole)</div>
        <ul class="findings">${chain.unchecked.map(entry => html`<li>leaves ${span(entry)}${entry.open ? " · until the next seal" : ""}</li>`)}</ul>`
    : "";
  const findings = (chain.findings || []).length
    ? html`<div class="k">findings (${chain.findings_total})</div>
        <ul class="findings">${chain.findings.map(found => html`<li><span class="a">${found.check}</span> ${found.detail}${found.index != null ? " · leaf " + found.index : ""}${found.segment != null ? ` · segment ${found.segment} line ${found.line}` : ""}</li>`)}</ul>`
    : "";
  const errors = (chain.collector_errors || []).length
    ? html`<div class="k">the collector's error records</div><ul class="findings">${chain.collector_errors.map(error => html`<li>${error.reason || ""}</li>`)}</ul>`
    : "";
  const ignored = Object.keys(chain.ignored || {}).length
    ? kv("ignored kinds", Object.entries(chain.ignored).map(([kind, count]) => `${kind} ${count}`).join(", "))
    : "";
  return html`${head}${facts}${ignored}${holes}${unchecked}${findings}${errors}`;
}

const CONNECTION_TONE = { connected: "ok", off: "warn", waiting: "warn", connecting: "warn", stopped: "warn", idle: "warn" };

function counters(enforcer) {
  if (!enforcer) {
    return html`<div class="muted">no enforcer counters (the collector reads them for the governed net edge only)</div>`;
  }
  const tally = enforcer.counters || {};
  const cells = Object.keys(tally).sort().map(name => html`<td>${tally[name]}</td>`);
  const heads = Object.keys(tally).sort().map(name => html`<th>${name}</th>`);
  return html`<div class="muted">enforcer: ${enforcer.loaded ? "a policy is loaded" : "no policy loaded"} · image ${enforcer.image_index ?? "?"} · ${enforcer.n_rules ?? "?"} rules</div>
    <table class="series"><thead><tr>${heads}</tr></thead><tbody><tr>${cells}</tr></tbody></table>`;
}

function arrived(us) {
  return typeof us === "number" ? new Date(us / 1000).toISOString().slice(11, 23) : "";
}

function readingOf(entry) {
  return entry.reading ? Object.entries(entry.reading).map(([key, value]) => `${key} ${value}`).join(" ") : "";
}

function recentRow(entry) {
  const cause = entry.cause ? entry.cause.label : "";
  const what = entry.kind === "decision" ? entry.outcome_name || "?" : entry.kind === "receipt"
    ? `receipt ${entry.prev_node} → ${entry.next_node}` : `malformed (${entry.length ?? "?"} bytes)`;
  return html`<tr><td>${entry.index}</td><td>${arrived(entry.arrived_us)}</td><td>${what}</td><td>${cause}</td>
    <td>${entry.src_ip ? entry.src_ip + ":" + (entry.src_port ?? "") : ""}</td><td class="muted">${readingOf(entry)}</td></tr>`;
}

// The live view (/feed/live): the connection, the enforcer's counters, what the feed dropped, the chain
// and the newest records, newest first.
export function renderLiveFeed(payload) {
  const connection = payload.connection || "off";
  const head = html`<div class="verdict-line">${chip("feed: " + connection, CONNECTION_TONE[connection] || "warn")}
      <span class="muted">${payload.endpoint || ""}</span>${payload.reason ? html`<span class="muted">${payload.reason}</span>` : ""}</div>`;
  if (connection === "off") {
    return html`${head}<div class="muted">Launch the console with MC_COLLECTOR naming the collector's socket to see its decisions here.</div>`;
  }
  const lastError = payload.last_error ? html`<div class="muted">last: ${payload.last_error}</div>` : "";
  const kept = payload.kept ? kv("kept as evidence", payload.kept)
    : kv("kept as evidence", payload.store_error || payload.store || "not kept");
  const dropped = payload.feed ? html`<div class="muted">the collector's feed: ${payload.feed.clients ?? "?"} clients · ${payload.feed.dropped ?? 0} records dropped for slow clients · ${payload.collector_count ?? "?"} leaves sealed</div>` : "";
  const recent = (payload.recent || []).length
    ? html`<table class="series feed-recent"><thead><tr><th>leaf</th><th>arrived</th><th>outcome</th><th>cause</th><th>from</th><th>reading</th></tr></thead>
        <tbody>${payload.recent.map(recentRow)}</tbody></table>`
    : html`<div class="muted">no decision received yet</div>`;
  return html`${head}${lastError}${kept}${counters(payload.enforcer)}${dropped}${renderFeedChain(payload.chain)}${recent}`;
}

// A kept session read again from its bytes (/evidence/feed): the chain and every segment's bytes.
export function renderFeedReport(report) {
  const files = (report.files || []).map(file => html`<tr><td>${file.segment}</td><td>${file.lines}</td><td>${file.size}</td>
    <td>${file.ended || "open"}</td><td class="muted">${short(file.sha256)}</td></tr>`);
  return html`${kv("session directory", report.path || "")}${renderFeedChain(report)}
    <table class="series"><thead><tr><th>segment</th><th>lines</th><th>bytes</th><th>ended</th><th>sha256</th></tr></thead><tbody>${files}</tbody></table>
    <div class="muted">${report.note || ""}</div>`;
}

// The /evidence/feed body for the card's inputs.
export function feedRequest(inputs) {
  const body = { path: (inputs.path || "").trim() };
  const segment = (inputs.segment || "").trim();
  if (segment) {
    body.segment = Number(segment);
  }
  return [PATHS.evidenceFeed, body];
}

export async function loadLiveScreen() {
  try {
    const payload = await getJson(PATHS.feedLive, { limit: "50" });
    renderInto(IDS.liveOut, payload.error ? html`<div class="muted">${payload.error.message}</div>` : renderLiveFeed(payload));
  } catch (error) {
    renderInto(IDS.liveOut, html`<div class="muted">${String(error)}</div>`);
  }
}

export async function readFeedReport() {
  const [path, body] = feedRequest({ path: inputValue(IDS.feedPath), segment: inputValue(IDS.feedSegment) });
  if (!body.path) {
    showToast("name a kept feed session under an evidence root");
    return;
  }
  renderInto(IDS.feedOut, html`<div class="muted">reading</div>`);
  const report = await postJson(path, body);
  renderInto(IDS.feedOut, report.error
    ? html`<div class="refusal">refused ${report.error.code ?? ""} ${report.error.reason || ""}: ${report.error.message || ""}</div>`
    : renderFeedReport(report));
}

// Fill the card with a kept session's directory and read it (from the Trails listing).
export function openFeedReport(path) {
  byId(IDS.feedPath).value = path;
  byId(IDS.feedSegment).value = "";
  readFeedReport();
}

async function readLiveSession() {
  const payload = await getJson(PATHS.feedLive, { limit: "0" });
  if (!payload.kept) {
    showToast(payload.connection === "off" ? "no feed client runs" : "the live feed is not kept as evidence");
    return;
  }
  openFeedReport(payload.kept);
}

export function wireFeed() {
  byId(IDS.liveRefresh).onclick = loadLiveScreen;
  bindAction(byId(IDS.feedGo), "POST", PATHS.evidenceFeed, readFeedReport);
  bindAction(byId(IDS.feedLiveSession), "GET", PATHS.feedLive, readLiveSession);
}
