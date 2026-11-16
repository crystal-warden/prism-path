// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// Transport. The console refuses any /api/v1 request that does not carry this launch's session token
// in SESSION_HEADER; main.mjs reads the token from the page's meta tag once and hands it here. Every
// call answers with the parsed body, and a body that is not JSON comes back in the console's own
// error envelope, so a screen has one shape to check.
import { API_PREFIX } from "./paths.mjs";

export const SESSION_HEADER = "X-PrismPath-Session";

const settings = { token: "", fetch: (...args) => globalThis.fetch(...args) };

export function configureTransport({ token, fetch } = {}) {
  if (token !== undefined) {
    settings.token = token || "";
  }
  if (fetch) {
    settings.fetch = fetch;
  }
}

export function requestHeaders(extra = {}) {
  return { ...extra, [SESSION_HEADER]: settings.token };
}

export function apiUrl(path, query) {
  const search = query ? new URLSearchParams(query).toString() : "";
  return API_PREFIX + path + (search ? "?" + search : "");
}

async function parsed(response) {
  try {
    return await response.json();
  } catch {
    return { error: { code: response.status, message: "the console answered " + response.status + " with no JSON body" } };
  }
}

export async function getJson(path, query) {
  return parsed(await settings.fetch(apiUrl(path, query), { headers: requestHeaders() }));
}

export async function postJson(path, body) {
  return parsed(await settings.fetch(apiUrl(path), {
    method: "POST",
    headers: requestHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body || {}),
  }));
}

export async function openStream(path) {
  return settings.fetch(apiUrl(path), { headers: requestHeaders(), cache: "no-store" });
}
