// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The few document helpers the screens share. Elements are addressed by the ids in ids.mjs only.
import { IDS } from "./ids.mjs";
import { markupOf } from "./markup.mjs";
import { available } from "./state.mjs";

export const TOAST_MS = 2600;
export const UNAVAILABLE_TITLE = "unavailable: the console runs read-only and mounts no write routes";

export function byId(id) {
  return document.getElementById(id);
}

export function inputValue(id) {
  return byId(id).value.trim();
}

export function renderInto(id, markup) {
  byId(id).innerHTML = markupOf(markup);
}

let toastTimer = 0;

export function showToast(message) {
  const toast = byId(IDS.toast);
  toast.textContent = message;
  toast.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add("hidden"), TOAST_MS);
}

// Wire a control to a route: in a posture that does not mount the route the control is disabled and
// says why, so it never sends a request the console would refuse.
export function bindAction(element, method, path, handler) {
  if (!available(method, path)) {
    element.disabled = true;
    element.title = UNAVAILABLE_TITLE;
    element.classList.add("unavailable");
    element.onclick = null;
    return false;
  }
  element.onclick = handler;
  return true;
}
