// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// Markup. One tagged template does every render, so no screen has to remember to escape a server
// string. Values interpolate escaped, arrays join, and only markup this module produced passes
// through raw. The escape covers the attribute context as well as text: a double or single quote in
// a value cannot close the attribute it sits in, and attr() writes an attribute value with its own
// quotes, so a value is safe even where the template left the quotes out.
//
// Nothing here touches the document, so every render function built on it runs under node --test.

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" };

export class Markup {
  constructor(text) {
    this.text = text;
  }

  toString() {
    return this.text;
  }
}

export function escapeText(value) {
  const text = value == null ? "" : String(value);
  return text.replace(/[&<>"']/g, character => ESCAPES[character]);
}

export function markupOf(value) {
  if (value instanceof Markup) {
    return value.text;
  }
  if (Array.isArray(value)) {
    return value.map(markupOf).join("");
  }
  return escapeText(value);
}

// An attribute value, quoted: html`<option value=${attr(path)}>` writes value="…" with the path escaped.
export function attr(value) {
  return new Markup("\"" + escapeText(value) + "\"");
}

export function html(literals, ...values) {
  let text = literals[0];
  values.forEach((value, slot) => {
    text += markupOf(value) + literals[slot + 1];
  });
  return new Markup(text);
}
