// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The live event stream. EventSource cannot send a header, so the stream is read with fetch, which
// can, and split into its `data:` frames by splitFrames. A dropped stream is retried after retryMs,
// as EventSource would.
import { PATHS } from "./paths.mjs";
import { openStream } from "./transport.mjs";

export const STREAM_RETRY_MS = 3000;

// The complete frames in `pending` as their joined data lines, and the unfinished tail.
export function splitFrames(pending) {
  let rest = pending.replace(/\r\n/g, "\n");
  const messages = [];
  let cut;
  while ((cut = rest.indexOf("\n\n")) >= 0) {
    const frame = rest.slice(0, cut);
    rest = rest.slice(cut + 2);
    const data = frame.split("\n").filter(line => line.startsWith("data:"))
      .map(line => line.slice(5).replace(/^ /, "")).join("\n");
    if (data) {
      messages.push(data);
    }
  }
  return { messages, rest };
}

// One stream message as an event object, or null when it is not JSON.
export function parseEvent(data) {
  try {
    const event = JSON.parse(data);
    return event && typeof event === "object" ? event : null;
  } catch {
    return null;
  }
}

export async function followEventStream({ onEvent, onConnection, retryMs = STREAM_RETRY_MS }) {
  for (;;) {
    try {
      const response = await openStream(PATHS.events);
      if (!response.ok || !response.body) {
        throw new Error("event stream refused: " + response.status);
      }
      onConnection(true);
      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
      let pending = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) {
          break;
        }
        const split = splitFrames(pending + value);
        pending = split.rest;
        split.messages.map(parseEvent).filter(Boolean).forEach(onEvent);
      }
    } catch {
      /* fall through to the retry */
    }
    onConnection(false);
    await new Promise(resolve => setTimeout(resolve, retryMs));
  }
}
