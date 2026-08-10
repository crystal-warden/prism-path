#!/usr/bin/env node
// Log-alert worker (JavaScript). Read one log line from the [context] block on stdin, extract its level
// and latency, print ONE JSON object, exit 0. A nonzero exit routes to the flow's error tier.
// Wire it in with:  cli_agent(["node", "log_alert.js"], pass_state=["line"])
let buf = "";
process.stdin.on("data", (c) => (buf += c));
process.stdin.on("end", () => {
  try {
    const ctx = buf.split("[context]")[1] || "{}";       // PrismPath appends: ...\n\n[context]\n{json}
    const line = JSON.parse(ctx.trim() || "{}").line;
    if (!line) throw new Error("no log line in context");
    const up = line.toUpperCase();
    const level = up.includes("ERROR") ? "error"
                : up.includes("WARN") ? "warn"
                : up.includes("INFO") ? "info" : null;
    if (!level) throw new Error("no recognizable log level");
    const m = line.match(/latency=(\d+)/);
    const latency_ms = m ? parseInt(m[1], 10) : 0;
    process.stdout.write(JSON.stringify({ level, latency_ms }));
  } catch (e) {
    process.stderr.write("alert parse failed: " + e.message);   // -> the flow's error tier
    process.exit(1);
  }
});
