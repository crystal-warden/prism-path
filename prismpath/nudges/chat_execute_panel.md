# Narrow task: add the EXECUTE / build-progress panel to the existing working chat UI

You are given a chat UI that ALREADY WORKS for plan→approve: the user types an idea, the agent
plans (POST /api/session, then /message), and an "Approve & Build" button appears. **Do not break or
refactor that working flow.** Make the SMALLEST change that adds the remaining piece below.

## The ONE thing to add: render the EXECUTE phase from the SSE stream
The app already opens the orchestrator SSE stream (`GET /api/session/{id}/events`). Handle these
event types (they arrive as `data:` JSON lines) and reflect them in the UI:
- `{"type":"phase","phase":"executing"}` → switch to a build-progress view (hide the approve button).
- `{"type":"build_status","status":{"iteration":N,"elapsed_s":N,"valid":bool,"files":[...],"help_open":null|N}}`
  → show a friendly line, e.g. "Building… step N, Ms elapsed, K files" and, if `help_open>0`,
  "the team hit a tricky part, a human is helping." (No jargon.)
- `{"type":"done","status":{...}}` → show "Done!" and reveal a **Download** button linking to
  `GET /api/session/{id}/artifact`.

Clicking **Approve & Build** must `POST /api/session/{id}/approve` (the transport adapter likely
already has `approveSession`) and then the UI updates from the events above.

## Hard rules
- Touch the FEWEST files possible. Prefer adding to the existing render/transport adapters over
  rewriting them. Do NOT rename existing exports/classes or change the working plan→approve code.
- No new dependencies, no CDNs, only the orchestrator base already in use.
- Keep the onion/hexagonal structure; keep every file small.
- If you find you cannot add this without breaking the working core, emit `HELP_NEEDED: <why>` rather
  than thrashing the working files.
