# Build: a "plan → approve → execute" chat interface (browser app)

GOAL: a single-page browser chat UI for a **non-technical person**. They type a rough idea in plain
language; an AI agent replies conversationally — asking a clarifying question or two and proposing a
PLAN (like a calm planning mode). The user reviews the plan and clicks an **"Approve & Build"** button.
The UI then shows live BUILD PROGRESS as the agents construct the thing, and finally a **Download**
link for the result. It must feel calm and obvious to someone non-technical — one clear action per step.

This is a thin FRONT-END over an existing backend (the "orchestrator"). Do NOT build your own server,
auth, accounts, or model calls — talk ONLY to the orchestrator HTTP API below.

## Orchestrator API (base URL: http://127.0.0.1:8771)
- `POST /api/session`               body `{"prompt": "<user text>"}`  → `{"session_id","phase","reply"}`
- `POST /api/session/{id}/message`  body `{"text": "<user text>"}`    → `{"phase","reply"}`
- `POST /api/session/{id}/approve`                                    → `{"phase":"executing"}`
- `GET  /api/session/{id}/events`   → Server-Sent Events (text/event-stream); each event `data:` is JSON:
  - `{"type":"message","role":"user|assistant","content":"..."}`
  - `{"type":"phase","phase":"planning|awaiting_approval|executing|done"}`
  - `{"type":"build_status","status":{"iteration":N,"elapsed_s":N,"valid":bool,"files":[...],"last_error":"...","help_open":null|N}}`
  - `{"type":"help","open":N}`   (the agents hit a hard problem; a human is helping)
  - `{"type":"done","status":{...}}`
- `GET  /api/session/{id}/artifact` → a downloadable `.zip` of the built project

## Phase → UI
- **planning / awaiting_approval:** show the conversation; a text box to reply. When phase becomes
  `awaiting_approval`, reveal a prominent **Approve & Build** button (calls `/approve`).
- **executing:** show a live build panel driven by `build_status` events — iteration, elapsed time,
  current files, pass/fail. If `help_open` > 0, show a friendly note: "the team hit a tricky part, a
  human is helping." (No jargon.)
- **done:** show success + a **Download** button (artifact), and let them start a new idea.

## Hard rules
- Native ES modules; NO CDNs; NO external network except the orchestrator base URL above.
- Follow the architecture contract (onion core + hexagonal adapters): a pure CORE for the session +
  phase state machine; a PORT for the orchestrator transport; an ADAPTER implementing it with `fetch`
  + `EventSource`; the composition root wires them. Keep every file small.
- Non-technical UX: plain language, one clear primary action per phase, nothing intimidating on screen.
