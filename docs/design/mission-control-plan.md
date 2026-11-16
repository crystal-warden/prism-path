# Mission Control, one console for three roles

*A plan for the Apache-2.0 Mission Control in this repository. It names the feature set, reviews what exists against it, and lays out the work packages an implementing agent can execute without the author. Written 2026-11-16 against research main 1b558bd.*

## 0. Decisions this plan rests on

Every part of PrismPath is Apache-2.0 and lands in this repository first. The product repository is generated from it by `tools/export_clean.py` and changes only by export. There is one Mission Control. Earlier notes that moved it to a commercial tier, gave it a licence of its own, put a plugin or a second audit backend behind it, or made it the chassis of a hosted product are set aside, and nothing in this plan depends on them. Multi tenancy, role based access control, directory mapping and a hosted queue are not built, because the console is a single user loopback program and the decisions above leave no second tier to pay for them.

The console serves the people the dictionary already names. The **process owner** authors and tests the policy of record (`docs/DICTIONARY.md:303`). The **operator** runs a deployment day to day, swaps and attests policy, authors short lived changes and reads the trail (`docs/DICTIONARY.md:273`). The **assessor** anchors, verifies and audits receipts (`docs/DICTIONARY.md:109`). The engineer (`docs/guides/engineer.md`) has no dictionary entry of their own and shares the operator's console, because the engineer's console tasks (lock, calibrate, contract, pack verify) are the operator's checks run earlier. So the console has three interfaces, **authoring**, **operating** and **auditing**, and the paper draft's triple of author, operate and administer maps onto them with administer folded into operating, since there is no fleet registry to administer in this repository.

Words follow `docs/DICTIONARY.md`. A **receipt** is the durable per decision record and a Merkle leaf of its audit log (`:317`). A **root statement** is the deployment's signed statement of a log's root (`:331`). The **trail** is the Merkle rooted sequence of receipts over a window and the operator's read side of it (`:363`). A **cause** is the registered one byte reason a decision refused, parked or escalated (`:141`). An **audit event** is the record of an administrative action (`:115`). The bare words rule 5 bans (`the ledger`, `image`, `the control plane`) are not used in this plan's prose, and rule 11 is kept, so a fact the Merkle tree holds is attested and a fact Lean checks is proven.

## 1. The feature set

### 1.1 Shared by every interface

| Feature | What it does | Reads and writes | Source |
|---|---|---|---|
| S1 Session | The server mints one random session token per launch, writes it 0600 into the state directory and into the page it serves, and refuses any request to `/api/v1` that does not carry it in a header. A foreign `Host` or `Origin` is refused before routing. | Writes the token file. | Review of the current server (section 2.3). |
| S2 Deployment identity | The header shows the instance key fingerprint the console signs with, or says the audit log is unsigned, and the authority key ids the followed deployment's audit events name. | Reads `PRISMPATH_INSTANCE_KEY`, root statements beside the console's audit log, `swap` audit events. | `prismpath/mission_control/prove.py:50-67`, `prismpath/ledgers/root_statement.py:564-571`, operator guide §2. |
| S3 Console audit log | Every control action and every authoring write is an audit event in the console's own append only log, Merkle committed and, with an instance key, followed by a signed root statement. The event is written before the effect and names the interface and session that asked. | Writes `mission_audit.log` and its statements file. | `prismpath/mission_control/audit.py`, mdflow origin docstring (appends before acting). |
| S4 Followed project and evidence roots | The console follows one project and reads evidence only under roots the launch names. A project can be selected only from the discovered sprints or the allowlisted roots. | Reads `status.json` heartbeats, the registry file. | `prismpath/mission_control/discovery.py`, review finding on the `/tmp` scan default. |
| S5 Posture | `--read-only` mounts no control, edit or write capable route. The auditing interface is complete in that posture. | Nothing. | Design decision (section 3.2). |
| S6 Cause registry decoder | Any cause byte or name shown anywhere is rendered from `prismpath/kernel/causes.py` with its class, never from a string in the UI. | Reads the registry. | Decision console note (WHY panel), `docs/design/spec-cause-codes.md`. |
| S7 Events | The server pushes change notifications over SSE so screens refresh on change rather than by polling. | Reads mtimes of the followed artefacts. | `prismpath/mission_control/events.py`. |

### 1.2 Authoring (the process owner)

| Feature | What it does | Reads and writes | Source |
|---|---|---|---|
| A1 Flow editor | Opens a flow document or its fixture table from the followed project, edits it, saves it atomically. Only flow documents and fixtures are editable. The save is an audit event carrying the sha256 before and after. | Writes `*.md` and `*.tests.md` in the project. | `prismpath/mission_control/edit.py`, process owner guide `:41-47`. |
| A2 Graph | The parsed flow drawn with edges coloured by tier, with the live active node when a run is followed. | Reads the flow, `checkpoint.json`. | `prismpath/mission_control/graph.py`, `static/app.js`. |
| A3 Validate, lint, test, contract, portable | The process owner's loop from the terminal, run in process over the selected flow and shown beside the editor. `test` runs the fixture table with no model. | Reads flow and fixtures. | `prismpath/mission_control/inspect.py`, process owner guide `:24-39`. |
| A4 Prove | Level M membership and bounded reachability under an assumption, text in, with the witness path painted on the graph. | Reads nothing on disk. | `prismpath/mission_control/prove.py`, API guide `:35-57`. |
| A5 Change status | The flow's sha256, whether a flow manifest beside it is signed by a pinned authority key and names that hash, and whether the followed deployment's last attestation runs a pack built from it. Authoring never signs, packs or swaps. | Reads `<flow>.manifest.json`, `.sig`, the policy host's active record. | `docs/guides/engineer.md:47-59`, `docs/guides/operator.md:17-50`, section 3.4. |
| A6 Scaffold | New flow from a bundled template, the same as `prismpath init --template`. | Writes one new flow document. | CLI exposure design note (planned, not built). |

Dropped from authoring. Chat with a model, document upload and reindexing (the mdflow origin's Chat and Files tabs) because the console runs no models (`docs/guides/mission-control-api.md:3-5`). The Mermaid export and file upload stay out until someone needs them.

### 1.3 Operating (the operator and the engineer)

| Feature | What it does | Reads and writes | Source |
|---|---|---|---|
| O1 Runs | Discovered sprints with heartbeat age and gate verdict, the followed one pinned or auto followed, start, stop, pause, resume of the sprint loop with the refusal path when the sprint flow is not authorized. | Reads `status.json`; writes `STOP` and `PAUSE` markers, launches `prismpath.orchestration.run_sprint`. | `prismpath/mission_control/launch.py`, `control.py`, API guide `:66-73`. |
| O2 Human queue | Runs suspended `needs_human`, each with its evidence packet (node, reason, candidate edges with router scores), the operator's choice recorded as `decided_by` and applied by the run's next resume. Nested fan out children are actionable by their relative id. | Reads and writes checkpoints in the queue directory. | `prismpath/ledgers/checkpoint.py:266-338`, authoring guide §6b, roadmap note on the Warden queue (features only). |
| O3 Event delivery | For a run suspended `waiting`, record the event to deliver (`stand_down`, or the timeout) the way a decision is recorded, applied at the next resume. The console never needs the flow's worker. | Writes the checkpoint's pending event. | `docs/guides/operator.md:52-98` ("or the same through Mission Control"), `prismpath/ledgers/checkpoint.py:155-175`. |
| O4 Lens | Who said what to which worker, and the retrievals pulled per turn, over `interactions.jsonl`. Worker labels come from the run's records, not from literals. | Reads `interactions.jsonl`. | `prismpath/mission_control/lens.py`. |
| O5 Policy host | What the followed deployment is running, signed, with its overlay line, from `swaps.log` and the active record; pack verify and attest as read only checks. | Reads the state directory. | `prismpath/mission_control/policy.py`, operator guide §2. |
| O6 Cause monitor | Counts by cause and by action over the trail windowed by time, so a cause that starts climbing is visible. | Reads audit logs. | `docs/guides/operator.md:152-175`, roadmap note (calibration and reuse error monitoring, features only). |
| O7 Quality | Routing lockfile check and write, calibration of the escalation threshold, centroid cross validation, annotator agreement. The write (lock) is an audit event and is absent in read only posture. | Reads labelled JSONL; writes the lockfile. | `prismpath/mission_control/quality.py`, engineer guide `:77-89`. |
| O8 Fan outs | Composition trees with every child's stop state. | Reads the queue directory. | `prismpath/mission_control/observe.py:53-70`. |

Dropped from operating. The telemetry minimap and sensor fusion views (the Tauri shell note) because the dictionary bars the sensor and fusion domains from the core (`docs/DICTIONARY.md:64-70`) and the telemetry adapters live under `adapters/`, which the product does not export. The agy run viewer of the origin because that tool is not part of PrismPath. Ledger anchoring and upgrading from the browser, deliberately, because they publish to a timestamp calendar (CLI exposure note, `attest.py:13-18`).

### 1.4 Auditing (the assessor)

| Feature | What it does | Reads and writes | Source |
|---|---|---|---|
| U1 Trails | Every audit log under the evidence roots (`run.audit.jsonl`, `swaps.log`, the console's own log), each with its root, whether it verifies, and its root statement chain status `signed`, `signed-unpinned`, `unsigned` or `invalid`, with the findings named as `trail` names them. Pinned public keys are supplied by the assessor, never read from the log. | Reads logs and `*.roots.jsonl`. | `prismpath/trail.py`, `docs/guides/assessor.md:26-73`, `prismpath/mission_control/attest.py:93-112`. |
| U2 Receipt | One receipt decoded field by field with its cause rendered from the registry, its leaf, its inclusion path and the first statement covering it. Export as a receipt bundle with the exact `prismpath trail --verify-bundle` command printed beside it. | Reads a log; writes nothing. | `prismpath/ledgers/root_statement.py:492-562`, assessor guide `:26-41`. |
| U3 Independent check | The browser recomputes the leaf, the inclusion path, the root and the statement signature from the raw bytes the server returns, with the assessor's pinned key, and shows its own verdict beside the server's. Where the browser lacks Ed25519 the page says so and the CLI command stands. | Reads raw log lines and statements. | Section 3.3. The convergence note's client side verify page (features only). |
| U4 Anchors | Verify an anchored record, OTS or RFC 3161, read only. | Reads anchor artefacts under the evidence roots. | `prismpath/mission_control/attest.py:115-151`. |
| U5 Evidence runs | A differential run directory (`run.json`, `cases.jsonl`, `images.jsonl`, `receipts.jsonl`, `receipts.roots.jsonl`) verified by `core_evidence.verify` with pinned authority and instance keys, including the governed harness, intent and population runs, which use the same layout. | Reads a run directory. | `prismpath/ledgers/core_evidence.py:349-470`, `docs/design/spec-verified-core.md` §11, `integrations/governed_*`. |
| U6 Change control | For a receipt, the flow hash and flow manifest it names, the authority key, and whether `authorize verify` agrees. | Reads manifests and keys. | `docs/guides/assessor.md:94-98`. |
| U7 Policy | Pack verify against pinned keys and the attestation history of a state directory. | Reads packs and the state directory. | `prismpath/mission_control/policy.py`. |

Dropped from auditing. The git commit ledger as a second evidence tier (the commit as state note), because the RFC 6962 tree with root statements is the one evidence structure the specs name and the Flow Ledger stays an optional provenance layer; the console shows it only through the trail. Audit retention policy because nothing in the repository defines retention. Fleet and dissent views (paper draft) because no population runs outside a simulation. The Kubernetes webhook (PR #10, branch `population-k8s`) is not a console feature; its receipts arrive as evidence runs through U5.

## 2. What exists, and what is unsound

The test suite was run in the research virtual environment on 2026-11-16 (`python -m pytest prismpath/tests -k "mission_control or audit_log or root_statement or merkle or trail" -q`), 285 passed. The server was exercised through `fastapi.testclient` only, never bound to a non loopback address.

### 2.1 Status by feature

| Feature | Status | Evidence |
|---|---|---|
| S1 Session | Not built | `app.py` has no host, origin or token check (`prismpath/mission_control/app.py:61-120`). |
| S2 Identity | Partly | `prove.py:50-67` reports signing status; the header shows only `audit_n`. |
| S3 Console audit | Partly | `audit.py:15-31` records after the effect (`edit.py:57-59`, `launch.py:99-102`), actor is the literal `operator`, a file edit records only path and byte count. |
| S4 Project roots | Partly | Containment per request in `files.py:23-47`; selection unrestricted at `control.py:20-25`; defaults `/tmp/demo` and `/tmp/*/status.json` at `config.py:36-38`. |
| S5 Posture | Not built | |
| S6 Cause decoder | Not built | Causes reach the UI as raw strings from `trail.run`. |
| S7 Events | Built | `events.py:39-65`. |
| A1 Editor | Partly | Atomic write and containment at `edit.py:32-59`; editable suffixes include `.js .html .css .pdf` (`files.py:12`); no content hash in the event. |
| A2 Graph | Built | `graph.py:43-78`, `static/app.js` graph screen. |
| A3 Inspect | Built on the server, broken in the page | `inspect.py:76-173`; the page's panel code is unreachable (section 2.2). |
| A4 Prove | Built | `prove.py:27-47`, tests `test_mission_control.py:60-86`. |
| A5 Change status | Not built | |
| A6 Scaffold | Not built | |
| O1 Runs | Built | `launch.py`, `control.py:14-53`. |
| O2 Queue | Built | `control.py:56-66`, `checkpoint.py:312-338`; nested ids resolve. |
| O3 Event delivery | Not built | `checkpoint.resume(event=)` exists, no console path. |
| O4 Lens | Built with literals | `lens.py:19-27` hardcodes two model labels and a role split. |
| O5 Policy host | Partly | `policy.py:64-100`; `pack-attest` constructs a `PolicyHost`, whose constructor creates the state directory (`prismpath/hotswap/policy_host.py:94`) and whose `attest()` appends an attestation event to the deployment's own log (`policy_host.py:385-391`), so a route documented as read only writes the evidence it reads. |
| O6 Cause monitor | Partly | `attest.py:93-112` returns counts by cause for one log; no window, no series. |
| O7 Quality | Built on the server, broken in the page | `quality.py:51-150`; `lock` writes a lockfile outside `FILE_LOCK` with no audit event (`quality.py:95-97`). |
| O8 Fan outs | Built | `observe.py:53-70`. |
| U1 Trails | Partly | `attest.py:93-112` walks one log; with no `source` it reads `core.AUDIT`, which does not exist (`attest.py:107`), so the console's own trail is a 500 on every call (reproduced with the test client). |
| U2 Receipt | Not built | `observe.py:79-87` returns a truncated proof for the console's own log only. |
| U3 Independent check | Not built | `prismpath/portable/prismpath.mjs` has `sha256Hex` and no Merkle or canon/2. |
| U4 Anchors | Built on the server | `attest.py:115-151`, untested. |
| U5 Evidence runs | Not built | `core_evidence.verify` exists; no route, no screen. |
| U6 Change control | Not built | |
| U7 Policy | Built on the server | `policy.py:42-61`, tests `test_mission_control.py` cover two calls. |

### 2.2 The static client is broken

`static/app.js` was merged twice. Lines 150 to 208 hold the CLI panel code (`activeFlow`, `runTool`, `prefillFlowInputs`, `populatePickers`, `wireCliPanels`) pasted inside the `else if (event.type === "interactions")` branch of the SSE handler (`app.js:149`), so those declarations are block scoped to that branch and `wireCliPanels()` runs again on every interactions event. Lines 578 to 603 hold an older copy of the same functions at top level that references `GRAPH`, `$`, `jget`, `jpost` and `esc`, none of which is defined anywhere in the file. `SCREEN_LOADERS` (`app.js:220-231`) calls the top level copies, so opening the Inspect, Quality, Proof or Policy screen throws `ReferenceError`. The file parses, so nothing caught it, and there is no test that loads it.

Escaping is incomplete. `escapeText` (`app.js:54-57`) replaces `&`, `<` and `>` only, while values are interpolated into attributes at `app.js:466` (`data-p="${file.path}"`) and `:172` (`<option value="${pth}">`, not escaped at all), so a file name holding a double quote breaks out of the attribute. File names come from the followed project, which a sprint's workers write. The review of 2026-09-12 found the earlier text context injections; the tagged template fixed those and left the attribute context open.

The page sets no Content Security Policy and the server sends none.

### 2.3 The server's write surface is reachable from other origins

The console binds loopback and that is its whole access control (`docs/guides/mission-control-api.md:80-84`). Loopback does not stop a web page open in the same browser. Measured with the test client on 2026-11-16, a `POST /api/v1/sprint/stop` with a form content type and a foreign `Origin` header is accepted and dropped the `STOP` marker, and the audit log recorded it as the operator. A browser sends exactly that request from any site without a preflight. JSON bodies need `application/json` (a `text/plain` or typeless body is a 422), so `POST /file` and `/sprint/start` are protected only by the browser's preflight, which a DNS rebinding attack removes, because the server does not check `Host` (a foreign `Host` is served, measured). Any local process or local user can also reach the port. The fix is one middleware (S1) and is the first work package.

### 2.4 Other soundness problems the plan fixes first

1. Audit after the effect. `edit.write_file` writes, then records (`edit.py:57-59`); `start_sprint` spawns, then records (`launch.py:99-102`). An `AuditWriteError` leaves an unrecorded effect. The origin's docstring promised the reverse.
2. Audit events carry no content. A `file.edit` event names the path and byte count, so the log cannot say which flow text a sprint ran afterwards.
3. The followed project is set by `follow_active_sprint` from inside `status()` on every poll, including the SSE loop (`status.py:14`, `events.py:47`), while request handlers read `core.STATE["proj"]` several times per request (`edit.py:18-19`), so the project can change between the containment check and the read. `STATE` has no lock.
4. The SSE generator does blocking file IO inside `async def` (`events.py:46-60`), and `interactions`, `retrievals` and `_recent_log` read whole files on every tick (`lens.py:56`, `:82`, `stage.py:27`, `:42`), so a large `interactions.jsonl` stalls the single event loop.
5. `read_file` opens with `errors="ignore"` and never closes the handle (`edit.py:28`).
6. `sprint_select` accepts any absolute path and the edit router then writes under it (`control.py:20-25`).
7. `quality.lock` writes a lockfile with no audit event and outside the write lock (`quality.py:95-97`). `pack-attest` writes to the deployment's own evidence (section 2.1, O5).
8. `attest.walk_trail` reads `core.AUDIT` (`attest.py:107`), a 500.
9. Model names and ports as literals in `lens.py:19-23`, the finding the 2026-09-12 review made against `core.py:222`, still open.
10. Dead registration comments at the foot of `attest.py`, `quality.py`, `inspect.py` and `policy.py`.
11. The API guide documents the first generation of routes only. `/attest`, `/inspect`, `/quality`, `/policy` and `/pick` are undocumented (`docs/guides/mission-control-api.md`), and `docs/design/architecture.md:69` still describes a single file console.

### 2.5 Tests that are missing

`prismpath/tests/test_mission_control.py` (290 lines, 30 tests) and `test_mission_control_defaults.py` cover proving, containment, atomic writes, the error envelope and two panel calls. Nothing covers the control routes end to end, `/quality`, `/fanouts`, `/audit/proof`, `/attest/ledger-verify`, `/attest/trail` without a source, the SSE stream, cross origin requests, the `Host` header, or any line of `static/app.js`. The CI job `mission_control` runs that one file (`.github/workflows/ci.yml:171-187`); the `conformance` job already runs `node --test` and can carry client tests.

## 3. Architecture decisions

### 3.1 The UI is a browser page served by the console, not a desktop shell

The Tauri idea in the strategy notes reuses a learning IDE's shell to host the console and decode telemetry in process. Evaluated against this repository it loses on every count that matters here. The console must ship as package data in the pip wheel (`pyproject.toml:83-84`, `.github/workflows/ci.yml:129`) and reach the product by export, and a Rust plus Node desktop build with per platform signing does neither. The one technical advantage claimed, in process telemetry decoding, is a read side function the Python server already exposes (`policy.py:103-147`) and is not a UI concern. The shell's own notes say its audience and content are different. A desktop wrapper can point any webview at the loopback page later without changing the plan. Decision. The page stays vanilla ES modules with vendored libraries and no build step, split by interface, with pure rendering functions testable under `node --test`.

### 3.2 One ASGI app, three interfaces, two postures

The three interfaces are three screen sets over one API under `/api/v1`, and the route names in the guide stay as they are, because they are a published contract. Routers carry an OpenAPI tag naming their interface and a capability, `read`, `observe` or `write`. The server has two postures. `full` is the loopback default. `read-only` (`--read-only` or `MC_READ_ONLY=1`) mounts only `read` routes, so an assessor can run the console over a copy of the evidence with no way to change it, and the authoring and operating screens show as unavailable. Identity is one local person, so authorisation is by posture and capability, not by user. The actor recorded in every audit event is `console/<interface>/<session fingerprint>`.

### 3.3 Auditing verifies without trusting the server

The server's verdicts (`trail.run`, `verify_receipt_bundle`, `core_evidence.verify`) are shown and labelled as the console's. Independence comes from three things. First, the auditing routes return the raw artefacts (log lines, statements, bundles) as bytes, not only verdicts. Second, pinned public keys are entered or dropped into the page by the assessor and kept in the browser, never fetched from the server. Third, the page recomputes leaf, inclusion path, root and signature itself. That needs canon/2 and the RFC 6962 tree in the portable JavaScript, held to the existing corpora (`prismpath/portable/conformance/canon2.json`, `merkle_stream.json`, `receipts.json`) under the same `run_vectors.mjs`, and Ed25519 through WebCrypto where the browser offers it. When it does not, the page says so and prints the CLI command, which is the check of record in any case (`docs/guides/assessor.md`).

### 3.4 Authoring changes reach policy images only through the signed path

The console edits flow documents and fixtures, nothing else. It never compiles, packs, signs or swaps. The path from a change to a running policy is the one the guides give. The owner edits and tests, the change is a diff under version control, the engineer packs and signs with the authority key off the console, the operator swaps and attests, and the assessor reads the receipt that names the flow hash. The console's part is to make each step visible. A1 records the flow's sha256 before and after every save, A5 shows whether a signed manifest and a live attestation match the saved text, and U6 closes the loop from the receipt side. The authority key never touches the console and `check_separation` (`root_statement.py:185`) keeps the instance key from standing in for it.

### 3.5 What is proven, tested and designed

Proven in Lean (`formal/Core/Merkle.lean`). The streaming accumulator equals the RFC 6962 tree for every list (`acc_root_eq_mth`, `:317`), the tree is injective (`mth_injective`, `:121`), the peak count is bounded (`accPeaks_length_le`, `:347`) and the retired tree collided (`retired_collides`, `:382`). The verified core's decision and canonical form theorems are in `formal/Core` and `formal/FQ` (`formal/README.md`).

Tested against frozen corpora. The Merkle stream (`test_merkle_stream.py`), canon/2, receipts and the differential evidence verifier (`test_core_evidence.py`, oracle gated in `formal.yml`).

Tested only. The audit log, root statements, receipt bundles, the queue, every route in section 2.1 marked built.

Designed, not built. Everything marked not built, S1 through S6, U2 through U6, O3, A5, A6, and the client side verifier.

## 4. Work packages

Each package is one agent session. Every package ends with the same gates. The research suite passes (`python -m pytest prismpath/tests -q`, and for packages touching the client `node --test prismpath/portable/prismpath.test.mjs` plus the new client tests). `cd formal && lake build` runs only when `formal/` is touched (no package here touches it). The export round trip passes (`python tools/export_clean.py --out <tmp>` then inside it `python -m tools.provenance check --research <research checkout>`). `tools/acceptance.sh --leg full` passes. gitleaks reports nothing over the branch. CI is green on a pull request against `crystal-warden/prism-path` before merge. Commit messages are one plain sentence. Nothing private appears in code, tests or docs.

Tests are written first and must fail before the change and pass after. File paths are relative to the repository root.

### WP0 The security floor

Goal. No request reaches a route unless it comes from the page the console served, in the browser it served it to, over the host it was bound to.

Files. New `prismpath/mission_control/session.py` (token mint, 0600 file under the state directory, constant time compare). `app.py` gains one middleware before everything else that refuses, with the error envelope and no other processing, any request whose `Host` is not `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>`, any request with an `Origin` header that is not that same origin, and any `/api/v1` request without `X-PrismPath-Session` equal to the token. The page is served by a route that reads `index.html` and inserts the token into a `<meta>` tag, replacing the static mount for that one file. Response headers `Content-Security-Policy: default-src 'self'; img-src 'self' data:; connect-src 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on `/api/v1`. `config.py` gains `read_only: bool` and `evidence_roots: list[str]` (`MC_EVIDENCE`, `os.pathsep` separated) and drops the `/tmp` defaults for `proj` and `scan` in favour of the state directory and the registry. `control.sprint_select` refuses a project that is not a discovered sprint or under an evidence root. `state.py` gains a lock around `STATE`, and `status()` stops mutating `STATE`, with following moved to the SSE loop under that lock. `__main__.py` prints the URL with no token in it and refuses `MC_HOST` other than loopback unless `MC_ALLOW_NON_LOOPBACK=1` is set, which prints a warning.

Tests (new `prismpath/tests/test_mission_control_session.py`). Form POST to `/sprint/stop` with a foreign Origin is 403 and drops no marker. A foreign `Host` is 403 on every route. A request without the header is 403 and one with it is 200. The token file mode is 0600. `sprint_select` outside the roots is 400. CSP header present on the page and the API. `index.html` holds the meta tag. Two threads selecting and reading do not observe a project change mid request (containment check and read use one captured project).

Done when the measurements in section 2.3 all refuse, the existing suite passes with the test client sending the header through a fixture, and the API guide's security section is rewritten to describe the middleware.

### WP1 The client repaired and made testable

Goal. One screen set per interface, every render a pure function, no unreachable or duplicate code, every interpolation escaped for its context, and tests that load the client.

Files. `static/app.js` becomes `static/js/{markup,transport,state,events,graph,authoring,operating,auditing,main}.mjs` loaded with `<script type="module">`. `markup.mjs` escapes `"` and `'` as well and offers `attr()` for attribute values. Remove lines 578 to 603 and move lines 150 to 208 out of the SSE branch. `index.html` gains three top level interface tabs with the existing screens under them (Graph, Files, Inspect, Prove under Authoring; Runs, Queue, Lens, Policy, Quality, Flows under Operating; Trails, Audit, Proof under Auditing). Every element id the modules reference is listed in one `ids.mjs` constant and every API path in `paths.mjs`.

Tests. New `prismpath/mission_control/static/js/tests/*.test.mjs` run by `node --test` for `markup` (an attribute value with a quote is inert, a `<script>` in a node instruction is text) and for each render function given fixture JSON. New `prismpath/tests/test_mission_control_client.py`. Every id in `ids.mjs` exists in `index.html`. Every path in `paths.mjs` exists in `app.openapi()`. Every `.mjs` parses under `node --check` in strict mode (skipped when node is absent, which CI's conformance job is not). `.github/workflows/ci.yml` `conformance` job runs the client tests.

Done when opening each screen in a browser against a local project shows data with no console error, and the three contract tests pass.

### WP2 The console's own evidence

Goal. Every effect the console causes is an audit event written before the effect, naming interface, session, inputs and content hashes, with the effect's result recorded after, and every write path is audited and locked.

Files. `audit.py` gains `record_intent(action, data) -> event` and `record_result(intent_event, ok, detail)` and takes the actor from the session (`console/<interface>/<fp>`). `edit.py` records `sha256_before`, `sha256_after` and the flow name. `launch.py`, `control.py` record intent then act. `quality.lock` records and takes `FILE_LOCK`. `policy.pack_attest` is split into `pack-active` (read the active record and history without constructing a `PolicyHost`) and the attesting call is removed, since attesting is the operator's CLI act. `attest.walk_trail` reads `core.audit.LOG.path`. Dead registration comments removed. `lens.py` reads worker labels from the interaction records (`model` or `role` fields) and names nothing.

Tests. An audit write failure (monkeypatched `AuditLog.append` raising) leaves the flow file unchanged. The intent event precedes the effect's mtime. A `file.edit` event's `sha256_after` equals the file's hash. `/attest/trail` with no source returns the console's own trail. `/policy/pack-active` creates no directory and appends nothing to the deployment's log. `/quality/lock` in write mode produces an audit event and is absent in read only posture.

### WP3 Evidence readers

Goal. Transport agnostic readers for everything the auditing interface shows, each a pure function over paths under the evidence roots, with the cause decoder.

Files. New `prismpath/mission_control/evidence.py`. `discover_logs(roots)` lists audit logs and their statement files. `trail_report(path, since, last, pinned)` wraps `trail.run`. `receipt_view(path, index)` returns the event, decoded cause (`causes.name`, `causes.cause_class`), leaf, inclusion path, covering statement and the bundle. `raw_lines(path, start, count)` returns bytes. `run_report(dir, pins)` wraps `core_evidence.verify` with sampling bounded by a setting. `cause_series(path, bucket_s)` returns counts by cause per bucket. `manifest_status(flow_path, pins)` wraps `flow_authority.verify_flow` (`prismpath/hotswap/flow_authority.py:124`) for A5 and U6. New `prismpath/mission_control/causes_view.py` renders any code or name. All paths are confined to the evidence roots with `files.is_contained`.

Tests (new `test_mission_control_evidence.py`). A log with a tampered line reports `invalid` and names the finding. A receipt view's bundle verifies with `verify_receipt_bundle` and fails when the leaf is altered. A run directory produced by `core_evidence.produce` with test keys verifies, and a resigned false receipt fails. A path outside the roots is refused. Every registered cause renders.

### WP4 The auditing interface

Goal. U1, U2, U4, U5, U6, U7 as routes under the `read` capability and screens under the Auditing tab, available in read only posture.

Files. New `prismpath/mission_control/auditing.py` router (`/evidence/logs`, `/evidence/trail`, `/evidence/receipt`, `/evidence/raw`, `/evidence/run`, `/evidence/manifest`) over WP3, plus the existing `attest` and `policy` read routes re tagged. `static/js/auditing.mjs` renders the trail list with chain status, the receipt view with the bundle download and the printed CLI command, the run verifier and the pinned key drop zone (keys kept in `sessionStorage`, never posted). The 2026-09-12 review's rule stands, every verdict shown says whose verdict it is.

Tests. Route tests for each endpoint over fixtures from WP3. Client render tests. A pinned key never appears in any request body (asserted by a transport mock).

Depends on WP0, WP1, WP3.

### WP5 Independent verification in the page

Goal. U3. The browser recomputes what it shows.

Files. `prismpath/portable/canon2.mjs` (canon/2 serialisation held to `conformance/canon2.json`), `prismpath/portable/merkle.mjs` (RFC 6962 leaf, node, path verification and the streaming accumulator held to `conformance/merkle_stream.json` and `receipts.json`), both run by `run_vectors.mjs`. `static/js/verify.mjs` uses them with WebCrypto SHA-256 and Ed25519 (`crypto.subtle.importKey("raw", ..., {name: "Ed25519"})`), falling back to a clear "this browser cannot check the signature" line. The auditing screen shows the page's verdict beside the console's.

Tests. The two portable modules pass every vector. A node test verifies a bundle fixture produced by Python and rejects a mutated one. Node 20 or later has WebCrypto Ed25519, so the signature test runs in CI.

Depends on WP4. This is the one package that adds to the portable kernel and its corpus runner, so the product boundary check (`tools.check_boundary`) must still pass.

### WP6 The operating interface

Goal. O3, O5 and O6 added, O1, O2, O4, O7, O8 under the Operating tab, posture respected.

Files. `control.py` gains `/queue/event {id, event}` writing `pending_event` into a `waiting` checkpoint the way `record_decision` writes `decision`, and `checkpoint.resume` applies it when `event` is not given, mirroring the `decision` branch at `checkpoint.py:180`. `observe.py` gains `/policy/active` (the active record and history from a state directory under the evidence roots) and `/trail/causes` (the WP3 series). `static/js/operating.mjs` renders runs, queue (with event delivery for waiting runs), lens, policy host and the cause series as a plain table with sparklines drawn in SVG, no library.

Tests. A `waiting` checkpoint with a recorded event resumes along the `on event` edge under a scripted worker. A `needs_human` checkpoint refuses an event. The cause series buckets a fixture log correctly. Posture read only has no `/queue/*` POST routes.

Depends on WP0, WP1, WP2, WP3.

### WP7 The authoring interface

Goal. A1 tightened, A3 and A4 reachable, A5 and A6 added.

Files. `files.py` `EDITABLE_SUFFIXES` becomes `(".md",)` with fixtures included by name, and `file_tree` marks each entry `flow`, `fixture` or `other`. `edit.py` refuses writes outside those kinds. New routes `/author/scaffold {name, template}` (the templates `prismpath init` ships) and `/author/status {flow_md}` (WP3 `manifest_status` plus the active attestation's pack hash when a state directory is under the roots). `static/js/authoring.mjs` renders the editor, the inspect panels with their verdicts, the prove panel painting the witness path, and the change status line.

Tests. A write to a `.json` path is refused. Scaffold creates exactly the template's files and records an audit event. Status reports `unsigned` for a flow with no manifest, `signed` with a manifest under a pinned key, and `stale` when the manifest names another hash.

Depends on WP0, WP1, WP2, WP3.

### WP8 Documentation, dictionary, export

Goal. The guides and the dictionary describe the console that exists.

Files. `docs/guides/mission-control-api.md` regenerated from `app.openapi()` by a small script in `tools/` so it cannot drift, with the posture and session sections written by hand. `docs/guides/{process-owner,operator,assessor}.md` each gain a short "in the console" paragraph naming their interface. `docs/DICTIONARY.md` entry for Mission Control updated to name the three interfaces and the postures, and a `session` entry added, with `docs/vocabulary.json` in the same commit (rule 13). `docs/design/architecture.md:69` corrected. `CHANGELOG.md` entry. `tools/mirror/docs` overlay updated where the product wording differs. Export, provenance and acceptance run and the report attached to the PR.

Depends on everything above. Can begin its guide text once WP4, WP6, WP7 routes are fixed.

### Order and parallelism

WP0 first and alone. Then WP1, WP2 and WP3 in parallel, since they touch the client, the audit path and a new module respectively. Then WP4, WP6 and WP7 in parallel. WP5 after WP4. WP8 last. Three agents at once is the ceiling, so the two parallel waves fit.

### Risks

The session token in a `<meta>` tag is readable by any script on the page, which is fine because the CSP allows only the console's own scripts, and the risk is a vendored library with an injection, so Cytoscape stays pinned and its licence file beside it. The `Host` check breaks a reverse proxy in front of the console, which is deliberate and documented. Node tests in CI depend on the `conformance` job's Node version carrying WebCrypto Ed25519, which Node 20 does. Removing `.js .html .css .pdf` from the editable set removes a legacy the mdflow origin needed for Luau projects and nothing in this repository uses. The regenerated API guide may read drier than the hand written one, so the hand written framing paragraphs are kept above the generated table.

## 5. Questions for the owner

1. Should the sprint loop controls (O1) stay in the operating interface, given that orchestration is kept as a fallback for an organisation without its own (`docs/POSITION.md:154`)? Recommendation. Keep them, below the queue and the policy host, because the console is the only place they are driven from today.
2. Should the default posture on loopback be `full`, with `--read-only` opt in? Recommendation. Yes. An assessor runs `--read-only`, and the product guide says so in its first paragraph.
3. Is the in page verifier (WP5) wanted now, given it adds canon/2 and the RFC 6962 tree to the portable JavaScript? Recommendation. Yes, after WP4 lands, because it is the only part of the plan that lets an assessor distrust the server from the page itself and the corpora to hold it to already exist.
4. The old paths stay under `/api/v1` and new ones join them, with no `v2`. Recommendation. Agree, the guide and the product carry the contract.
5. A desktop wrapper is not built. Recommendation. Agree, revisit only if a user asks for one.
