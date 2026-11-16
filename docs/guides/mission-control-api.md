# Mission Control: the proving + observability API

Mission Control is the control plane's **reference deployment**: a single user, loopback console for
**proving and observing flows**. It is *not* required by the PrismPath format, and it runs **no
models**: PrismPath routes and proves; inference belongs to the worker tier.

Architecturally it is a **driving (primary) adapter** over the Python core (`model_check` for proving;
the run artifact readers for observability). The browser command center is just the first client of
the same API: other services connect the same way.

## Run it

```bash
pip install -e ".[control-plane]"        # FastAPI/uvicorn/pydantic (the control-plane extra; from PyPI: pip install 'prismpath[control-plane]')
MC_PROJ=~/work/demo python -m prismpath.mission_control              # the full console
MC_EVIDENCE=~/evidence python -m prismpath.mission_control --read-only   # an assessor's console over a copy of the evidence
# command center + API at http://127.0.0.1:9109/  (loopback only; the schema is at /openapi.json)
```

Environment: `MC_PROJ` (the project followed at launch; the default is `project` under the state
directory), `MC_PORT` (9109), `MC_HOST` (127.0.0.1; any address that is not loopback is refused unless
`MC_ALLOW_NON_LOOPBACK=1` is set too, which prints a warning), `MC_SCAN` (status.json globs for sprint
auto discovery, `os.pathsep` separated, empty by default, so only sprints that announce themselves in
the registry `MC_REGISTRY`, `~/.prismpath/sprints.json`, are discovered), `MC_EVIDENCE` (evidence
roots, `os.pathsep` separated, the directories a project may be selected from besides the discovered
sprints), `MC_READ_ONLY=1` (the same as `--read-only`), `MC_STATE_DIR` (the console's own directory,
by default `$XDG_STATE_HOME/prismpath` or `~/.local/state/prismpath`, `%LOCALAPPDATA%\prismpath` on
Windows) and `MC_AUDIT` (the audit log path; the default is `mission_audit.log` in the state
directory). A sprint the console starts runs as `python -m prismpath.orchestration.run_sprint` under
the console's own interpreter, with the followed project as its working directory.

## The contract

All routes are under **`/api/v1`**. Requests and responses are JSON; the live machine readable schema
is at **`/openapi.json`**, where every route that changes something is marked
`"x-prismpath-capability": "write"`. The interactive `/docs` page is not served, because it loads its
script from a CDN, which the content security policy refuses. Every request under `/api/v1` carries
the session header (see Security posture). Errors use one envelope:

```json
{ "error": { "code": 400, "message": "path escapes project" } }
```

### Prove: the headline (text in, never a path)

Proving takes a flow **document**, not a server path, so there is no filesystem surface to traverse,
which is what makes it safe for other services. Verdicts come from the same `model_check` the kernel
and CLI use.

| Method | Path | Body → Result |
|---|---|---|
| POST | `/api/v1/prove/level-m` | `{flow}` → `{level_m, non_member_edges}`: does the deterministic tier compile to a hardware match action table (SPEC §7)? |
| POST | `/api/v1/prove/reach` | `{flow, reach?, forbid?, assume?}` → `{verdicts:{node:"yes\|may\|no"}, results}`: bounded reachability under an optional assumption |
| GET | `/api/v1/prove/audit` | → `{valid, n, signing, ok}`: the console verifies its own append only audit log, and `signing` is what `prismpath trail` reports for the root statements beside it (`status` signed-unpinned, unsigned, invalid or unchecked when the install lacks the signing extra; the keys that signed, how many events are covered, the findings, and whether this console's own key made them). It pins no key; `trail --pub` does |

```bash
# The session token, written owner only by the running console
TOKEN=$(cat ~/.local/state/prismpath/mission_control-9109.session)
# Is this flow Level M?
curl -s 127.0.0.1:9109/api/v1/prove/level-m -H "X-PrismPath-Session: $TOKEN" -H 'content-type: application/json' \
  -d '{"flow":"---\nname: f\nstart: a\n---\n## a\n-> b: when score > 5\n-> c: else\n## b\nx\n## c\ny\n"}'
# {"level_m": true, "non_member_edges": []}

# Can "danger" still be reached once amount <= 500?
curl -s 127.0.0.1:9109/api/v1/prove/reach -H "X-PrismPath-Session: $TOKEN" -H 'content-type: application/json' \
  -d '{"flow":"...","reach":["danger"],"assume":"amount <= 500"}'
# {"verdicts": {"danger": "no"}, "results": {...witness...}}
```

### Observe: read only over the followed run

`GET /api/v1/status` · `/interactions` · `/flow` · `/flow/graph` (topology + tier classified edges +
live active node + `flow_text`) · `/retrievals` (which RAG chunks a run pulled: source · path · score) ·
`/fanouts`, `/fanout/ckpt` (composition trees) · `/queue` (runs suspended for a human) · `/audit`,
`/audit/proof` (Merkle) · `/balance` · **`/events`** (SSE: `status` / `interactions` / `graph` pings).

### Control

`POST /api/v1/sprint/start`: accepts `{unbuffered: bool = true}` (the `-u`/PYTHONUNBUFFERED launch
toggle; `false` batches) plus the usual sprint config, and `/sprint/{select,auto,stop,pause,resume}`,
`/queue/decide` (human picks an edge for a suspended run). A sprint that runs `flows/sprint_loop.md`
(`SPRINT_FLOW=1`) is refused, with the registry causes and a `sprint.refused` audit event, when
`PRISMPATH_REQUIRE_AUTHORIZATION` is set and the flow has no valid flow manifest under the
`PRISMPATH_AUTHORITY_PUB` keys.

### Edit: the only write surface

`GET /api/v1/files`, `GET /api/v1/file?path=`, `POST /api/v1/file {path, content}`. Every path is
resolved and **contained** to the followed project tree; traversal (`../…`) is rejected with a 400.

### The console's own audit log

Every route that changes something (the sprint controls, `/queue/decide`, `POST /file` and
`/quality/lock`) writes an audit event to the console's log before it acts and a second event after,
under the action's name with `.result` appended, naming the first by its index and Merkle leaf, with
`ok`, `outcome` and what the effect produced (a pid, a file's sha256). A `file.edit` event carries the
path, whether it is a flow or a fixture, the flow's `name`, and the sha256 of the file before and of
the text it is about to hold, so the log says which flow text a sprint ran afterwards. When the first
event cannot be written nothing is done and the answer is a 503. An event with no result is an effect
whose outcome the console did not record. The actor of every event is `console/<interface>/<session
fingerprint>`, the interface that asked (`authoring` for the file write, `operating` for the rest)
and the first sixteen hex digits of the sha256 of the launch's session token, never the token. A
queue decision's `decided_by` is the same actor. `/attest/trail` with no `source` walks this log.

`POST /api/v1/policy/pack-active {state_dir}` reads what a deployment's state directory names as
active, whether the image is there with that digest, and its `swaps.log` history and root statement
status. It reads only, creates no directory and appends nothing. Attesting appends to the
deployment's own log, so it is the operator's `prismpath swap attest`, not a console route.
`POST /api/v1/quality/lock-check {flow_md}` checks a routing lockfile and is mounted in either posture.

## Security posture

The console is one local person's, on loopback, and loopback alone is not access control. A web page
open in the same browser can post a form to `127.0.0.1` without a preflight, a page under a hostname
that rebinds to `127.0.0.1` reads the answers unless the server checks `Host`, and any local process
can reach the port. So one guard runs before everything else and refuses, with the error envelope and
status 403, any request that fails one of these checks.

1. The `Host` header is the bound port under a loopback name, `127.0.0.1:<port>`, `localhost:<port>`
   or `[::1]:<port>`. A foreign `Host` is refused on every route, the page included, which is what
   defeats DNS rebinding. It also means a reverse proxy in front of the console is refused, on purpose.
2. An `Origin` header, when the request has one, is that same origin. A form or a fetch from another
   site is refused before it reaches a route, even when it carries the token.
3. Every request under `/api/v1` carries `X-PrismPath-Session` equal to this launch's session token,
   compared in constant time. The token is minted at random on every launch. The page gets it in a
   `<meta name="prismpath-session">` tag written into `index.html` as the page is served (the file
   on disk never holds one), and a script on the same machine reads it from
   `mission_control-<port>.session` in the state directory, a file only the console's user can read,
   which the console removes when it stops. The URL the launch prints has no token in it.

Every response carries `Content-Security-Policy: default-src 'self'; img-src 'self' data:;
connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`, and
the page and the API answer with `Cache-Control: no-store`, since the page holds the token. A script
on the page can read the token, which the policy makes safe by running only the console's own
scripts. What the guard does not stop is another account on the same machine that can reach the port
and fetch the page, so on a shared machine the console is for its own user's session only.

The console has two postures. The full posture is the default on loopback. `--read-only` (or
`MC_READ_ONLY=1`) mounts no route marked `write`, the sprint controls, the queue decision, the file
write and the lockfile write, and refuses a request for one with a 403 that
says the console is read only, so an assessor can run it over a copy of the evidence with no way to
change it. The page learns the posture from a `<meta name="prismpath-posture">` tag written as it is
served (`full` or `read-only`), and shows each control whose route that posture leaves out as
unavailable rather than sending a request the console would refuse.

The project the console follows is chosen only from the discovered sprints (the registry, the scan
globs and the launch project) or from a directory under an evidence root, and never one that holds
the console's own audit log or session file. A request that names another project, to select it or to
start a sprint in it, is a 400. A request captures the followed project once and resolves every path
against that one value, and the project moves only when a request selects one or when the event
stream follows the live sprint, both under one lock, so no answer mixes two projects. Proving is text
in (no server paths). File routes are contained to the followed project and fail closed, symlinks
included. All inputs are validated by pydantic. There is no multi tenancy and no model serving.

## Command center

The browser UI (vendored Cytoscape, no build step) renders the flow **topology** with edges colored by
tier (deterministic / semantic / error / event), overlays **Level M** membership and **reachability**
verdicts onto the graph, follows live run state over SSE, and shows the RAG chunks pulled per node.
Tabs: **Graph** · **Files** · **Audit** · **Queue** (HITL) · **Flows** (fan outs).
