# Mission Control: the proving + observability API

Mission Control is the control plane's **reference deployment**: a single user, loopback console for
**proving and observing flows**. It is *not* required by the PrismPath format, and it runs **no
models**: PrismPath routes and proves; inference belongs to the worker tier.

Architecturally it is a **driving (primary) adapter** over the Python core (`model_check` for proving;
the run artifact readers for observability). The browser command center is just the first client of
the same API: other services connect the same way.

## Run it

```bash
pip install -e ".[control-plane]"        # FastAPI/uvicorn/pydantic (the control-plane extra)
MC_PROJ=/tmp/demo python -m prismpath.mission_control
# command center + API at http://127.0.0.1:9109  (loopback only; OpenAPI at /docs)
```

Environment: `MC_PROJ` (followed project), `MC_PORT` (9109), `MC_HOST` (127.0.0.1, do **not** expose),
`MC_SCAN` (status.json glob for sprint auto discovery), `MC_AUDIT` (audit log path).

## The contract

All routes are under **`/api/v1`**. Requests and responses are JSON; the live machine readable schema
is at **`/openapi.json`** (rendered at `/docs`). Errors use one envelope:

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
| GET | `/api/v1/prove/audit` | → `{valid, n}`: the console verifies its own append only audit log |

```bash
# Is this flow Level M?
curl -s localhost:9109/api/v1/prove/level-m -H 'content-type: application/json' \
  -d '{"flow":"---\nname: f\nstart: a\n---\n## a\n-> b: when score > 5\n-> c: else\n## b\nx\n## c\ny\n"}'
# {"level_m": true, "non_member_edges": []}

# Can "danger" still be reached once amount <= 500?
curl -s localhost:9109/api/v1/prove/reach -H 'content-type: application/json' \
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
`/queue/decide` (human picks an edge for a suspended run).

### Edit: the only write surface

`GET /api/v1/files`, `GET /api/v1/file?path=`, `POST /api/v1/file {path, content}`. Every path is
resolved and **contained** to the followed project tree; traversal (`../…`) is rejected with a 400.

## Security posture

Single user, `127.0.0.1` only, no identity headers. Proving is text in (no server paths). File routes
are path scoped and fail closed. All inputs are validated by pydantic. There is no multi tenancy and
no model serving: the surface is deliberately small.

## Command center

The browser UI (vendored Cytoscape, no build step) renders the flow **topology** with edges colored by
tier (deterministic / semantic / error / event), overlays **Level M** membership and **reachability**
verdicts onto the graph, follows live run state over SSE, and shows the RAG chunks pulled per node.
Tabs: **Graph** · **Files** · **Audit** · **Queue** (HITL) · **Flows** (fan outs).
