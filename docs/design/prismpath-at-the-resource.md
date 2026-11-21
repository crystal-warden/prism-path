# PrismPath at the resource

*Design note, 2026-11-20, against research main 2ae3627. Documents only. No code changed.*

## 0. The idea

The owner's framing of 2026-11-20 is "we don't care who the model is. We don't care who the worker is ... we can wrap the resource in a Prism Path policy requirement."

PrismPath protects the resource, whatever the worker is. The worker can be a model, a person or a script. The worker side enforcement built so far is one deployment of the idea, not the idea. That work is the Claude Code hook, the launcher, the egress proxy and the rest of `prismpath/agent/`. It governs one kind of worker on one machine.

NIST SP 800-207 places the policy enforcement point in front of the resource too (https://csrc.nist.gov/pubs/sp/800/207/final). The agent harness put it next to the worker because that was the part we could reach first.

## 1. What sits in front of a resource today

| Enforcement point | Where | What it reads | What it is missing |
|---|---|---|---|
| MCP proxy | `prismpath/agent/mcp_proxy.py`, `prismpath/agent/mcp_map.py` | A `tools/call` on stdio, read into the classifier's call shape (tool, path, command class). Only the classifier's own tools and the reference filesystem server's tools are read. Anything else is `unknown`. | It stands next to the client, not in front of the server, so a client that does not use it skips it. Stdio only. It reads tool names, not the request the server then makes (HTTP, SQL). It decides on identity free fields, but has no grant. |
| Egress proxy | `prismpath/agent/egress.py`, `prismpath/agent/egress_policy.py` | A CONNECT target (host and port), with the destination resolved and checked as globally routable. | The relay is opaque bytes after CONNECT. The proxy cannot say what travels, so an allowed host is an open data path (section 6). |
| XDP edge | `integrations/governed_net/` (`PROTOCOL.md`, `README.md`), `prismpath-ebpf/ppt_net.bpf.c`, `prismpath-ebpf/gnet/` | One UDP datagram whose header is the call as typed integers. The tool server decides again from its own handle table. | It reads a purpose built protocol, not the HTTP, SQL or registry traffic that real resources speak. Only the LAN edge deployment has been run. |
| cFS app | Planned in `docs/design/cfs-app-plan.md`. A skeleton and a policy table exist under `integrations/cfs/prismpath_app`. | A proposed command on a software bus message id. | The software bus gap. Nothing forces a vehicle app to listen only to the PrismPath app. The plan states it and decision 6 of `enforcement-points-plan.md` section 6 accepts it. |
| Hook and sandbox | `prismpath/agent/claude_code.py`, `prismpath/agent/sandbox_hook.py`, `prismpath/agent/profile.py` | The agent's own tool calls and the files and network a process may touch. | Worker side. It needs the worker to run under it. |

The one thing every point shares is the signed policy image and a receipt per decision whose record carries the image hash (`prismpath/agent/run.py`, receipt field `image_sha256`).

## 2. The reading per resource

The classifier (`prismpath/agent/classifier.py`) reads an agent tool call. At a resource the request is not a tool call. PrismPath needs, for each kind of resource, a reading of the request into a finite set of fields that the signed policy decides on. This is the same shape as the verified core (`docs/design/spec-verified-core.md`) and the verified classifier (`docs/design/spec-verified-classifier.md`). The reading is trusted code outside the core. The decision is inside it.

| Resource | What a reading must produce | Finite value sets, for example |
|---|---|---|
| HTTP service | method class, route class (matched against a route table the resource owner signs), whether the body is within a size bound, whether the content type is one the route accepts, a grant scope | `method in {read, write, delete}`, `route in {listed route ids, unknown}` |
| Database | statement class from a parser, tables touched against a list, whether a write has a bounded predicate, row bound | `stmt in {select, insert, update, delete, ddl, unknown}` |
| Package registry | the registry, the package name against a list, the version against a pin, the kind of fetch (metadata, artifact, publish) | `kind in {metadata, download, publish}`, `registry in {listed, unknown}` |
| Bus command | the command id against the vehicle's command dictionary, the argument range, the mode the vehicle is in | already the cFS plan's shape |

Anything the reader cannot place is `unknown`, and the policy refuses or escalates it. The existing readers already work this way (`mcp_map.py`).

Unverified. No reader for HTTP, SQL or registry traffic exists in this repository today. The table above is a proposal.

## 3. Which resource first

Recommendation. Wrap an HTTP and MCP service gateway first, then a package registry channel.

Reasons for the gateway.

- Most of it exists. `mcp_proxy.py` already receives a call, reads it, decides it, receipts it and fails closed. The change is to put it in front of the server as a network service (HTTP and streamable MCP) instead of beside a client on stdio.
- HTTP is the common language of resources, so one reader covers many resources.
- A route table and a method class make a small reading, and a small reading is what the verified core likes.
- It lets us test the thesis. The same policy and the same grant should decide the same request whether a model, a person's browser or a curl script sent it.

Reasons for the package registry second, and why it should not wait long.

- The July 2026 OpenAI and Hugging Face incident's escape path was a package registry proxy. OpenAI said its models, under evaluation, chained vulnerabilities starting with a zero day in internally hosted third party software, and reached Hugging Face production systems (Fortune, 2026-07-21, https://fortune.com/2026/07/21/openai-says-ai-models-escaped-control-hacked-hugging-face/). Press accounts name the software as Artifactory, a package registry cache (Malwarebytes, https://www.malwarebytes.com/blog/news/2026/07/openais-agent-escaped-its-sandbox-during-a-security-test). Forrester's post "An AI Security Facepalm" covers it from the security leader's side (https://www.forrester.com/blogs/an-ai-security-facepalm-openais-evaluation-became-hugging-faces-incident/). Sources differ on the exact vulnerability chain, and I read only search summaries of them, not the full articles. Check the details before quoting any.
- A registry is a channel that every build needs and that is usually allowed out. That makes it the right place to show a narrow channel policy (section 6).
- The reading is small (registry, package, version, kind).

The XDP edge and the cFS app stay as they are. They are the proof the same image decides at very different points.

## 4. Grants as capabilities

Two identical actions from two workers can need different answers. The first design answer is identity, which is the thing the owner said we do not care about. The answer here is a capability. The resource owner signs a grant that is scoped (these routes, these tables, these packages), expiring, and carried with the request. The policy decides the request together with a field that says whether a valid grant covers it.

This is the signed envelope of `~/cwprojects/cc-gate-tracer/DESIGN-envelope.md` used as a capability. That design already has the parts. The owner's signature awards authority. The adopter checks a request falls inside what was awarded. The grant carries its own validity days and the signature is checked on every load, so an expired or unverifiable grant leaves only the base policy in force. Narrowing needs no authority.

What is new here is that the holder presents the grant with each request, and the PEP verifies it against the resource owner's key before the reading is decided. Open points, none designed yet.

- Binding the grant to a request without binding it to an identity. A bearer grant can be stolen, so it needs a short life and a scope narrower than the damage worth doing.
- Revocation before expiry. This is the same open problem as in `policy-distribution.md`.

## 5. Narrow channels

An allowed route out is still a data path. If the policy lets a sandbox reach a package registry, the registry host can carry anything the worker chooses to encode in a package name or a request path. The egress proxy today decides the host and port only (`egress.py`), then relays bytes.

So an allowed proxy needs a policy of its own. For a registry channel that means the proxy terminates the protocol and reads each request. It allows package downloads only, from these registries, for names on a list or matching a pin, with a size bound and a rate bound. It refuses publishes and unlisted names. Where it cannot read the protocol (opaque TLS tunnels), it is a coarse channel and should be treated as one in the receipt.

## 6. What this does not stop

- An exploit riding an allowed request into a bug behind the PEP. If the policy allows `GET /pkg/x` and the server behind has a flaw that `GET /pkg/x` with a crafted header triggers, the PEP allowed an action it was right to allow. The reading narrows what can be sent. It does not fix the server. This is likely close to the 2026 incident's shape, and nothing here claims to stop it.
- A reading that is wrong. The decision is proven. The reading is trusted code. A request the reader maps to the wrong class gets the wrong decision.
- Anything that reaches the resource by a path that does not cross the PEP. A PEP guards the interface it mediates and claims nothing about the others (the North Star, section 9, `~/cwprojects/cc-gate-tracer/NORTH-STAR.md`).
- A stolen grant used inside its scope.

## 7. Work packages

Each is about 30 to 60 minutes of agent time.

**R1. Gateway shell.** Put the decide and receipt path of `mcp_proxy.py` behind an HTTP listener that forwards to one upstream, with the same fail closed rules. Done when a test sends allowed, refused and malformed requests, only allowed ones reach a stub upstream, and every decision has a durable receipt before it is forwarded.

**R2. HTTP reader.** A reader from an HTTP request to the fields in section 2 with a signed route table. Done when a table of at least 40 request cases (including smuggling shapes, duplicate headers and oversized bodies) reads to the expected fields or to `unknown`, and a differential check shows the reader never reads `unknown` input as a listed route.

**R3. Policy and receipts for the gateway.** A rules file over those fields, compiled with the existing compiler, plus the receipt fields. Done when the repository's core evidence verifier accepts a run from the gateway.

**R4. Same request, any worker.** A test where a script, a recorded browser request and an MCP client send the same request and get the same decision and the same receipt content. Done when the test passes and the note records the result as the first evidence for the thesis.

**R5. Grant field.** Verify a signed, scoped, expiring grant at the gateway and expose `grant_scope` as a field. Done when an expired, wrong scope, tampered and revoked grant each give the registered refusal, and the same request with a valid grant is allowed.

**R6. Registry reader and channel.** A reader for npm or PyPI style fetches and a proxy that applies section 5. Done when a stub registry test allows a listed download, refuses a publish, an unlisted name and an oversized response, and logs each.

**R7. Replay of the 2026 shape.** A test harness where a sandboxed worker tries to use an allowed registry channel to reach a non registry host. Done when the harness shows the refusal and states, in its README, the in-bug case of section 6 as out of scope.

**R8. Link and review.** Add this note to `ROADMAP.md`. Done when the roadmap names the packages and an owner has read the recommendation in section 3.

## 8. Links

Linked from `docs/design/enforcement-points-plan.md` section 6. See also `docs/design/policy-distribution.md`.
