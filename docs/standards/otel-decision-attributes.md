# Decision attributes for OpenTelemetry GenAI tool calls

*A proposal, 2026-11-16. Status: drafted in this repository, not yet raised with OpenTelemetry. It is the second step of making PrismPath's cause codes usable outside PrismPath, after the crosswalk in [`cause-crosswalk.json`](cause-crosswalk.json).*

## The gap

The OpenTelemetry GenAI semantic conventions, now in their own repository (`open-telemetry/semantic-conventions-genai`) with every attribute at status Development, describe an agent's tool call: its name (`gen_ai.tool.name`), its id (`gen_ai.tool.call.id`) and, where privacy allows, its arguments and result. They have no attribute for the question a governed agent answers before the call runs, whether a policy allowed it, refused it or sent it to a person, and why. Observability write ups of 2026 and the Kubernetes agentic networking observability proposal point at the same gap. Every product that governs tool calls today reports its decisions in its own words.

## The proposal

One set of attributes on the tool call's span, or on an event recorded before the call runs, under `gen_ai.tool.call.decision`.

| attribute | type | meaning |
|---|---|---|
| `gen_ai.tool.call.decision.outcome` | string | `allow`, `deny` or `ask`: the call ran, did not run, or was put to a person |
| `gen_ai.tool.call.decision.decider` | string | what decided, e.g. `prismpath.core/1` |
| `gen_ai.tool.call.decision.cause.code` | int | the registered cause of a `deny` or an `ask`, absent on `allow` |
| `gen_ai.tool.call.decision.cause.name` | string | the cause's registered name, e.g. `agent:outside-workspace` |
| `gen_ai.tool.call.decision.cause.class` | string | the cause's registered class |
| `gen_ai.tool.call.decision.cause.registry` | string | the sha256 of the cause registry the code is from, so a code is never read against another registry |
| `gen_ai.tool.call.decision.receipt.index` | int | where the decision sits in its signed record, when one is kept |
| `gen_ai.tool.call.decision.receipt.run` | string | the record (session or run) the receipt belongs to |
| `gen_ai.tool.call.decision.policy.sha256` | string | the digest of the policy that decided |

The outcome needs no registry and is useful alone. The cause attributes are where a shared registry matters: a code means one thing everywhere only if its registry is named, which is why the registry digest travels with it. The receipt attributes let a trace point at evidence anyone can verify offline, without putting that evidence in the trace.

## In PrismPath

`prismpath/agent/otel.py` produces these attributes for each decision as a plain dict, with no OpenTelemetry dependency. Until the names are adopted it uses `prismpath.decision.*`, a namespace of its own as OpenTelemetry advises for names it has not adopted, and the same values under the proposed names on request, so a backend can map one onto the other.

## What it does not do

It does not record the person's answer to an `ask`; that belongs to the client that asked. It does not carry the call's arguments, which the GenAI conventions already treat as opt in content. It says nothing about whether the decision was right; that is what the receipt and its replay are for.

## Next

Raising it is the maintainer's step: an issue in `open-telemetry/semantic-conventions-genai` with this table, and the same text to the OWASP GenAI Security Project and the Coalition for Secure AI under OASIS, which work on the agent risks these causes map to. The cause registry itself (`docs/design/spec-cause-codes.md`, section 4.1 on registration) is what a shared registry would start from.
