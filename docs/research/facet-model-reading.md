# Can a model read a Facet stream?

Generated 2026-11-20. Data in `results/facet_model_reading_2026-11-20.json` (every run, with its answer and tool calls). Code in `tools/facet_model_tools.py` (the two tools), `tools/facet_model_reading.py` (the harness) and `tools/facet_model_summarize.py`.

## The question

A Facet stream has no header, no field tags and no codebook (PROTOCOL.md 2.1). Both ends derive the codebook from the same signed policy. So a reader that holds only the stream cannot know what it says. The question is how much of that gap a model can close, and what closes it.

## Method

The model is the local Gemma 4 31B on vLLM, temperature as the server sets it, at most four requests at once.

Three policies of different size. `fusion_triage.md` (the SIEM fusion policy, 4 fields, 108 cells, decision node `correlate`, 7 outcomes), `demo_input.md` (1 field, 3 cells, 3 outcomes) and `intent_calls.core.json` from governed_intent (18 fields on the wire, 16 outcomes). Streams of 1, 8 and 64 readings. Each stream is built by drawing a cell for every field, encoding with `wire.encode_reading`, packing with `packed.pack`, and taking the policy's own route for the decision. Ground truth is exact. Five streams per policy and length, and the same five streams are used in every condition. That is 45 runs per condition, 1,095 readings.

The three conditions.

- A. The hex, and the question "what does this say?". Nothing else.
- B. The hex, the signed policy text (the flow, or the core image rendered back to rules), and a short statement of the wire rules and how cells are cut. No tools. The model must decode by hand, with no scratch work, because the answer format asks for JSON only.
- C. The hex, an out of band binding (`facet/1`, policy sha256, epoch) and two tools, `facet_describe(policy_hash)` and `facet_decode(stream_hex, policy_hash)`. The tools are Python on the existing codec. `facet_decode` returns each reading as named cells plus the decision. Both refuse a hash that is not the session's binding, and `facet_decode` refuses a stream that does not fit the codebook (a symbol count that is not a whole number of readings, a leftover that is not zero padding, a symbol outside its field).

All three answer in the same JSON: the field order, one entry per reading with a cell index for each field and a decision, and an `error` for when it cannot read. A reading scores "cells correct" when every cell index matches and "decision correct" when the decision matches. An invented field is a name in the answer that the policy does not have. An invented decision is an outcome the decision node cannot produce.

Tamper tests in C, eight readings each, five per policy. A detectable flip is one bit chosen from those the codec refuses. A silent flip is one bit chosen from those it still decodes. A wrong hash gives the model a binding that names another shipped policy while the session is bound to the true one.

One departure from the brief. The served vLLM returns Gemma's native call text (`<|tool_call>call:facet_decode{...}`) in the message rather than parsed `tool_calls`, so it has no tool parser enabled. The harness reads that text, runs the tool, and returns the result as a user message. The model is making real structured calls, but it is not the server's function calling path.

## Results

Per cell, five runs. Cells and decisions are the percent of readings correct. Tokens are means per run (prompt / completion).

| Policy | Readings | A cells / decision | B cells / decision | C cells / decision | C tokens |
|---|---|---|---|---|---|
| demo_input (1 field) | 1 | 0 / 0 | 0 / 0 | 100 / 100 | 2140 / 209 |
| demo_input | 8 | 0 / 0 | 5 / 5 | 100 / 100 | 2251 / 302 |
| demo_input | 64 | 0 / 0 | 6.9 / 6.9 | 100 / 100 | 4978 / 1112 |
| fusion_triage (4 fields) | 1 | 0 / 0 | 0 / 40 | 100 / 100 | 2432 / 243 |
| fusion_triage | 8 | 0 / 0 | 0 / 5 | 87.5 / 87.5 | 2976 / 438 |
| fusion_triage | 64 | 0 / 0 | 0 / 1.9 | 99.7 / 100 | 8945 / 2015 |
| intent_calls (18 fields) | 1 | 0 / 0 | 0 / 0 | 100 / 100 | 3585 / 373 |
| intent_calls | 8 | 0 / 0 | 0 / 0 | 95 / 100 | 6830 / 957 |
| intent_calls | 64 | 0 / 0 | 0 / 0.3 | 28.1 / 75 | 17182 / 5208 |
| All | 1,095 | 0 / 0 | 2.2 / 2.2 both | 78.3 / both | |

A and B cost little because they say little. A used about 150 completion tokens per run and B about 310, against about 1,200 for C, whose prompt also carries the tool results. C buys correctness with tokens.

A abstained in 44 of 45 runs. In the other it began to answer with made up temperature, humidity and pressure fields and ran into the token cap, so it did not parse. Invented content in A is therefore 1 run in 45 and it is total invention. B named invented fields in 45 runs but see below. Neither A nor B produced an invented decision.

Tamper tests in C, five runs each.

| Test | Policy | Tool refused | Answer gave no readings and reported the reason | Readings right against the original |
|---|---|---|---|---|
| Detectable flip | all three | 15 of 15 | 15 of 15 | 0 of 120 |
| Wrong hash | all three | 15 of 15 | 15 of 15 | 0 of 120 |
| Silent flip | fusion_triage | 0 of 5 | 0 of 5 | 15 of 40 |
| Silent flip | intent_calls | 0 of 5 | 0 of 5 | 33 of 40 |
| Silent flip | demo_input | no such flip exists | | |

Every refusal was relayed faithfully. No run decoded around a refusal or guessed. The silent flips are the weak point and they are not the model's fault. Over every single bit flip of the streams used, the codec alone refuses 92 to 99 percent for fusion_triage, 100 percent for demo_input and 88 to 89 percent for intent_calls (`single_bit_flip_detection` in the results file). The rest still decode to valid symbols, the tool returns them without complaint, and the model reports them as fact. The stream has no integrity check of its own. That is the epoch Merkle root's job, and the tools do not check it.

## Failures

B reads the policy and then guesses. For eight fusion readings it returned a single reading, cells `[2,1,0,1]` with decision `coincident_critical`, none of it right. Hand decoding a Fibonacci bit stream, then cutting the cells from the conditions, then routing, is more than the model does in one pass. The 40 percent decision score at one reading is what guessing among seven outcomes gives.

B also lists `classifier_version` and two other fields for intent_calls. The policy header declares them, but nothing routes on them, so they have no cells and are not on the wire. This is where the 45 "invented fields" come from. They are the model trusting the header, not fabrication, but they would shift every later cell in a reader that believed them.

C fusion, eight readings, one run: the model returned three readings of eight. It decoded all eight through the tool and dropped five while copying the result into its answer.

C intent_calls, 64 readings, is the clear failure. The tool result is about 16,000 prompt tokens and the model must copy 64 readings of 18 fields back out, about 5,000 tokens. Decisions came out 53 to 91 percent right (75 percent over the five runs) and cells only 28 percent. In three of five runs the model never called `facet_describe`, so it had cell meanings such as "7299 or less" with no indices, and it numbered them from its own guess. All 18 fields times 64 readings of cell indices were wrong in those runs.

## What this says

A model given only the stream cannot read it and says so. That is the right answer to the question as posed. The model given the policy text and the wire rules cannot decode by hand. Neither failure is a surprise. The codebook is derived, and a model does not derive it reliably.

A model with the two tools reads short streams perfectly, and the refusals are honest. Its mistakes come from copying long tool output into an answer, and from tool results that name cells without numbering them.

## Recommendation

Build a Facet MCP server with these two tools. It works, it refuses a wrong hash and a malformed stream every time, and the model passes the refusal on. The alternative of giving a model the policy and asking it to decode is not a usable path.

Three changes before it ships.

1. Put the cell index in `facet_decode` output next to each label, and return a compact form for long streams (cell indices in canonical order, plus decisions), so the model does not have to number cells itself or copy named cells.
2. Add a summary mode that returns the decision distribution for a stream, since a model asked about 64 readings usually wants counts and exceptions, not 64 transcribed rows.
3. Do not present a decode as authentic. A silent flip decodes. The server should take the epoch Merkle proof or root as an argument and report it checked or unchecked, and the model prompt should say which.

Limits of this experiment. One model. Five streams per cell. B had no scratch space, so a reasoning model with room to work could do better on short streams, though not on 64 readings of 18 fields. The wrong hash test uses another shipped policy's hash, and the session pin is held by the server, so the model cannot learn the true hash by itself.
