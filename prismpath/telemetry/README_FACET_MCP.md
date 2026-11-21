# The Facet MCP server

A Facet stream has no header, no field tags and no codebook. This server lets a model (or any MCP client) read one
through the signed policy that defines the codebook.

```
python -m prismpath.telemetry.facet_mcp --registry DIR --authority-pub PUB [--authority-pub PUB2] [--revoked LIST] [--pin POLICY_SHA256]
```

It speaks newline delimited JSON-RPC on standard input and output, reusing the line parser of
`prismpath/agent/mcp_proxy.py`. It answers `initialize` and `server/discover`, `tools/list`, `tools/call` and `ping`.
It adds no dependency; checking a signature needs the `signing` extra (`cryptography`) as the pack machinery does.

## The registry

`DIR` holds signed policies, found by the sha256 of the policy file.

| Policy | Signature |
|---|---|
| a flow `NAME.md` | `NAME.md.manifest.json` and `.sig`, as `prismpath swap`/`flow_authority.sign_flow` write them |
| a core image `NAME.core.json` | `NAME.core.json.attest`, written by `facet_mcp.sign_image` (Ed25519 over `core_evidence.IMAGE_DOMAIN` and the image's canon/2 bytes) |

The trusted authority key is named on the command line (or `PRISMPATH_AUTHORITY_PUB`), never taken from the registry.
A policy with no signature, a signature no trusted key makes, a revoked key, or content changed after signing is not
served, and the refusal names the registry cause (`sig:missing`, `sig:invalid`, `sig:revoked-key`,
`flow:sha256-mismatch`). A hash no signed policy has is refused as unknown. The directory is re-read on every call.
`--pin` binds the session to one policy, so another signed policy's hash is refused as a mismatch.

## The tools

| Tool | Returns |
|---|---|
| `facet_describe(policy_hash)` | every field in canonical order, every cell with its 0-based index and meaning, the decision node, its possible decisions and default |
| `facet_decode(stream_hex, policy_hash, format?, epoch_root?, block_bits?, epoch_blocks?)` | each reading with the index of every field in canonical order and the decision. `format: "compact"` gives only `{"cells": [...], "decision": "..."}` per reading |
| `facet_summary(stream_hex, policy_hash, decision?, limit?, epoch_root?, block_bits?, epoch_blocks?)` | the decision distribution, the cells that appear in each field with counts, and the exception readings: those with the decision you name, or every decision other than the policy's default (the most frequent decision when the policy has no default edge) |

A refusal is a tool result with `isError: true` and `{"error": "refused", "reason": ...}`. Nothing is decoded around a
refusal: an unknown or unsigned policy, a hash other than the pinned one, a stream that does not fit the codebook
(a symbol count that is not a whole number of readings, non zero padding, a symbol outside its field) and a root
mismatch.

## Integrity

The stream has no check of its own, and a bit flip can still decode to valid symbols. The epoch's Merkle root is the
check (`telemetry/epochs.py`, `selfheal.commit`, an RFC 6962 tree over sha256 of each block's bit string).

- `epoch_root` and `block_bits`: the stream is the epoch. Its transmitted bits, padding included, are cut into blocks
  of `block_bits` and the root recomputed.
- `epoch_root` and `epoch_blocks`: the epoch's blocks as bit strings must hash to the root and be the bits of the
  stream.

Every `facet_decode` and `facet_summary` answer carries `"integrity": "checked"` or `"unchecked"`. With no root it
says `unchecked` and why, in `integrity_note`. A root that does not match is refused, and no readings come back.
Chained roots (`epochs.chain_root`) are not taken yet.

Results with Gemma 4 31B are in `docs/research/facet-model-reading.md`. Tests are in `telemetry/tests/test_facet_mcp.py`.
