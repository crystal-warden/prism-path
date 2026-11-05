# prismpath-hotswap-rs

The secure policy hot swap, natively: Ed25519 signed policy packs, envelope bounded image
validation, and the atomic, audited PolicyHost.

**What it mirrors.** `prismpath/hotswap/policy_pack.py` (the Authorized and Envelope bounded gates) and
`prismpath/hotswap/policy_host.py` (the Attested and Audited and atomic host), per
`docs/design/spec-secure-hotswap.md`. The `.ppt` image is a read only input here as in Python;
nothing in this crate touches the compiler or the image bytes, so the certified hashes stay exactly
what the FPGA and eBPF evidence rows cite.

**What enforces agreement.** A cross language contract gated by `tests/test_hotswap_conformance.rs`
against `prismpath/portable/conformance/hotswap.json`: signatures are Ed25519 over Python's exact
canonical JSON bytes, so a pack signed by either runtime verifies on the other, and every refusal
uses the same stable reason strings the Python tests pin (`sig:missing`, `image:sha256-mismatch`,
`version:not-monotonic`, and the rest). Run `cargo test` in this directory; CI runs the tests and
clippy for this crate.

**What is here.** `src/lib.rs` (pack build and verify), `src/host.rs` (the PolicyHost: verify,
envelope, version floor, stage, atomic flip, one audit event per attempt), and the receipt verifiers
described next.

## Verifying receipts the Python engine produced

Release 0.1.2 signs: a deployment's instance key signs a chained root statement over each audit log,
and the policy authority signs a flow manifest that authorizes a Markdown flow. This crate is the
verify side of both, in Rust, for a consumer that has no Python: it checks what the Python engine
wrote and reports what Python would report, finding for finding. It has no signing path for either
(no key generation, no private key loading for statements or manifests), by design.

| module | mirrors | checks |
|---|---|---|
| `root_statement` | `prismpath/ledgers/root_statement.py` | a statement's form, key id and Ed25519 signature over the domain prefixed canonical bytes; the `prev` chain; leaf counts; the root against the log's leaves; truncation; pinned keys; policy authority keys in the log; one receipt bundle offline |
| `merkle` | `prismpath/ledgers/ledger_ots.py` | the Bitcoin style tree under the log: root, and leaf to root inclusion paths |
| `flow_authority` | `prismpath/hotswap/flow_authority.py` | a flow manifest against the flow (LF normalised hash), the trusted and revoked authority keys, and the version floor |

```rust
use prismpath_hotswap_rs::root_statement::{verify_trail, verify_receipt_bundle};
use prismpath_hotswap_rs::flow_authority::{verify_flow, VersionFloor};

// A log and the statements file beside it (run.audit.jsonl, run.audit.roots.jsonl), pinned to the
// deployment's instance public key (the 32 raw bytes of instance.pub).
let report = verify_trail(&log_text, Some(&statements_text), &[instance_pub.to_vec()]);
assert_eq!(report.status, "signed");          // or "signed-unpinned", "unsigned", "invalid"
println!("{:?}", report.finding_names());     // "root_mismatch", "log_truncated", "chain_broken", ...

// One receipt, self contained (the JSON `prismpath trail LOG --receipt IDX --json` prints).
let verdict = verify_receipt_bundle(&bundle, &[instance_pub.to_vec()])?;
assert!(verdict.ok);

// A flow, its manifest and signature beside it, the authority's public key, the revoked key ids
// and the versions already accepted.
let mut floor = VersionFloor::from_json_str(&floor_text)?;
let verdict = verify_flow(&flow_bytes, Some(&manifest_text), Some(&signature), &[authority_pub.to_vec()], &revoked, Some(&floor));
if verdict.ok { floor.accept(verdict.manifest.as_ref().unwrap())?; }   // then write floor.to_json_string() durably
else { println!("{:?}", verdict.causes); }  // "sig:invalid", "flow:sha256-mismatch", "flow:version-replay", ...
```

`verify_chain` takes the log's root function, so a different log can be checked the same way (the
epoch chain's roots are chained, not a plain Merkle root; pass `ChainOptions { log: "epoch-chain", .. }`
and your own `root_at`). The instance key and the authority key must stay apart: a host calls
`root_statement::check_separation` with its instance key id and the authority key ids before it
signs or runs anything, as Python's `run` does.

**What enforces agreement.** `prismpath/portable/conformance/receipts.json` is a frozen vector set
written by `prismpath/portable/gen_receipt_fixtures.py` from the Python reference (257 cases: the
canonical JSON bytes, the tree, valid and tampered audit trails, receipt bundles, flow manifests, the
version floor, the key separation). It is reproducible byte for byte, `prismpath/tests/test_receipt_vectors.py`
refuses drift and replays it through Python, and `tests/test_receipt_verify.rs` replays it through
this crate and requires every verdict to match. `tests/test_receipt_edges.rs` pins the places this
crate is stricter.

**Where Rust is stricter than Python.** Each fails closed; none can make Rust accept what Python
refuses.

- Signatures are checked with `verify_strict`, so a small order public key is refused. Python
  accepts a signature under one; only a statement carrying such a key in an unpinned check could
  tell the two apart, and a pinned key is never small order.
- A JSON boolean is not an integer (`"seq": true` is `bad_format` here; Python's `isinstance(True,
  int)` lets it through).
- A public key file of the wrong length is skipped in `verify_flow` (Python raises); a signature of the
  wrong length is `sig:invalid` on both.
- A flow that is not UTF-8 is `flow:sha256-mismatch` (Python raises when it reads it). Where Python
  raises on a malformed receipt bundle (a missing field, hashes that are not hex) the Rust function
  returns `Err`.

**Limits of the number reading.** JSON integers beyond the 64 bit range and the literals `NaN` and
`Infinity` are not read as Python reads them (an event holding one is a skipped log line, and a
statement holding one is unreadable, both reported). Floats are written as Python's `repr` writes
them (`prismpath_rs::durable::py_float_repr`), and the crate reads them with serde_json's
`float_roundtrip`, so a receipt's `ts` hashes to the same leaf on both sides.

**What it does not do.** It does not sign, create or load private keys for statements or manifests,
write an audit log or a statements file, check an OpenTimestamps or RFC 3161 anchor, or decide when
a root was signed (the statement's `time` is the signer's clock). The writers in other ports
(telemetry epochs, eBPF receipt sealing, the mesh firmware, the Rust, Go and JavaScript kernels) do
not yet produce root statements; see the changelog.

**Related.** The `prismpath swap` command drives the Python side of the same contract;
`prismpath-hw/` and `prismpath-ebpf/` consume the images this host activates.
