# prismpath-hotswap-rs

The secure policy hot swap, natively: Ed25519 signed policy packs, envelope bounded image
validation, and the atomic, audited PolicyHost. `DIVERGENCES.md` at the repository root lists the places
where it answers differently from the Python host on purpose.

**What it mirrors.** `prismpath/hotswap/policy_pack.py` (the Authorized and Envelope bounded gates) and
`prismpath/hotswap/policy_host.py` (the Attested and Audited and atomic host), per
`docs/design/spec-secure-hotswap.md`. The `.ppt` image is a read only input here as in Python;
nothing in this crate touches the compiler or the image bytes, so the certified hashes stay exactly
what the FPGA and eBPF evidence rows cite.

**What enforces agreement.** A cross language contract gated by `tests/test_hotswap_conformance.rs`
against `tests/fixtures/hotswap.json`, a byte identical copy of `prismpath/portable/conformance/hotswap.json`: signatures are Ed25519 over Python's exact
canonical JSON bytes, so a pack signed by either runtime verifies on the other, and every refusal
uses the same stable reason strings the Python tests pin (`sig:missing`, `image:sha256-mismatch`,
`version:not-monotonic`, and the rest). Run `cargo test` in this directory; CI runs the tests and
clippy for this crate.

**What is here.** `src/lib.rs` (pack build and verify), `src/host.rs` (the PolicyHost and the audit
log: verify, envelope, version floor, stage, then the commit in the reference's order, intent record,
floor, audit event, the new image `active-<sha256>.ppt`, the record naming it, clean up; a rollback commits the same way;
a fresh host restores the active policy and records an interrupted commit; every audit event is fsynced before it has a leaf and a
write that fails is an `AuditWriteError`). The host trace corpus `tests/fixtures/host_trace.json`
is generated from the Python host, `tests/test_host_trace.rs` replays it byte for byte,
`tests/test_host_crash.rs` stops a swap and a rollback before each step, and `tests/test_host_cross_language.rs`
has each runtime open the other's state directory.
The receipt verifiers described next sit beside the host.

## Verifying receipts the Python engine produced

Release 0.1.2 signs: a deployment's instance key signs a chained root statement over each audit log,
and the policy authority signs a flow manifest that authorizes a Markdown flow. This crate is the
verify side of both, in Rust, for a consumer that has no Python: it checks what the Python engine
wrote and reports what Python would report, finding for finding. It has no signing path for either
(no key generation, no private key loading for statements or manifests), by design.

| module | mirrors | checks |
|---|---|---|
| `root_statement` | `prismpath/ledgers/root_statement.py` | a statement's form, key id and Ed25519 signature over the domain prefixed canonical bytes; the `prev` chain; leaf counts; the root against the log's leaves; truncation; pinned keys; policy authority keys in the log; one receipt bundle offline |
| `merkle` | `prismpath/ledgers/ledger_ots.py` | the RFC 6962 tree under the log (`prismpath_rs::merkle`): root, and leaf to root inclusion paths |
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
written by `prismpath/portable/gen_receipt_fixtures.py` from the Python reference (245 canon/2 cases, among them
the refusals of what canon/1 wrote, which is retired and has no twin: the
tree, valid and tampered audit trails, receipt bundles with 0.1.3's checks (`status`, `index`, `covered`, and the `problem` for a malformed bundle), flow manifests, the
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
- A flow that is not UTF-8 is `flow:sha256-mismatch` (Python raises when it reads it).

A receipt bundle that is not shaped like one is no longer a difference: as 0.1.3's Python does, the
Rust function returns an `invalid` result with the same `problem` text (`bundle_problem`) and no
`Err`. `Err` is left for the cases where the reference still raises, a statement whose `key_id` is not
text, or is a list or object while a key is pinned.

**The number reading.** Documents are read as `prismpath.canon.loads_document` reads them: the literals
`NaN` and `Infinity` and a number beyond the double range are refused (an event holding one is a skipped log
line, a statement holding one is unreadable, and a manifest holding one is `manifest:bad-format`, all
reported), and a document that names canon/2 is read by the strict canon/2 reader as well, which refuses any
float, a duplicate key and an integer beyond plus or minus 2^53 minus 1. A canon/2 document is hashed over
its canon/2 bytes (`prismpath_rs::durable::document_bytes`). A document without the tag is canon/1, which is
retired: it is not read, hashed or verified (an untagged log line is skipped and the log no longer verifies,
an untagged statement is `bad_format`, an untagged manifest is `manifest:bad-format`).

**What it does not do.** It does not sign, create or load private keys for statements or manifests,
write an audit log or a statements file, check an OpenTimestamps or RFC 3161 anchor, or decide when
a root was signed (the statement's `time_us` is the signer's clock). The writers in other ports
(telemetry epochs, eBPF receipt sealing, the mesh firmware, the Rust, Go and JavaScript kernels) do
not yet produce root statements; see the changelog.

## Policy distribution

`src/dist/` is the Rust side of `docs/design/spec-policy-distribution.md`, mirroring
`prismpath/distribution/`. `dist::envelope` reads and writes the distribution envelope and the sealed
container (signatures first, each an Ed25519 signature over the DSSE encoding of the envelope bytes),
and computes the envelope and release ids. `dist::trust` is the trust store and its durable file, and
`dist::verify::verify` is the one verifier, rules V2 to V11 in order, the first failure the only cause.
The kind table and each artifact's own check are in `dist`. Every document derives the one canon/2 serde
reader and writer of `prismpath_rs::canon2::codec`, so its field list is its member list.

```rust
use prismpath_hotswap_rs::dist::{trust::TrustStore, verify::{verify, PepView}, TargetKind};

let trust = TrustStore::load("state/trust.store");          // unreadable counts nothing (K1)
let mut pep = PepView::new(TargetKind::Host, "host/demo")?;
pep.qualification = Some(qualification_envelope);           // the envelope images are admitted under
let verdict = verify(&sealed, &body, &trust, &pep, now_unix_seconds);
match verdict.cause { None => { /* stage it, and keep verdict.time_floor durable */ }
                      Some(cause) => println!("{cause}") }  // "dist:seq-replay", "sig:invalid", ...
```

`tests/test_distribution_conformance.rs` replays `tests/fixtures/distribution.json`, a byte identical
copy of the corpus the Python verifier wrote, and gives every case that runs on Rust its own test. Each
must report the cause, the unchanged flag, the time floor and the envelope id Python recorded, and the
Rust writers must give back the corpus's bytes, the containers the Python writer sealed with the fixed
test keys included.

**Related.** The `prismpath swap` command drives the Python side of the same contract;
`prismpath-hw/` and `prismpath-ebpf/` consume the images this host activates.
