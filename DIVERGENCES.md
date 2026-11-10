# Where the Rust crates differ from the Python reference

Python is the reference. Each line is a place where a Rust crate answers differently on purpose, with the reason, and the test that holds the difference. Anything not listed is held to Python by a frozen corpus or a cross language test, and a difference there is a defect.

| Place | Python | Rust | Why, and where it is held |
|---|---|---|---|
| The host's `active_unreadable` event for a record that cannot be read | the text is the JSON decoder's | the text is the Rust error's, and a number beyond the double range is worded `1e+400` | the wording is a library's, not the protocol's; `prismpath-hotswap-rs/tests/test_host_corners.rs` |
| A verified manifest whose `version` is not an integer | raises, or compares by Python's rules | `HostError::BadManifest`, nothing changed | the same; `test_host_corners.rs` |
| `PolicyHost.anchor_attestations` | stamps the leaves with the external `ots` program | absent | the crate drives no process; the Merkle root and every proof are there |
| An error a worker returns as a plain message | the flow's `error_type` is the exception's class name | the kind `Error`; a `WorkerError` names its own kind | a Rust closure has no exception class; `prismpath-rs/tests/test_engine_cross_language.rs` |
| An integer of the Facet wire, a receipt field or a reading beyond 64 bits | read at any width | `ReceiptError::Overflow` or `ConcentratorError::Overflow`, and a stream id beyond 64 bits is an unknown stream | the wire fields are `u64`; the corpora list such a case under `wide` and `prismpath-telemetry-rs/tests/test_cross_language.rs` holds it |
| An integer literal beyond 2^53 minus 1, or a float beyond the double range, in a flow's predicates | the contract is derived | `derive_contract` returns an error | no engine holds the number exactly; `prismpath-rs/tests/test_contract.rs` |
| The digits of other scripts, and an integer beyond 64 bits, in `PRISMPATH_MAX_FLOW_BYTES`, `PRISMPATH_MAX_NODES`, `PRISMPATH_MAX_EDGES` | `int()` reads them | refused | the corpus holds the strings both read alike; `prismpath-rs/tests/test_parse_limits.rs` |
| The receipt verifiers | read what Python reads | refuse a small order key, a boolean for an integer, a flow that is not UTF-8 | the list is in `prismpath-hotswap-rs/README.md`; each fails closed and none accepts what Python rejects |
| The private test keys of a core run (`core_evidence produce --keys`) | PKCS8 PEM, as `swap keygen` and `ledger keygen` write them | the raw 32 byte seed, as the hot swap crate's `keygen` writes it | each language signs with its own key files; a run holds only the raw 32 byte public keys, which are the same format, and each verifier checks the other's run (`prismpath/tests/test_core_evidence.py`) |
| The Rust core run verifier | checks signatures with `cryptography` | `verify_strict` | it also refuses a small order key or signature, as the receipt verifiers do; no honest key is affected (`prismpath/tests/test_core_evidence.py`) |
| `prismpath-preflight --privacy` | measures aggregation privacy, the decision-relevant field combinations a frame hides | the option is not accepted, the report has no privacy section | not yet ported; the JSON report is identical to Python's without it (`prismpath-preflight/tests/e2e.rs`) |
| The preflight Markdown report | a mismatch line shows the reading with `json.dumps` spacing, and the reasons of one line in Python's order | the reading in compact JSON and the reasons in Rust's own order | cosmetic, the JSON report is identical |
