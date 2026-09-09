# prismpath-hotswap-rs

The secure policy hot swap, natively: Ed25519 signed policy packs, envelope bounded image
validation, and the atomic, audited PolicyHost.

**What it mirrors.** `prismpath/policy_pack.py` (the Authorized and Envelope bounded gates) and
`prismpath/policy_host.py` (the Attested and Audited and atomic host), per
`docs/design/spec-secure-hotswap.md`. The `.ppt` image is a read only input here as in Python;
nothing in this crate touches the compiler or the image bytes, so the certified hashes stay exactly
what the FPGA and eBPF evidence rows cite.

**What enforces agreement.** A cross language contract gated by `tests/test_hotswap_conformance.rs`
against `prismpath/portable/conformance/hotswap.json`: signatures are Ed25519 over Python's exact
canonical JSON bytes, so a pack signed by either runtime verifies on the other, and every refusal
uses the same stable reason strings the Python tests pin (`sig:missing`, `image:sha256-mismatch`,
`version:not-monotonic`, and the rest). Run `cargo test` in this directory. This crate is a workspace
member but is not yet in the CI matrix.

**What is here.** `src/lib.rs` (pack build and verify), `src/host.rs` (the PolicyHost: verify,
envelope, version floor, stage, atomic flip, one audit event per attempt).

**Related.** The `prismpath swap` command drives the Python side of the same contract;
`prismpath-hw/` and `prismpath-ebpf/` consume the images this host activates.
