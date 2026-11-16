# Rust lockfiles and minimum versions

The repository holds one Cargo workspace and three standalone crates, and a lockfile is committed
wherever a build has to be reproducible. The rule is one lockfile per build root, and no lockfile
anywhere else.

## The policy

| build root | what it builds | lockfile |
|---|---|---|
| `Cargo.toml` at the repository root | the workspace members `prismpath-rs`, `prismpath-telemetry-rs`, `prismpath-hotswap-rs` and `prismpath-preflight`, which the CI jobs and the cross language tests build together, and the preflight binary | `Cargo.lock`, committed |
| `prismpath-reflect-bindings` | a test harness that is its own workspace, since it pulls a release candidate of `facet` the members must not inherit | `prismpath-reflect-bindings/Cargo.lock`, committed |
| `integrations/vector/facet-sink` | a binary that is its own workspace | `integrations/vector/facet-sink/Cargo.lock`, committed |
| `prismpath-ebpf/collector` | the collector, a binary that is its own workspace because it sits with the kernel target the export holds back, resolved to the same releases as the root lockfile | `prismpath-ebpf/collector/Cargo.lock`, committed |

A workspace member never carries a lockfile of its own, because Cargo ignores it and reads the root
one, so a second copy only drifts. Rust guidance for libraries is that a lockfile does not bind the
people who depend on the crate, and that holds here: `prismpath-rs` and `prismpath-telemetry-rs` are
libraries, their consumers resolve their own versions, and the root `Cargo.lock` exists for this
repository's own CI and for the preflight binary, not as a statement to downstream users.

## Minimum supported Rust version

`prismpath-rs`, `prismpath-telemetry-rs` and `prismpath-preflight` declare `rust-version = "1.82"`,
the release that stabilised `Option::is_none_or`, the newest standard library call their sources use.
`prismpath-hotswap-rs` declares 1.85, because the committed `Cargo.lock` resolves `ed25519-dalek`'s
`zeroize` and `base64ct` to releases written in edition 2024. The `msrv` job in
`.github/workflows/ci.yml` builds each group at its declared version with `--locked` and fails if the
manifest declares anything else, so raising a floor means changing the manifest and the job together.
The three standalone crates declare no `rust-version` and are built only with the stable toolchain.

## Changing a lockfile

Update a lockfile on purpose, in a commit that says so (`cargo update -p <crate>`), and rebuild the
`msrv` job's crates afterwards, since a dependency release can raise the floor the lockfile implies.
