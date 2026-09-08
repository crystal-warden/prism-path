# Comparator toolchain (Phase 1, installed 2026-09-08)

*Phase 1 of `PREREGISTRATION.md` section 10. Every comparator is installed at a pinned version
into the gitignored `prismpath/comparisons/.toolchain/` by `toolchain/install.sh`, each download
verified against the checksum its project published, and every binary answers one trivial decision
in `toolchain/smoke.sh`. Nothing here touches the corpus; translators are Phase 2. These are the
exact `system_version` strings result files must carry.*

## Host

| item | value |
|---|---|
| machine | gx10-f60f (the GX10 dev station) |
| arch | aarch64 |
| kernel | 6.17.0-1032-nvidia |
| cargo | cargo 1.97.1 (c980f4866 2026-06-30) |
| installed | 2026-09-08T17:17:19Z |

## Pins and checksums

| system | system_version | source | published sha256 (artifact) | installed binary sha256 |
|---|---|---|---|---|
| opa | 1.20.2 | github.com/open-policy-agent/opa release v1.20.2, `opa_linux_arm64_static` | 431bed5a365578241ab06c7cc1c7d0cdff8c11dcbc6f12c3488590deb8b8d66d | 431bed5a365578241ab06c7cc1c7d0cdff8c11dcbc6f12c3488590deb8b8d66d |
| cedar | 4.12.0 | crates.io `cedar-policy-cli` 4.12.0, `cargo install --locked` (cedar-policy 4.12.0) | crates.io registry, cargo verifies the crate checksum | d8903c786ccadc3b4f289f1ee39a5ba1e246c56272e4754d83421355c3ed5aa4 |
| cerbos | 0.55.0 | github.com/cerbos/cerbos release v0.55.0, `cerbos_0.55.0_Linux_arm64.tar.gz` | 838c9d1339a69e078fccb1f30e5bfd85662c3b3b6d42a142c336bb34d1e5e3a3 | 93aa51dddc0de4881039622fd75d989abc57fd65cd5703dbb812f26918336870 |
| cerbosctl | 0.55.0 | same release, `cerbosctl_0.55.0_Linux_arm64.tar.gz` | 4544d02d20e01fb9a915ce62f7b46f4243adea6dd5236095ce79411c9f139ef0 | 7faf53be8b8adea38abaabe7a3ed57bea480640960f0ac961c04b5ba8190a0ab |
| openfga | 1.19.0 | github.com/openfga/openfga release v1.19.0, `openfga_1.19.0_linux_arm64.tar.gz` | 067e09ef5f1894e4f292bcc265da0063e7d6d763f2eb53cdebc8c3337adf0f64 | 68123b0d40e38b9e17668355fbabe6474b865012ed0f1be8e4c0c342702ca9de |
| cedarpy (Python binding, in process Cedar for A7) | 4.8.7 | PyPI `cedarpy` 4.8.7 installed into `./.venv` in Phase 3 (pip, wheel verified by pip); the Cedar CLI stays the Phase 2 translator target | pip resolved | n/a |
| openlane | docs only | graded from documentation and API surface in Phase 4; nothing installed by design (PREREGISTRATION section 3) | n/a | n/a |

Each was the latest stable release of its project on the install date (release dates: OPA
2026-09-03, Cedar 2026-07-28, Cerbos 2026-08-13, OpenFGA 2026-08-25). The Cerbos and OpenFGA
releases also ship sigstore signatures over their checksum files; the installer verifies the
sha256 only, and that limitation is stated rather than implied.

Phase 3 addition: `cedarpy` 4.8.7 gives Cedar an in process embedding so the A7 latency measurement compares
libraries where a library exists; the CLI remains the idiomatic translation target from Phase 2.

## Smoke (`toolchain/smoke.sh`, output verbatim)

```
== opa
Version: 1.20.2
Build Commit: b2c26708e9d55645d7f837db495031f7e4152594-dirty
Platform: linux/arm64
eval port=443 -> allow
eval port=23  -> deny
== cedar
cedar-policy-cli 4.12.0
authorize port=443 -> ALLOW (exit 0 = ALLOW, exit 2 = DENY)
authorize port=23  -> DENY
== cerbos
0.55.0
Build timestamp: 2026-08-13T08:04:59Z
health -> {"status":"SERVING"}
check port=443 -> EFFECT_ALLOW
check port=23  -> EFFECT_DENY
== openfga
2026/09/08 12:16:25 OpenFGA version `v1.19.0` build from `130c30aea5e73543e63b173dadfbd1ee519aa97a` on `2026-08-25T14:48:10Z` 
health -> {"status":"SERVING"}
check bob viewer doc:d2   -> true
check alice viewer doc:d2 -> false
```

## Observations recorded now, before any translator exists

- The Cedar CLI signals the decision in its exit code as well as its output: ALLOW exits 0, DENY
  exits 2 and prints a leading blank line. A runner must read the text, not the exit status alone.
- Cedar `authorize` requires `--entities` even when the request needs none (an empty list file).
- Cerbos and OpenFGA are servers; the smoke drives them over loopback HTTP on non default ports
  (3592/3593 and 8090/8091). Their in process embeddings do not exist for Python, which A7 will
  record as a transport cost, not hide.
- OPA is a static binary and evaluates in process via `opa eval`; a server mode also exists. Its
  Python side (WebAssembly bundles, `opa build -t wasm`) is the A3 attempt and is not installed
  here.
- Client libraries and language bindings for the runners (for example `cedarpy`, the Cerbos and
  OpenFGA Python SDKs) are a Phase 2 decision, pinned in that phase's own record when chosen.

## Reproduce

```bash
bash prismpath/comparisons/toolchain/install.sh     # pinned, checksum verified, idempotent
bash prismpath/comparisons/toolchain/smoke.sh       # one trivial decision per system
./.venv/bin/python -m pytest prismpath/tests/test_comparisons_toolchain.py -q
```
