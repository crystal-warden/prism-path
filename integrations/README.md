# integrations

Deliver a signed PrismPath policy anywhere, and carry its decisions as a tiny, tamper evident wire. Every path below runs with the real `zarf`, `uds`, and `vector` binaries and the PrismPath toolchain. Nothing here is mocked, and all three share one signed Level M policy (`adapters/fusion/flows/fusion_triage.md`).

| Path | What it shows |
|------|---------------|
| [`zarf/`](zarf) | Zarf delivers a signed policy and its CycloneDX SBOM (from the compliance emitter, `adapters.compliance.emit --pack-sbom`); on arrival it is verified, envelope bounded, and atomically swapped. A tampered policy fails the deploy closed. Zarf's own SBOM catalogs software packages and finds none in a policy, which is why the emitter describes the pack from its signed manifest. |
| [`zarf-kernel/`](zarf-kernel) | Delivery through to activation: the same signed policy is verified and swapped, then the host's accepted copy is hashed against the attestation and loaded into the in-kernel evaluator, whose path for a probe reading must equal the host reference. The receipt is `deployed/activation.json`. A tampered package stops at verification, and a copy swapped on disk after acceptance is refused before the kernel is touched. Needs a built `prismpath-ebpf` and CAP_BPF. |
| [`uds/`](uds) | The same policy composed as a UDS bundle: `uds create`, then `uds deploy`. |
| [`vector/`](vector) | Facet as a native Vector codec, both directions: `encoding.codec = "facet"` on a sink, `decoding.codec = "facet"` on a source, about 2 bytes per event framed. [`CANARY.md`](vector/CANARY.md) is the migration recipe: fan one source to your existing sink plus a Facet sink, prove route parity with `canary_verify.py`, then cut over. The standalone `facet-sink` simulator adds the Merkle committed wire that self heals across a degraded link. |

## Run it

```sh
# Zarf: sign, deliver, verify, swap (files land in ./deployed; see the tamper case fail closed)
cd zarf && ./build.sh
zarf package create . --confirm && zarf package deploy zarf-package-*.tar.zst --confirm
cd ../zarf-tampered && zarf package create . --confirm && zarf package deploy zarf-package-*.tar.zst --confirm   # aborts: fail closed

# Kernel: delivery through activation (needs a built prismpath-ebpf and CAP_BPF, here through sudo)
cd ../zarf-kernel && PRISMPATH_EBPF=$PWD/../../prismpath-ebpf ./build.sh
PRISMPATH_EBPF=$PWD/../../prismpath-ebpf zarf package create . --confirm && PRISMPATH_EBPF=$PWD/../../prismpath-ebpf zarf package deploy zarf-package-*.tar.zst --confirm
cat deployed/activation.json
cd tampered && zarf package create . --confirm && zarf package deploy zarf-package-*.tar.zst --confirm   # aborts at verify; activation never runs
cd ..

# UDS: the same package as a bundle (run the Zarf build above first)
cd ../uds && uds create . --confirm && uds deploy uds-bundle-*.tar.zst --confirm

# Vector, step 0: will YOUR events survive the codec? One command, stock Python, no Vector needed
cd ../vector && python3 ../../prismpath/telemetry/preflight.py ../../adapters/fusion/flows/fusion_triage.md your_sample.ndjson

# Vector: Facet as a native codec, both directions (build of crystal-warden/vector, branch facet-codec)
vector -c vector.toml &                               # aggregator: socket source, decoding.codec = "facet"
python3 gen_events.py | vector -c vector_edge.toml    # edge: stdin json -> socket sink, encoding.codec = "facet"

# Vector: the self heal over a lossy link (standalone facet-sink simulator; stock Vector-shaped NDJSON in)
python3 gen_events.py | cargo run -q --manifest-path facet-sink/Cargo.toml -- ../../adapters/fusion/flows/fusion_triage.md --interference 0.3
```
