# integrations

Deliver a signed PrismPath policy anywhere, and carry its decisions as a tiny, tamper evident wire. Every path below runs with the real `zarf`, `uds`, and `vector` binaries and the PrismPath toolchain. Nothing here is mocked, and all three share one signed Level M policy (`adapters/fusion/flows/fusion_triage.md`).

| Path | What it shows |
|------|---------------|
| [`zarf/`](zarf) | Zarf delivers a signed policy; on arrival it is verified, envelope bounded, and atomically swapped. A tampered policy fails the deploy closed. |
| [`uds/`](uds) | The same policy composed as a UDS bundle: `uds create`, then `uds deploy`. |
| [`vector/`](vector) | PrismPath decision telemetry running alongside a Vector pipeline: about 1.5 bytes per decision, over a Merkle committed wire that self heals across a degraded link. |

## Run it

```sh
# Zarf: sign, deliver, verify, swap (files land in ./deployed; see the tamper case fail closed)
cd zarf && ./build.sh
zarf package create . --confirm && zarf package deploy zarf-package-*.tar.zst --confirm
cd ../zarf-tampered && zarf package create . --confirm && zarf package deploy zarf-package-*.tar.zst --confirm   # aborts: fail closed

# UDS: the same package as a bundle (run the Zarf build above first)
cd ../uds && uds create . --confirm && uds deploy uds-bundle-*.tar.zst --confirm

# Vector: decision telemetry, plus the self heal over a lossy link
cd ../vector && python3 gen_events.py | vector -c vector.toml
cargo run -q --manifest-path facet-sink/Cargo.toml -- ../../adapters/fusion/flows/fusion_triage.md --interference 0.3 < vector_out.ndjson
```
