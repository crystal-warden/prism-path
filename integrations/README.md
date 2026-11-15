# integrations

Deliver a signed PrismPath policy anywhere, and carry its decisions as a tiny, tamper evident wire. Every path below runs with the real `zarf`, `uds`, and `vector` binaries and the PrismPath toolchain. Nothing here is mocked, and all three share one signed Level M policy (`adapters/fusion/flows/fusion_triage.md`).

| Path | What it shows |
|------|---------------|
| [`zarf/`](zarf) | Zarf delivers a signed policy and its CycloneDX SBOM (from the compliance emitter, `adapters.compliance.emit --pack-sbom`); on arrival it is verified, envelope bounded, and atomically swapped. A tampered policy fails the deploy closed. Zarf's own SBOM catalogs software packages and finds none in a policy, which is why the emitter describes the pack from its signed manifest. |
| [`zarf-kernel/`](zarf-kernel) | Delivery through to activation: the same signed policy is verified and swapped, then the host's accepted copy is hashed against the attestation and loaded into the in-kernel evaluator, whose path for a probe reading must equal the host reference. The receipt is `deployed/activation.json`. A tampered package stops at verification, and a copy swapped on disk after acceptance is refused before the kernel is touched. Needs a built `prismpath-ebpf` and CAP_BPF. One link is not yet signed: the probe reading is encoded with the compiler's binding of the same flow (field names to registers, strings to ids), which the pack does not carry; `make_probe.py` refuses unless the flow recompiles to the delivered image, and carrying the binding in the pack is a pack format decision still open. |
| [`uds/`](uds) | The same policy composed as a UDS bundle: `uds create`, then `uds deploy`. |
| [`vector/`](vector) | Facet as a native Vector codec, both directions: `encoding.codec = "facet"` on a sink, `decoding.codec = "facet"` on a source, about 2 bytes per event framed. [`CANARY.md`](vector/CANARY.md) is the migration recipe: fan one source to your existing sink plus a Facet sink, prove route parity with `python -m prismpath.telemetry.canary_verify`, then cut over. The standalone `facet-sink` simulator adds the Merkle committed wire that self heals across a degraded link. |
| [`governed_harness/`](governed_harness) | A research example of a different kind, with a policy of its own: a small agent harness over the local Gemma in which every proposed tool call is classified into typed fields, decided by the verified core against a signed policy of the owner's agent rules (allow, refuse with a registered cause, or escalate to the owner), receipted before anything runs, and run only on allow inside bubblewrap. Each episode is a signed core run that `formal/diff/core_evidence.py` verifies, every receipt replayed through the Lean oracle; the classifier is trusted code outside the verified core. Scores and limits are in [`RESULTS.md`](governed_harness/RESULTS.md). |
| [`governed_net/`](governed_net) | Phase 2 of the governed harness: each tool call is a fixed layout UDP datagram whose header is the call in typed integers (no path, no shell text), decided before the tool server sees it by an XDP program running the shared in-kernel evaluator over the signed policy's table, and decided again by the server against its own handle table, which runs it in bubblewrap only when both allow. XDP reports each decision through a ring buffer to a logger that writes signed core receipts. In the LAN edge layout it runs on a shared LAN NIC, matching only the configured server address and agent port so the rest of the household LAN passes untouched, with per-verdict counters, per-client receipts and two concurrent clients; a no-install pure-Python loader fills the pinned maps where the host has no libbpf. Here the XDP program's own text runs on its userspace path in front of the server on loopback, which is not the kernel; [`SETUP.md`](governed_net/SETUP.md) is the owner's two layouts, and [`RESULTS.md`](governed_net/RESULTS.md) the differential, the scores and the limits. |

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
# Assess what was delivered against NIST SSDF and the Cyber Resilience Act's Annex I (OSCAL + CycloneDX)
(cd ../.. && python -m adapters.compliance.assess_policy_delivery integrations/zarf-kernel/deployed --out integrations/zarf-kernel/reports)
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
