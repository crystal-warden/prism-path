# Policy distribution

*Design note, 2026-11-20, against research main 2ae3627. Documents only. No code changed. One metaphor and no more: a fleet of constrained actors that all need their policies pushed, the owner's early Terminator picture.*

## 0. The gap in the frameworks

No zero trust framework names a distribution point. NIST SP 800-207 folds distribution into the policy administrator and the control plane (https://csrc.nist.gov/pubs/sp/800/207/final). XACML and NIST SP 800-162 have a policy administration point (PAP) and a policy retrieval point (PRP) (https://csrc.nist.gov/pubs/sp/800/162/upd2/final). The NCCoE zero trust project overview is said to name the lack of a standard way to distribute, manage and enforce policy. I could not confirm that sentence. My search reached the project page (https://www.nccoe.nist.gov/projects/implementing-zero-trust-architecture) and its PDF did not extract. Treat the claim as unverified until someone reads the document.

PrismPath has a signed policy and many enforcement points. The question is how one signed policy reaches all of them and stays true.

## 1. The six duties and what exists

| Duty | What exists | Where |
|---|---|---|
| 1. Sign | An Ed25519 signed manifest (`ppt-pack/1`) binds the image hash, the field schema, the worst case cycles, a monotonic `version`, an envelope id, a key id and a creation time. | `docs/design/spec-secure-hotswap.md` section 3.1, `prismpath/hotswap/policy_pack.py`, `prismpath/cli.py` (`authorize`) |
| 2. Deliver to many PEPs | A three ESP32 mesh swaps one table over ESP-NOW. One node broadcasts, the others stage, and all flip together. | `prismpath-hw/mesh/README.md`, `prismpath-hw/mesh/main/ppt_mesh.c` |
| 3. Verify on arrival | Software tier verifies signature, envelope, version and parse before staging (`policy_host.py`). eBPF has a trusted pre loader (`prismpath-ebpf/net_swap.py`). The mesh recomputes the FNV-1a id on every node and checks it against a baked allowlist, and refuses rather than downgrades. | `spec-secure-hotswap.md` sections 3 and 5, `prismpath/hotswap/policy_host.py`, `mesh/README.md` |
| 4. Know the version each PEP runs | Receipts carry the image hash. The audit log records every swap attempt, accepted or rejected, with from and to hashes. Facet decodes only under the running policy (see below). | `prismpath/agent/run.py` (`image_sha256`), `spec-secure-hotswap.md` section 3.4, `PROTOCOL.md` section 2.1 |
| 5. Roll back and revoke | A monotonic version floor, a key revocation list (`--revoked`), a shadow swap with an explicit rollback that never lowers the floor, and an eFUSE or secure element counter named for hardware. The mesh keeps a floor in NVS. | `spec-secure-hotswap.md` sections 3.1, 3.4, 5, `prismpath/hotswap/policy_pack.py` (`load_revoked`), `ppt_mesh.c` (`version_floor`) |
| 6. Never widen silently | Every swap attempt is audited. An envelope bounds what a swap may change, and the envelope has an expiry. The design for adopted rules never lets a proposal weaken a base rule, and narrowing needs no authority. | `spec-secure-hotswap.md` section 3.2, `~/cwprojects/cc-gate-tracer/DESIGN-envelope.md` |

The North Star states the rule all six serve. Observations may change what the system knows, never silently what it is permitted to do (`~/cwprojects/cc-gate-tracer/NORTH-STAR.md`).

### What the mesh is, and is not

The mesh already does coordinated delivery, verify on every node, quorum two phase commit (PREPARE, ACK, COMMIT at a shared tick), a flip within about 1 ms across nodes, and epochs. Its ids are FNV-1a 32 bit hashes standing in for signatures, and Ed25519 on the mesh is the named follow on (`prismpath-hw/mesh/README.md`). It is a demonstration on three boards with a baked allowlist of two images. It is not a general push service. The 1 ms figure is the README's, as observed from the host.

### What `spec-secure-hotswap.md` names as open

Revocation distribution and key rotation (section 6, item 8, "follow on"). Key compromise is "its own workstream" (section 7). The software anti rollback counter is file backed and tamper evident, not tamper proof (section 7). Those are the real gaps. The rest of the six is covered per substrate, though not by one protocol.

### Facet as version attestation

Facet derives its codebook from the shared signed policy, and the codebook is never transmitted. Both ends run `build_partitions` over the same policy (`PROTOCOL.md` section 2.1, `docs/research/paper-facet-figueroa-quantization.md`). So distributing a policy distributes the codebook, and a telemetry stream decodes only under the policy that is running. That is version attestation for free in the wire format. A node on the wrong policy sends bytes the fleet cannot decode correctly. It costs a median of 1.26 bytes per decision across the 66 shipped policies that encode, and about 4.6 bytes for the 12 field agent policy (`docs/research/facet-across-policies.md`). That is cheap enough for constrained fleets.

Unverified. A heartbeat built from this has not been built or measured. I have not checked that a wrong policy decodes to garbage rather than to plausible wrong values, and the paper's treatment of a mismatched codebook should be read before the claim is used.

## 2. One protocol across every PEP kind

The PEP kinds are the hook and decider, the sandbox profile, the egress and MCP proxy, the XDP edge, the ESP32 and the cFS app. Each has its own loader today. The proposal is one protocol over them, with the existing pieces reused. Labels mark what is built, designed but unbuilt, and new.

**The pack and its signature.** Built. `ppt-pack/1` with an Ed25519 manifest (`policy_pack.py`). Designed. Per target extras (`packing`, `wcet_cycles`). New. A distribution wrapper that names the target kinds a pack is valid for, so a sandbox profile and an XDP table derived from one policy travel as one signed unit with one policy hash. Without it, a PEP can hold a mix of versions of the "same" policy.

**Delivery, push or pull.** New. A narrow transport interface of "offer pack, fetch bytes, report state". Transports are pluggable, with HTTP for hosts, MQTT for constrained fleets with a broker, ESP-NOW for the mesh (built as a one off, in `ppt_mesh.c`) and the cFS software bus for flight software. Pull suits PEPs behind a firewall. Push suits a mesh. The pack is signed, so the transport is untrusted.

**Verify, stage, then commit.** Built per substrate (section 1 duties 3 and 5). Designed. Shadow slot, single flip, explicit rollback (`spec-secure-hotswap.md` 3.4). Built for three nodes. Quorum two phase commit (`ppt_mesh.c`). New. Making stage and commit separate protocol messages everywhere, so a controller can stage a pack on every PEP of a group, see all stage replies, then commit. Quorum matters only where PEPs must agree at once (a mesh, a set of proxies behind one resource). A single hook does not need it.

**Fleet view.** New. Each PEP sends a heartbeat of its state, Facet coded and bound to the policy hash it runs, so the control plane learns the version from the stream that it already has, without sending the hash each time. The controller keeps the expected hash per PEP and flags any node whose heartbeat fails to decode or is silent. Receipts already carry the hash for PEPs that can send them (`run.py`).

**Revocation distribution.** Designed but unbuilt. A revocation list exists on the verifier side (`load_revoked`), distribution of it is named open. Proposal. A signed revocation statement for a key id or a pack hash, delivered over the same transport as a pack and carrying a monotonic sequence number so an old list cannot replace a newer one. A PEP that cannot receive it before a deadline fails toward its last signed policy's expiry. That ties to the envelope's expiry, which already means the base policy comes back when authority lapses.

**Key rotation.** Designed but unbuilt (`spec-secure-hotswap.md` item 8). Proposal. Rotation is a pack too. The old key signs a statement that names the new key and a start sequence, PEPs accept it with the version floor rules, and the old key is then revoked by the statement above. The first deployment of a key is trust on provisioning, which is the one step that cannot be done over the wire.

**Never widen silently, in the protocol.** A pack that grants more than the one it replaces (a larger allow set) must carry an envelope or an owner signature that says so, or the PEP refuses it. A pack that grants less may install on the signature alone. This reuses the envelope check (`spec-secure-hotswap.md` 3.2) and the narrowing rule of the delegate envelope design. How a PEP tells "larger" cheaply is unsettled. For an image it can be decided by the exhaustive walk the profile compiler already does (`prismpath/agent/profile.py`), which suits hosts and not an ESP32. Constrained targets would take the signed claim and the controller's check instead.

## 3. What this does not solve

- A PEP that has been compromised can lie in its heartbeat. Attestation here says which policy the PEP claims to run. Hardware attestation would say more and is out of scope.
- Clocks. Expiry and revocation deadlines trust local time (the envelope design says so for its own expiry).
- The first key. Provisioning is a manual, physical step.
- Mixed fleets mid swap. Any scheme has a window where PEPs differ. The protocol bounds it and reports it. It does not remove it, except where quorum commit is used.

## 4. Work packages

Ordered. Each is about 30 to 60 minutes of agent time unless noted.

**D1. Write the protocol.** One spec with message types (offer, stage, stage-ack, commit, abort, state, revoke, rotate), the pack wrapper, sequence numbers and the refusal causes, registered in `docs/design/spec-cause-codes.md`. Done when the spec has a message table, a state machine per PEP and a conformance case list, and an owner has read it.

**D2. Reference controller and host PEP.** A controller and the software tier PEP (`policy_host.py`) over HTTP, with stage then commit and audit. Done when a test pushes a pack to three host PEPs, one refuses a downgrade, one a bad signature, and the audit logs show all three outcomes.

**D3. Fleet view over Facet heartbeats.** The heartbeat message, its encoder and decoder under the running policy, and the controller's expected hash table. Done when a test shows a PEP on the right policy decoded, a PEP on a different policy flagged, and a silent PEP flagged, and the cost per heartbeat is measured and written down.

**D4. Revocation.** The signed statement, sequence numbers, and PEP handling, including fail toward expiry. Done when a revoked key's pack and a revoked pack hash are refused after the statement arrives, an older statement cannot undo a newer one, and a PEP without the statement falls back at expiry.

**D5. Key rotation.** The rotation statement and its rules. Done when a rotation test installs a pack under the new key, then refuses a pack signed by the old key, and refuses a rotation signed by an unknown key.

**D6. Widening rule.** The check that a larger allow set needs the envelope or owner signature. Done when tests show a narrowing pack installs on the signature alone and a widening one is refused without the envelope.

**D7. Proxy and XDP adapters.** Wire the protocol to the egress and MCP proxy and to the XDP loader (`net_swap.py`). Done when one pack update changes the decision of both and both report the new hash. 60 minutes or more.

**D8. ESP32 mesh to the protocol, with Ed25519.** Replace the FNV-1a ids with Ed25519 verification and carry the stage and commit messages. Hardware work, needs the three boards, so it is gated on them. Done when the three node demo of `mesh/README.md` runs with signed packs and a bad signature is refused on all three.

**D9. cFS adapter.** The cFS software bus transport and the table validate callback as the verify step (`docs/design/cfs-app-plan.md` S1 and S2). Done when a pack offered on the bus loads through the table, and an older version is refused after a simulated reset.

**D10. One policy, all targets.** An end to end test that offers one policy to a host PEP, a proxy, and a simulated cFS table, and shows one policy hash in all three heartbeats. Done when the test passes and the note's built, designed and new labels are updated.

## 5. Links

Linked from `docs/design/enforcement-points-plan.md` section 6. See also `docs/design/prismpath-at-the-resource.md`.
