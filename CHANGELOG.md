# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versioning: the **package** follows
SemVer; the **format spec** is versioned independently (SPEC.md §8); any regeneration of the
frozen conformance vectors that changes an existing case bumps the spec version, and that diff
is the spec-change review. Pre-1.0, minor versions may break APIs; the flow *format* is already
spec stable.

## [Unreleased]

### Added: the Rust host follows a policy stream and reports signed state records (2026-11-23)

- **`prismpath_hotswap_rs::dist::pep` is the enforcement point machine in Rust.** It is provisioned by a trust anchor's fingerprint, stages, commits, aborts and rolls back, applies a revocation or a rotation as soon as it verifies, lapses at expiry, locks on a floor, anchor or setting it cannot read, and keeps its state under the file names the Python machine uses. A counter it cannot read locks it for that start only, and its records count on from its time so none repeats.
- **A commit is durable step by step as C4 orders it.** Killed at any step, the machine's own or the host's inside its install, a restart holds the old release before the active record flips and the new one after, never a mix.
- **Every transition is reported as a state record signed by the instance key.** `dist::state_record` writes and reads the record of H1 byte for byte as Python does. The Python controller accepts the Rust PEP's records within its first heartbeat interval only: the Rust PEP holds no controller key, so every record carries epoch 0, and the controller on main files epoch 0 as `fleet:state-replay` once its epoch has risen past 1. The cross language test pins the controller's clock inside that interval. The controller's own fix for a PEP with no controller key (H6) is its own pull request.
- **`PolicyHost::install_verified` is the commit half of a swap for an image already verified, and `PolicyHost::withdraw` makes the host hold nothing.** Once the enforcement point in the state directory has committed an envelope, `swap` and `rollback` refuse with `dist:legacy-refused`.
- **The trust store applies revocations and rotations and reads trust anchors in Rust.** An anchor with more than 8 keys is refused, and a confirm checks the new trust store before it lets go of anything held.
- **A runtime step that fails after its record is durable makes the PEP `reconciling`, as section 9.5 says.** The runtime is withdrawn at once, every decision, commit and rollback is refused with `dist:reconciling`, and the PEP goes on staging, aborting and applying trust statements. Only a tick and a start try again, each try holding the held release, and the running release while it will not withdraw, to revocation and expiry first, so a release that falls is lapsed and never installed. Every record has status 3 and the reconciling entry of H14, the record the transition owed goes once a try works, and a start that finds the state reports it again. A renewal whose step fails stays active and is tried again at each tick, and provisioning over a runtime that will not withdraw is refused (P5). A lapse is durable in the order of C7, with its own intent record. A lapse whose record cannot be written stays active until the next check lapses it, and a stage whose write fails keeps the release staged before it.
- **The Rust PEP takes no epoch id and reports 0 in every record (H9, H15).** It reads `/1` anchors only and holds no controller key, so no statement can give it one.
- **The Rust PEP holds a release to the widening rule (V12, W1 to W7) at staging and again at commit (C3), as Python does.** On `host` a table that is not byte for byte the active one is larger (W2), a larger release that says it does not widen is refused even with a statement (W6), a first install is larger than no policy, and a rollback is held to the same rule (RB3). Cases 62, 63, 139, 140 and 143 run on Rust.
- **A try whose install fails withdraws the runtime again at once, and names the held release as running when that fails too (C10, H14).** A host whose record flipped before its clean up failed may run the held release, so a revocation of it keeps the PEP reconciling until a withdrawal works. A restart reads the running release from the intent record whether or not the transition flipped (C7), audits a lapse once (C12) and keeps a renewal whose step fails active (C10). A confirm whose write fails after the withdrawal holds nothing.
- **A Rust PEP whose home holds the private half of a trusted authority key refuses to start (K2).** It scans as the Python machine does, two levels deep, past the PEP's store and `runs`, files up to 16,384 bytes and at most 4,096 of them. It opens only regular files, reads each as bytes and checks every PEM private key block on its own, past a block with no end line and past RFC 1421 header lines. It also finds a raw 32 byte seed.
- **`Pep::commit` refuses a delay (B8)**, which belongs to the frame binding this crate does not build. DIVERGENCES.md lists what else of the Python machine is not ported.
- **The cross language CI step runs a release sealed by Python through the Rust host and a release sealed by Rust through the Python host.** Each first install says it widens and carries the owner's widening statement, as the Python controller and both PEPs ask. The Python controller's clock is pinned inside its first heartbeat interval, the limit of the Rust PEP's epoch 0 above.

### Changed: grants and route tables travel in distribution envelopes, and a grant is revoked through the signed list (2026-11-23)

- **The `gateway` row joins the kind table.** A gateway release needs `policy.core` and `gateway.routes`, a route table must read as `Routes.from_doc` reads it and be its canonical spelling, and any change of the table is a widening. `prismpath dist pep --kind gateway` runs the PEP of a gateway home that holds its instance key and no authority key.
- **A gateway home that follows a stream reads its policy, its route table and its grants' trust store from the committed release at every request.** A revocation, an expiry or a new route table takes effect at the next request, a commit of another policy refuses the run that began under the old one, and the gateway's decisions reach the PEP's heartbeat. `--routes` is refused in such a home, as are `init`, `grant` and `revoke`.
- **`prismpath gateway grant` writes a grant envelope.** Its header value is the sealed envelope and its `prismpath.dist-grant/1` body joined by a dot, its id is the envelope id, and `--stream` names the gateway it is for. A gateway reads it with the verifier's GR2 rules, V2 to V7 and V9, then holds it to its policy, its classes and its lifetime of at most 30 days.
- **A grant is revoked by its envelope id in the signed `trust.revocation`, and a gateway that follows a stream reads no other list.** A home that holds its own authority key still lists ids in `grants.revoked`, now in the trust store its grants are verified under.
- **The older `prismpath.grant/1` form is still read in a home that holds its own authority key and refused in one that follows a stream.** Nothing writes it any more. A receipt's journal line takes either form's grant id.

### Added: an agent home can follow a policy stream, with a floor, an expiry and no authority key on the machine (2026-11-23)

- **`prismpath agent init --follow STREAM --anchor FILE` makes the agent home follow a stream.** It shows the anchor's fingerprint, takes it back with `--confirm`, writes the hook entries, and the home holds an instance key and no authority key. `prismpath dist pep --kind agent` pulls its releases.
- **The hook, the egress proxy and the MCP proxy decide under the committed release, checked again on every load by the same test the PEP machine runs.** Its signature, its expiry, the revocation list and a raised floor are read each time, a PEP locked for a floor, counter or setting that does not read decides nothing, and an authority key in the home is refused.
- **The egress proxy reaches only the committed `egress.hosts`, and `--allow-host` is refused in such a home.** A commit changes the hook's policy and the proxy's hosts together.
- **The egress proxy and the MCP proxy follow the committed state at every decision, not the release they started with.** They load again when a file of the PEP's store changes or the release expires, so a revocation, an expiry or a commit that removes a host stops them at the next call, and a commit of another policy refuses the run that began under the old one.
- **A staged `sandbox.profile` must be the profile the staged policy compiles to, or the commit is `dist:derived-mismatch`.**
- **The zone file is a distributed `agent.zones` artifact.** A release that protects fewer names, or drops the file, is a widening. `prismpath agent zones set` records the project, its index and the Context Cloud program as the home's own setting, and the index stays a control path.
- **The hook and the proxies hand their readings to the next state record, so an agent home's heartbeat carries its decisions.** A spooled line the Facet codec cannot encode is skipped and counted and never stops a record, and a commit of another policy drops what was spooled under the old one.
- **The search of a home for an authority key skips the runs and stops at two levels and 4,096 files, and a stored sealed envelope must still be signed by a key the store holds when it is read back.**

### Added: signed state records with a Facet body, and a fleet view that finds a wrong policy by its hash (2026-11-22)

- **A PEP whose active release has a `policy.core` puts the decisions it made since its last record, at most 64, in the record's body as a grouped Facet stream of that policy at the band tier.** The stream's preamble names the policy and its layout. A record with no decision in it still carries the preamble. A commit, a rollback or a lapse to another policy drops the decisions the old one made, so no decision is reported under a policy that did not make it.
- **The fleet view marks a rollout of a release that says it widens as larger by comparison or larger by rule.** Larger by rule is a table a host or a mesh node counts as larger only because it changed, so a widening the owner pushed stands out.
- **The controller finds a PEP on another policy from the hashes in the record's header, before it reads any body.** A body built from another policy is `fleet:policy-mismatch`, and one that does not decode under the policy it names is `wire:codebook-mismatch`.
- **A host, a mesh node and the cFS app send no body, since their releases carry no flow text.**
- **A record with 64 decisions in it is about 310 bytes on the shipped agent policies, against 212 bytes with no body.**

### Added: a release that allows more needs the owner's signed widening statement (2026-11-22)

- **An enforcement point stages a release that allows more than its active one only with a `trust.widening` statement of the same release, staged before it, whose `from` is empty or holds the active policy hash.** Otherwise the release is `dist:widening-unsigned`, at staging and again at commit. A first install allows more than no policy, so it needs one too.
- **A host, a mesh node and the cFS app cannot decide, so they take a release on its signature alone only when its `widens` is false and its `replaces` is their active policy.** A host and a mesh node still compare the table, which has no order, so another table than the active one is larger and one that says it does not widen is refused even with a statement. A table goes in on its signature only as a renewal. The cFS app goes by the signer's word.
- **A target that can decide compares for itself and refuses a larger release that says it does not widen, even with a statement.** The comparator walks the finite reading domain of `policy.core` with the agent profile compiler's own walk, a wide integer field by its boundary values, and compares host lists, route tables and zone files. Any change of a `policy.ppt` image is larger, and a `cfs.table` is ordered by the core image inside it.
- **The `agent` row joins the kind table.** An agent release needs `policy.core` and `egress.hosts` and takes `agent.zones` when the owner declares zones, each with its check, and an agent PEP decides for itself. The agent home that runs it comes later.
- **A widening statement lists at most 64 policy hashes, in Python and Rust.**
- **A controller refuses to offer a release that says it does not widen when the release it holds for `replaces` shows it does, or when it holds none.** The sealing tool sets `widens` by the same test, so a host or a mesh table is written with `widens` false only on a renewal.
- **A rollback falls under the same rule, and a rollback to a release identical to the active one is never a widening.**
- **`prismpath dist widen` signs the statement, and `prismpath dist seal --held` fills in `replaces` and sets `widens` from the comparator.** The controller offers a release's statement before the release, and counts a member staged only once every envelope of the release is.
- **The corpus gains the widening cases for a PEP that cannot decide, on a host for Rust and on a mesh node for the C core.**
- **The C core holds a release to the same rule on a mesh node, at staging and at commit, and a rollback to an identical release is never a widening there either, step by step as the Python machine does.**
- **A first install that says it does not widen is refused on every kind, even with a statement, in Python and the C core.** Going from no policy to one is a comparison every enforcement point makes (W6).
- **A rollback on a host or a mesh node is held to W1 to W7 as a staged release is, so a kept renewal that says it does not widen is refused from another table even with a statement, in Python and the C core.**
- **An enforcement point commits a release only whole.** It computes the release id again over the artifacts it staged and refuses with `dist:incomplete` when that is not the signed `release`, so a transport cannot withhold a signed `agent.zones`, `sandbox.profile` or `policy.spiral`, in Python and the C core. The corpus gains its commit cases, 137 and 138.
- **An agent policy whose rule names a value outside its field's reading domain, such as a tool the classifier does not produce, is refused when it is loaded and at V11 with the new cause 160 `policy:out-of-domain`.** The engineer who installs PrismPath defines that domain, and a reading whose category value is outside it is refused with the same cause before the policy decides it. The comparator walks the combinations the classifier never gives too, so a release that allows more on one of them is larger.
- **A commit holds a release to the widening rule again against what is active then (C3), so a renewal whose active release lapsed before its commit needs a statement, case 143.**
- **The conformance cases run to 143, and the trace test counts a case one implementation runs only half of as pending, as case 60 is for the C core until it has the `cfs` kind.**

### Added: prismpath dist, the reference controller and the pull binding for hosts (2026-11-22)

- **`prismpath dist` seals, verifies, revokes, rotates and rekeys on the machine that holds the authority key, and runs the reference controller and a host enforcement point.** `anchor` writes a stream's trust anchor, `enroll`, `offer`, `commit`, `abort` and `fleet` work on the controller's directory beside `serve`, and `pep` provisions a host PEP by fingerprint, pulls, reports its state and rolls back.
- **The controller holds no authority key and stores only what the one verifier passed, reading `meta` in full.** It refuses a revocation list that drops a key, or an envelope or a policy no floor has passed, and the sealing tool refuses the same list.
- **Each group's rollout runs under `each` or `all`.** Under `each` a member commits as soon as it staged, and under `all` nobody commits until every member staged and a refusal or the end of the stage window aborts the group. A commit window that ends with a member still out leaves the rollout `partial` until it reports.
- **Every state record is checked in a fixed order.** A record not signed by the enrolled instance key, or with the hold bit from a host, is `fleet:state-invalid`. A counter that did not rise or an old epoch is `fleet:state-replay`, another policy than expected is `fleet:policy-mismatch`, and three silent intervals are `fleet:silent`. An attestation token in a record must be bound to that record.
- **A host PEP pulls and the controller only listens.** It never reads more than it was promised, fetches a body only after its sealed envelope passed the verifier through V8, refuses a blob that is not the one it asked for with `dist:body-mismatch`, and fetches no body it already holds. The offers answer carries an ETag and may be long polled.
- **Every offer, ack, commit, abort, finding and trust statement goes to the controller's own audit log, signed with its instance key.**
- **A commit may carry a delay, and the PEP makes the release active at its own monotonic time plus that delay, checking it again when the time comes.** The controller drives a whole group over the frame binding with it, and the corpus gains the frame cases for the C core.
- **The frame assembler admits an envelope through the verifier run to V8 as its own call.**
- **A revocation or a rotation reaches every enforcement point whatever its `targets` says, in Python and Rust, so the one trust sequence counts the same everywhere.** A PEP behind on the trust chain is offered only the statements it lacks until it holds them all, and a refusal in that time is filed against the statement.
- **A rollback is held to what a commit checks.** The kept release needs a counting signature and must not be below a floor a revocation raised, and the refusal names the check that failed.
- **The C core takes a revocation or a rotation whatever its `targets` says, and holds a rollback to the same checks, as the Python machine does step by step.**
- **The pull client tries an envelope again only when it was refused for a reason a later clock or trust statement may remove.** The controller keeps at most 64 unknown senders and logs each at most once an interval.

### Changed: escape hatches work only in a dev build (2026-11-22)

- **`--allow-unsigned` on a swap and on the XDP preloader, `PPT_NET_ALLOW_UNVERIFIED=1` in the XDP loader, and a verify of evidence or of in-toto envelopes without both keys pinned now pass through `devbuild.hatch`.** A production build refuses each with `dist:hatch-refused`, writes that to the audit log, and runs the check the hatch would have skipped. A dev build, a checkout holding `.prismpath-dev-build`, lets them through and marks every hatch event `dev_build`.
- **`prismpath evidence verify` without both `--pin-authority` and `--pin-instance` exits 1 outside a dev build.** Pin your own copies of the authority and instance public keys, or run `python tools/dev_build.py on` in a research checkout to see the unpinned result.
- **The loader's bypass is compiled only into `loader-dev`, which `make -C prismpath-ebpf dev` builds for the observe only demos.**
- **The Rust host refuses `allow_unsigned` the same way unless the crate is built with its `dev-hatches` feature, which is off by default.** The host trace corpus replays its unsigned cases once for each build.

### Added: authority key rotation, signed by the old key and the new (2026-11-22)

- **An enforcement point applies a signed `trust.rotation` as soon as it verifies.** It is taken only at the next trust sequence, which revocations share, and only when the key it adds signed it too. It may never add the PEP's own instance key or a revoked key, nor retire a key the store does not hold.
- **A retired key's signatures no longer count, and a release already active under it keeps deciding until it expires or is replaced.**
- **The Rust host applies the same checks of a rotation and the same bounds of the trust store, and replays the rotation cases.**
- **A retired key does not come back.** A rotation that adds a key the store retired is `dist:rotation-invalid` in Python and Rust.
- **The C core applies the same rotation with the same checks and bounds, step by step as the Python machine does.** It keeps a retired key beside the 8 it may count, so a store holds 24 keys at most.
- **A trust store holds at most 8 keys and remembers at most 16 retired ones.** A rotation that would add a ninth is `dist:too-large`, and the oldest retired key is forgotten when a seventeenth is retired.

### Changed: the C core of policy distribution persists its state in parts (2026-11-23)

- **A state record now writes the 12 byte counter and nothing else.** The core tells the store which parts of its durable state changed, the anchor, the counter, the trust store, the floor, each release and a pending commit named by its release id and seq, and packs each part on its own for a store such as NVS.
- **The durable state is 39,720 bytes where it was 98,456.** A release keeps a widening statement at its real size, which W4 now bounds at 64 hashes, and the frame assembler marks arrived bytes with one bit each.
- **A commit and a rollback write the releases one part at a time, the previous release, then the active one, then the staged one.** A power loss between two of them leaves the node on one of the two releases with a previous that is its own or the right one, and a commit cut off can be made again.

### Added: signed revocation lists with a sequence, and fail toward expiry (2026-11-22)

- **An enforcement point applies a signed `trust.revocation` as soon as it verifies, durably before it reports it.** A list is taken only at the trust sequence plus one, and the PEP holds that list and no other, so what it remembers is bounded. Its keys, envelopes and policies are refused, its floor for the PEP's stream only rises, and a list that drops a revoked key is `dist:trust-replay`. A list over 64 entries or 16 streams is `dist:too-large`.
- **A revocation that removes the ground of the active release lapses it to no policy with `dist:revoked`, and drops a staged release on the same test.** That ends a hold as well. A PEP that never hears of a revocation still stops at the release's expiry.
- **Every kind takes a trust body up to 16,384 bytes, the largest revocation list allows, beside its own bound for an artifact's body.** The signed `body_size` is held to the bound for its artifact before any body is read, by the verifier, the frame assembler and the Rust host alike.
- **The Rust host applies the same checks of a revocation list as Python and replays the new revocation cases.**
- **A mesh node or a cFS app, whose own check does not read `meta`, only checks that it is an object nested at most three levels inside the envelope.** Every other reader checks its members and their forms.
- **The C core in `prismpath-hw/dist/` applies revocations as the Python machine does.** A mesh node holds the latest list, refuses one that drops a revoked key, keeps the floor a list raises for its own stream, holds a trust body to 16,384 bytes, and is held step by step to the Python machine and frame by frame to `frames.py`.
### Fixed: the zone index is a control path and an index the agent could have written reads unknown (2026-11-22)

- **The zone index, `.contextcloud/` by default, can no longer be edited by the agent to claim that protected code reaches nothing.** The hook refuses a write or a mutating command onto it as a control write, both per call sandbox backends hold it read only, and the zones information point answers `unknown` for every path when the agent could have written the index or the Context Cloud program that reads it. `prismpath agent zones set` now records the Context Cloud program and its package directory in the signed zone file, checks both again at hook time, runs the program in a fixed environment with no PYTHON variable, refuses a package the agent could change, and rebuilds an existing index after the zone file is signed.

### Added: the distribution verifier and state machine in C, tested natively against the shared corpus (2026-11-22)

- **`prismpath-hw/dist/` is the C core of policy distribution for mesh nodes and the cFS app.** It reads the sealed container and the envelope with a strict canon/2 reader that allocates nothing, checks the signatures with Monocypher before it reads the envelope, and runs the one verifier, the frame reassembly and the enforcement point machine with its signed state records.
- **The C core answers as the Python reference does.** `prismpath/tests/test_distribution_c.py` builds it with the host compiler and its sanitizers, replays every mesh case of the corpus, requires the machine's signed state records byte for byte beside the Python machine, and runs the reassembly frame for frame beside `frames.py`.
### Added: the frame binding of policy distribution for broadcast media (2026-11-22)

- **`prismpath.distribution.frames` writes and reads the six frames of a broadcast medium.** They are the offer, the chunk, the state record, the commit with its delay, the abort and the epoch, each within the link's limit of 250 bytes on ESP-NOW, and anything a reader refuses is `dist:frame-invalid`.
- **`frames.Assembler` puts a release back together from chunks in any order, repeated or lost.** A chunk outside the offer or with no offer, or a part whose hash is not the offered one, drops the transfer, and a transfer still incomplete after 5 seconds is dropped silently. On a link declared ordered a chunk out of order drops it too.
- **No body is read before its envelope has passed the verifier through V8.** The body is then read only to the signed size and against the signed hash.
### Added: the distribution envelope and verifier in prismpath-hotswap-rs, replaying the shared corpus (2026-11-22)

- **`prismpath_hotswap_rs::dist` reads, writes and verifies the distribution envelope as Python does.** It holds the sealed container, the envelope and release ids, the kind table with each artifact's own check, the trust store and its durable file, and the one verifier with rules V2 to V11 in order.
- **`prismpath_rs::canon2::codec` is one serde reader and writer for canon/2.** Every distribution document derives it, so its fields are its members and a member missing or extra does not read.
- **`tests/test_distribution_conformance.rs` replays every corpus case that runs on Rust, each under its own test.** The verdicts match Python's, and the Rust writers give back the corpus's bytes, the trust stores and the 38 containers the Python writer sealed included.
- **Every `meta` member is read in its own form when the envelope is read.** A `policy.ppt` whose `fields`, `counts`, `wcet_cycles`, `qualification`, `packing`, `flow_sha256` or `overlay_of` has another form is `dist:bad-format`, and so is a `net.edge` or `sandbox.profile` member of another form.
- **The host row says which trust kinds its machine applies and bounds a body, as Python's does.** V5 refuses any other trust kind with `dist:target-mismatch`, and a body is held to the smaller of the PEP's bound and its kind's.
- **The pack gate refuses a manifest whose `fields` or `counts` is not an object with `manifest:bad-format`.** Its count check is now `check_counts`, which the envelope check shares.

### Added: the enforcement point state machine for policy distribution, with the software host as its first target (2026-11-22)

- **`prismpath.distribution.pep.Pep` stages, commits, aborts, rolls back and lapses at expiry, one machine for every Python target.** Its store under `<state>/dist/` is written in the commit order of the spec, so a death at any step leaves the old release or the new one and never a mix. A store it cannot read refuses every envelope and decides nothing.
- **Every transition is reported in a state record signed by the PEP's instance key** (`state_record`). Provisioning takes a trust anchor and waits for the operator to confirm its fingerprint.
- **The host adapter installs a committed release through `PolicyHost.install_verified`, the commit half `swap` now ends in,** and checks a declared spiral sidecar. Once a release came by distribution, `swap` and `rollback` refuse a pack with `dist:legacy-refused`.
- **Every `meta` member of a distribution envelope has a fixed form, checked when the envelope is read,** so no check ever reads a signed member of another type. The older pack gate refuses a manifest whose `fields` or `counts` is not an object with `manifest:bad-format`.
- **A modelled mesh node and a modelled cFS app run the same machine,** the mesh row in the kind table and the cFS row registered from `integrations/cfs/dist_kind.py`. Either may be provisioned to hold an expired release instead of refusing, and every record and receipt it signs while held says so.

### Added: the distribution envelope, the trust store and the one verifier (2026-11-22)

- **`prismpath.distribution` writes, seals and reads the distribution envelope.** `envelope.build`, `seal`, `unseal`, `release_id` and `envelope_id` are the signed form every distributed artifact will travel in. A signature covers the DSSE encoding of the envelope bytes, and `to_dsse` and `from_dsse` map a sealed envelope to DSSE JSON and back. `kinds` holds the artifact and target kinds in one table.
- **`verify.verify` checks a sealed envelope in the order V2 to V11 and reports only the first cause.** It reads keys with their roles, retired keys, revocations, the trust sequence and the time floor from `trust.TrustStore`, whose durable file counts nothing when it cannot be read.
- **`devbuild.hatch` refuses every escape hatch with `dist:hatch-refused` outside a dev build.** A dev build is a checkout holding `.prismpath-dev-build` beside `pyproject.toml`, which only `python tools/dev_build.py on` writes and git ignores, so no package carries it.
- **`portable/conformance/distribution.json` freezes 50 verifier cases and the release id vectors from fixed test keys,** and a trace test fails when a conformance case of the spec has no test in an implementation it names.

### Added: the policy distribution spec and its refusal causes (2026-11-22)

- **`docs/design/spec-policy-distribution.md` defines how one signed policy reaches every enforcement point and stays true there.** It sets out one signed envelope for every distributed artifact, the messages and their two bindings, the enforcement point and controller machines, revocation, rotation, the widening rule, the hold at expiry for mesh and cFS, the heartbeat and 126 conformance cases.
- **The cause registry gains 135 to 159 for policy distribution.** They are 20 `dist:` refusals, the `dist:held` mark and four `fleet:` findings, with their crosswalk entries, the regenerated Rust and Lean registries and the frozen corpora.
### Added: the spiral profile for policies too large to list (2026-11-22)

- **A node whose joint grid is over 300,000 cells now has a band tier and a signature tier.** `prismpath/telemetry/spiral_groups.py` finds the band by evaluating the policy once, so no grid is listed, and costs 5 to 7 bits a decision on the seven large policies. The signature tier groups the fields that rules read together, sends each group's class of rule residuals, and refines inside a class in Gray order, at 14 to 43 bits. `layout_for` returns the existing `SpiralLayout` for a node that fits, so every existing layout, sidecar and recorded stream is byte identical. A stream carries a 42 byte preamble naming the policy and the layout, and a decoder refuses another policy's or another layout's stream. PROTOCOL.md section 2.6.1 defines the profile.
- **Decision preservation is proven and tested.** `formal/FQ/Signature.lean` proves that readings whose disjoint, covering field groups have equal signatures route alike. `test_spiral_groups.py` round trips the seven policies and checks every reading of a seeded sample of the uniform and boundary populations, and the full 64,484 reading populations run at the checkpoint. `prismpath-telemetry-rs` has the band tier, held to the Python bits by `conformance/grouped_band.json`. The signature tier is not ported to Rust yet.
### Fixed: the spiral mesh referee compares frames again (2026-11-22)

- **`prismpath-hw/spiral-mesh/referee_mesh.py` takes each frame's hex from the sender's `X` line.** Since the node began to batch triples, its `T` line carries no hex, so the referee read none, skipped every received frame and could pass its wire integrity check having compared nothing. A triple whose frame line was lost on serial is still not judged.

### Fixed: control files a killed run left behind, and a cached profile made for another policy (2026-11-22)

- **A run that was killed no longer leaves empty `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `.mcp.json` or `.claude/` in the workspace.** What a run creates to bind them read only is now written to a marker outside the workspace first, and the next run removes what a marker from a process that is gone lists, only while it is still empty. A marker is read only from a directory this user owns and no one else can write, and it can remove only the workspace's own control paths. A file that was already there, or that has content, is never removed.
- **A cached sandbox profile is used only for the policy image and compiler version it was made for.** The cache entry now carries the compiler version and a binding hash over the image digest, the version and the profile, and an entry that does not match is compiled again.

### Removed: the unused agent OpenTelemetry attribute module (2026-11-22)

- **`prismpath.agent.otel` is gone.** Nothing imported it. The span exporter in `prismpath.ledgers.otel` is unchanged.
### Fixed: the crates publish check fails on any answer from the index but 200 and 404 (2026-11-22)

- **The already published check in `publish-crates.yml` treats only a 404 from the crates.io index as not published.** A rate limit, a server error or a network failure stops the step instead of letting a publish go ahead. `tools/tests/test_export.py` runs the step with the index stubbed.

### Changed: the export ships only files listed in a manifest (2026-11-22)

- **`tools/export_clean.py` fails and names any tracked file under an included prefix that is not in `tools/export_manifest.txt`,** so a new research file no longer ships by default. Add it to the manifest to ship it or to an exclude rule to hold it back. `--write-manifest` rewrites the manifest from the current rules, and the exported tree is unchanged.
### Fixed: the in-toto export finds keys only where it is told to, and says when verify was unpinned (2026-11-22)

- **`prismpath.ledgers.intoto` no longer patches `InstanceKey.__init__` or scans live objects for a private key.** A key comes from an argument, the environment variable or the run's key files.
- **`verify` reports `pinned`, `pinned_authority` and `pinned_instance`.** A check without pins reads the run's own `instance.pub`, which says nothing about who made the run, so its report says `pinned: false` and `signed-unpinned`.
- **A failed `import_envelopes` leaves the run directory as it was.** The roots file it restored is removed when verification fails, and a malformed envelope is a `Bad` error.

### Fixed: a cFS store that does not read no longer resets the version floor to 0 (2026-11-21)

- **After a processor reset with a run state in the Critical Data Store that does not read,** the cFS app begins a new run under the response its mission chose (`PRISMPATH_APP_PLATFORM_LOST_FLOOR`), not a floor of 0 that would admit any older signed image. `PP_LOST_FLOOR_LOCK`, the default, admits no image, so every proposal is refused, until ground deletes the store and restarts the app; the mark is saved with the state, so a later reset keeps it. `PP_LOST_FLOOR_MINIMUM` admits every image from `PRISMPATH_APP_PLATFORM_LOST_FLOOR_MIN_VERSION` up. The state's spare word holds the mark, so the store's size is unchanged. `tests/run_check.c` checks both responses.

### Changed: the Rust Facet encoder writes codes straight into words (2026-11-21)

- **`prismpath-telemetry-rs` builds each Fibonacci code as an integer (a compile-time table for 1 to 255, a search over a fixed table above) and packs it with a `BitWriter`, instead of building a string of `0` and `1` characters and walking it.** `zeckendorf::encode`, `encode_stream`, `packed::pack` and `packed::encode` give the same bytes as before and are held to the old string algorithms by `tests/test_fast_encode.rs`. Acceptance checks a value without copying it (`quantizer::accept_check`, `prismpath_rs::field_definitions::check_canonical`), since the accepted value compares as the value given. `wire::Encoder` sorts the field order once and writes a reading's packed bytes directly: `encode_packed_into` takes the HashMap reading `encode_reading` takes, with the same refusals, `encode_row_into` takes one value per field in wire order, and `encode_symbols_packed` takes cell symbols. On 1M readings of the fusion policy the shipped path went from 1.5M to 2.0M readings per second, the encoder takes 7.6M (HashMap) and 12M (row), and code and pack alone about 45M; on the 12 field agent policy 0.53M, 0.68M, 2.7M, 4.7M and about 22M.

### Fixed: programs the classifier read as read only could write files or run commands (2026-11-21)

- **What was wrong.** `sed`, `sort`, `uniq`, `xxd` and `tree` were on the classifier's read only list, and only the
  literal flags `sed -i`, `sort -o` and `tree -o` were caught. So `sed -ri`, `sort -o.claude/settings.json`,
  `uniq notes .claude/settings.json`, `sed 'w FILE'`, `sed '1e CMD'` and `xxd -r notes .git/hooks/pre-commit` read
  `read_only` and the starter policies allowed them, through the Claude Code hook. Likewise `git diff --output=FILE`,
  `git grep -O sh` (and `--open-files-in-pager`) and `git diff --no-index` read as a plain allowed git listing.
  Through the Claude Code hook that let a command rewrite the agent's own settings or hooks.
- **What changed.** `CLASSIFIER_VERSION` is 3. `sed`, `sort`, `uniq`, `xxd`, `tree`, `file` (`-C` writes a file) and
  `date` (`-s` sets the clock) are mutating, and so are named writers in the hazard scan. A git argument that is
  `--output`, `--open-files-in-pager`, `--no-index`, `--ext-diff`, `--contents`, `--ignore-revs-file` or `--remerge-diff` (it writes temporary objects) (or any prefix of
  one, which git accepts) or a short cluster holding `O` is an unsafe option, so the call reads git `unknown`. The three
  starters are recompiled for version 3, the previous images are named as older starters, and a recorded policy from
  before this fix gets the re-init message. The MCP proxy now decides under the recorded, attested policy of
  `agent init` (`commands.load_checked`), refuses every call without one, and accepts `--policy` only when it is that
  policy.
- **What is proven.** The theorems prove the model's readings and refusals given the model's lists. They do not prove
  that a listed program is read only. `prismpath/tests/test_read_only_runs.py` now checks that by running every
  read only program and every plain git read, with the options each prints in its own help, in a temporary tree, and
  requires the tree unchanged and no child run.

### Changed: review fixes (2026-11-21)

- **`prismpath gateway` will not serve without `--routes FILE`**, because with an empty table every path reads `other` and a policy that allows `other` would allow all of them. The route table's canon/2 digest is kept on each receipt's journal line (`routes_sha256`, outside the sealed root and the receipt format) and `gateway verify` reports it.
- **The egress proxy records the digest of the `--allow-host` list** (`hosts_sha256` on each egress receipt's journal line, reported by `agent verify`), since the list is a launcher argument and no signed policy holds it. The egress log is kept by default in the egress run's directory as `egress.log`, and `--egress-log` names another place.
- **`agent approvals` counts an asked receipt as approved only when the call ran.** A call that failed or was interrupted is reported as `asked_failed` and does not count toward `--min`.
- **A PostToolUse outcome finds its receipt by `tool_use_id` from the end of the journal** instead of validating every line each time.
- **The Lean oracle cases of the egress and edge table tests run in CI** (the `formal` workflow), the launcher shell child tests run wherever a per call backend works (Landlock included), and a test fails when a source file names a `docs/` path that does not exist.

### Added: hook inputs recorded from a real Claude Code session (2026-11-21)

- **`prismpath/tests/fixtures/claude_code_live_2026-11-21.json` holds the 18 hook inputs Claude Code 2.1.326 sent to `prismpath agent hook` in a headless session** (PreToolUse for Read, Glob, Grep, Bash, Write and Edit, PostToolUse for each call that ran, SessionEnd), with paths and ids replaced. `test_agent_claude_code_live.py` answers each PreToolUse input again and requires the live answer. The real inputs carry fields the written fixtures do not (`session_id`, `transcript_path`, `permission_mode`, `tool_use_id`, `prompt_id`, `scratchpad_dir`, `effort`). The hook inputs in `claude_code_hooks.json` are written in that shape, not recorded, and the spec and this changelog now call them written. The same session gave 9 receipts that replay with no disagreement and 11 outcome records bound to them.

### Fixed: file tool paths that start with `~` refuse as outside the workspace (2026-11-20)

- **A path whose first component is `~` or `~user` reads as outside the workspace** for Read, Write, Edit, MultiEdit, NotebookEdit, Glob, Grep and the filesystem server's tools, so the agent's own Read of `~/.ssh/config` refuses with cause 111 where it was asked with 124. The rule is always outside, whatever `HOME` is, as the Bash scan already reads it. A `~` that is not the first component is an ordinary name, and a leading `~` no longer sets `path_glob`. Proved in Lean (`pathFacts_home`, `classify_home`), covered by the oracle, the differential harness and four written hook inputs.

### Added: gateway grants (2026-11-21)

- **`prismpath gateway grant --path-class CLASS --method-class CLASS --ttl SECONDS` signs a grant with the gateway home's authority key, and the gateway reads the `X-PrismPath-Grant` header as the request's `grant` field.** A grant (`prismpath.grant/1`, canon/2, Ed25519 over a domain-separated document) names the route and method classes it covers, the policy image it was issued under and a window of at most 30 days. It names no holder, so it is the same grant whoever presents it. It reads `valid` only when it verifies under this gateway's key and policy, covers the request and is in force, `expired` past its window, and `invalid` otherwise. `prismpath gateway revoke --grant-id ID` adds it to `grants.revoked` in the home, which is read again when it changes, so the next request that presents it is refused; a list that cannot be read revokes every grant. The grant id and the SHA-256 of the grant are kept on the receipt's journal line (bound to the line by the journal check, not under the sealed root), and the grant header is never forwarded. The demo policy lets a granted read reach the admin routes.

### Added: what became of each call, and approvals worth a rule (2026-11-20)

- **The receipt's journal line carries Claude Code's `tool_use_id`**, an optional key bound to the line the way `sandbox.profile_sha256` is. `core-receipt/1` and the signed root are unchanged: the key is in the journal line, not the receipt, so no oracle or replay changed.
- **`prismpath agent init` installs `PostToolUse` and `PostToolUseFailure` hook entries**, and `merged_settings`, `doctor` (a warning when missing), `status` and the launcher's staged settings know them. Each event appends one entry to a new hash-chained `outcomes.jsonl` in the run, bound to the receipt with the same `tool_use_id`: `ran` or `failed` with a failure class, the tool name and the receipt's index and hash, and no tool output. An event that cannot be bound is recorded `unbound` and changes nothing. The nested runner's report of a finished shell command is an outcome too. At SessionEnd an allowed receipt with no outcome is recorded `no outcome` and an escalated one `no outcome (declined or not run)`. The file is outside the signed root, like `observations.jsonl`; outcomes are records and decide nothing. `verify` checks its chain and binding.
- **`prismpath agent rules` counts what became of each rule** (`allowed_ran`, `allowed_no_outcome`, `asked_approved`, `asked_no_outcome`, `refused`, also in `--json`), and `status` shows totals for each session.
- **`prismpath agent approvals [--min N]` lists the rules whose asks were approved N times (3 by default)** with counts and example readings as classes only, labelled as candidates for the owner to sign. It changes nothing and adopts nothing.

### Added: a Landlock backend for the per call sandbox (2026-11-21)

- **Where a bwrap inside a bwrap is forbidden (Ubuntu 24.04), an allowed shell command under `prismpath agent run` now runs under Landlock instead of being refused with cause 129.** `prismpath/agent/landlock.py` (standard library `ctypes`, ABI detected at run time) applies the bash role profile to the command's process: read and execute under the profile's mounts, read write under the workspace and a private scratch directory, TCP bind and connect refused from ABI 4, and a small seccomp filter that refuses `socket()` (which also closes the proxy's and the decider's unix sockets, UDP and `io_uring`), `ptrace` and System V IPC. The launcher probes bubblewrap, then Landlock, and denies with cause 129 only when neither works. The journal line of each receipt and each observation record the backend that ran (`sandbox.backend`).
- **Both per call backends keep the workspace's control paths read only** (`prismpath/agent/controls.py`, the list the launcher also uses), so a script run by an allowed call cannot edit `.claude/settings.json`, `CLAUDE.md` or `.git/hooks/`. Under Landlock without the launcher's mounts a directory that holds a control path (the workspace root, `.git`) takes no new entries.

### Added: the gateway, the first enforcement point in front of a resource (2026-11-20)

- **`prismpath gateway --upstream URL --listen ADDR` is an HTTP reverse proxy that decides every request with the core under an attested policy and receipts the decision before the service sees it.** A request is read into the fields `method_class`, `path_class` (from the owner's route table), `body_class`, `content_class`, `query` and `grant`, in the canon/2 form the agent classifier's readings use, without asking who sent it, so a curl, a script and a model get the same decision. What it cannot read reads `unknown` and is refused, nothing is forwarded without a durable receipt, a missing or unattested policy refuses every request, and sizes and times are bounded. A refusal is a 403 with the new cause 131 `gateway:request-refused`; `gateway init`, `verify` and `rules` record the policy, verify the run and count rule hits. The demo policy `prismpath/gateway/policy/demo.rules.md` compiles to its attested image; grants are a stub until a later package.
### Added: the network edge is closed, and its destination table and first attach are signed and gated (2026-11-21)

- **The owner's destination table is signed by the owner's authority key.** `net_from_policy.py sign-dests` writes a detached `prismpath.net_dests_pack/1` manifest and signature (the Ed25519 signing of `policy_pack`, canon/2), and `compile` refuses a table that is unsigned, signed by another or a revoked key, or edited after signing. The signed table travels in the edge directory, the signed flow names its canonical hash, and `verify` refuses an edge whose carried table does not verify or is not the flow's.
- **The first attach is gated as the swap is.** `net_from_policy.py attach` and `net_swap.py --attach --edge DIR` check the pack, the envelope, the version floor, the flow, the recompiled table and the signed destination table before `loader netattach`, and `--edge` does the same for a swap. The loader now refuses `netattach` and `netupdate` unless `PPT_NET_VERIFIED_SHA256` names the table it is about to load (`PPT_NET_ALLOW_UNVERIFIED=1` is the explicit bypass for the observe only demos), and `loader x netverify` runs that check alone without root.
- **`ppt_net.bpf.c` drops what it cannot classify when its table enforces, and counts it.** IPv6, VLAN tags (802.1Q and 802.1ad), other ethertypes and a cut off or malformed IPv4 header were passed; a table that names a drop node now drops them and a table that only observes still passes them. Each is counted by reason in a new `refused_map`, which `loader netstats` prints. ARP is the one exception, counted and passed. IPv6 destinations are not offered: the register ABI has 32 bit fields, so an IPv6 address in the destination table is refused. The packet corpus holds IPv6, VLAN, QinQ and other frames, held to the oracle with an IPv4 connect inside a VLAN tag.


- **`prismpath gateway --upstream URL --listen ADDR` is an HTTP reverse proxy that decides every request with the core under an attested policy and receipts the decision before the service sees it.** A request is read into the fields `method_class`, `path_class` (from the owner's route table), `body_class`, `content_class`, `query` and `grant`, in the canon/2 form the agent classifier's readings use, without asking who sent it, so a curl, a script and a model get the same decision. What it cannot read reads `unknown` and is refused, nothing is forwarded without a durable receipt, a missing or unattested policy refuses every request, and sizes and times are bounded. A refusal is a 403 with the new cause 131 `gateway:request-refused`; `gateway init`, `verify` and `rules` record the policy, verify the run and count rule hits. The demo policy `prismpath/gateway/policy/demo.rules.md` compiles to its attested image.
### Added: the network edge is compiled from the signed agent policy (2026-11-20)

- **`prismpath-ebpf/net_from_policy.py` projects the signed image's connect allow set onto the table `ppt_net.bpf.c` loads.** The edge passes TCP to port 443 at the addresses of the owner's destination table (`prismpath.net_dests/1`, host to IPv4 addresses) for each class the image allows and the agent profile's proxy state covers, for the sources it governs, and drops every other IPv4 packet from those sources. Frames it cannot classify (IPv6, VLAN tags, other ethertypes, a malformed IPv4 header) are handled as the entry on `ppt_net.bpf.c` above says. An address shared by an allowed and a refused name is dropped and reported, a name that moves is not followed until the owner compiles and signs a new table, and `other` and `unknown` are never passed. The node order is fixed so the loader's drop mask index never moves.
- **The table is signed with its flow.** The flow names the source image hash, `policy_pack` signs the table with the flow's hash, and `verify` is a dry run (pack signature, envelope, version floor, the table recompiled from the flow and from the image, the loader's own parser) that loads nothing. `net_swap.py` gains `--dry-run`, and `net_compile.address_refusals` takes `bit_pattern_constants` so a destination at or above 128.0.0.0 is named by the value the front end puts in the register. `prismpath/tests/test_net_from_policy.py` holds the table, run through the userspace C evaluator, to the Lean oracle over a packet corpus.

### Added: state across calls (2026-11-21)

- **A policy can read what the session already did.** `session_protected_changes` (`none`, `some`) and `session_shell_runs` (`none`, `few`, `many`) are reading fields the decider computes from the session's own journal (`prismpath/agent/session_state.py`) and adds to the reading only for a policy that defines them, so the core stays a pure function of (policy, reading) and no other policy's readings, receipts or classifier version change. The state comes from receipts only (a change whose `zone_reach` was not `none` and was not refused, and the `run_command` receipts that were not refused, banded at 20); an outcome is never read. Under `prismpath agent run` the state is every session of the launch, so `/clear` does not reset it. The journal's validated-prefix record keeps the counts of the lines it covers, so a call reads only the lines appended since.
- **The fail safe is the most restrictive state.** A journal that cannot be read in full (a line that does not verify, a missing journal, a run with no image, a torn tail) reads as `some` and `many`; a reading that lacks the fields is refused at the core's boundary, and `Policy.reading_bytes` gives it the restrictive values. A parallel tool call that appends a receipt between the state read and the append makes the decision be made again (`Run.append(expect=)`).
- **The `session` starter, `prismpath agent init --policy session`.** `agent_default` and two rules after every refusal: cause 133 `agent:session-change-asked` (after a protected change, a change inside the workspace, a commit and a push to an allowed remote ask) and cause 134 `agent:session-shell-asked` (after many shell commands, a read only command or a local git operation asks). Its sandbox profile is the default's.
- **The Lean model proves a state only adds restriction** (`Session.lean`). The oracle's `--session IMAGE BASE` mode checks, over every reading and state, that the stateful image is at least as restrictive as the stateless one, at most as restrictive as its own top state, and never a contract violation; `session_refused`, `session_not_allowed`, `session_failsafe` and the carried zone, control, network and scan theorems follow for every state. The differential harness runs the check, and decides the starter on every state in Python and in Lean.

### Added: zones, the owner's protected code (2026-11-20)

- **The classifier reads `zone_reach` (`none`, `protected`, `unknown`) for every call that changes files.** It asks a zone information point once for each path the call names and joins the answers. With no point, or with no path to ask about, a changing call reads `unknown`. A call that changes no file reads `none`. The field is not part of the classifier version, and the three starters from before it are named as older.
- **Every starter asks with the new cause 132 `agent:zone-asked` about a file change whose `zone_reach` is `protected` or `unknown`.** It comes after every refusal, and strict applies it to the file tools only, so it never turns a refusal into a question.
- **`prismpath agent zones set|status|warm`.** The owner lists the protected names in a zone file that is signed with the policy's authority key and bound to the recorded policy and the project. A declared zone file that does not verify, or with no Context Cloud or index, reads `unknown`. With no zone file nothing is protected. The Context Cloud adapter runs `contextcloud reaches --json` for each function of the file, checks the index holds the file's current version, and caches each fact.
- **The Lean model proves the rule** (`Zone.lean`): `zoneOf_none_iff`, `zoneOf_absent`, `zoneOf_protected`, `zone_not_allowed`, `allowed_change_every_path_none`, `absent_point_not_allowed` and `protected_not_allowed`. The oracle's `--policy` mode prints `zone_asked`, and the differential harness gives each case a seeded point.

### Added: the compile and the egress proxy read the policy (2026-11-20)

- **`compile_profile(image, role)` takes a role, `bash` or `agent`.** The agent role derives `net` from the allow set (`proxy_model` when an allowed connect reads `model_api`, `proxy_allow` when one reads `allowed_host`, `none` otherwise) and keeps the fixed mounts. A profile that carries `net` is `prismpath.profile/2`; one with none (the bash role, and the starters' profile, hash 767dd3c8) keeps its `prismpath.profile/1` bytes.
- **The egress proxy decides each CONNECT with the signed policy and writes a receipt.** The constant allowlist is gone. `prismpath agent run` loads the recorded policy, refuses to start when it allows no connection to the model API, and takes `--allow-host` for the `allowed_host` class.

### Added: the classifier reads a connection, version 2 (2026-11-20)

- **The classifier gains the tool `connect` and the reading fields `net_dest` and `proc_class`; `CLASSIFIER_VERSION` is 2.** A connect call (`{"tool": "connect", "args": {"host", "port"}}`) reads `net_dest` `model_api` for a host of the constant `MODEL_API` table on port 443, `allowed_host` for an owner listed host on 443, `unknown` for a host it does not read (upper case, a trailing dot, userinfo, a port or a path in it, short IPv4 forms) or a port outside 1 to 65535, and `other` for the rest. `proc_class` is `single`, `tree` or `unknown` for a command and `none` otherwise. Nothing feeds a connect in yet (the proxy is a later package).
- **Every starter refuses a connection that is not the model's own API with the new cause 130 `agent:net-refused` and allows one to it.** The starter images are recorded again (their field `classifier_version` now holds 2 only), so an older recorded starter refuses every reading until `prismpath agent init`; `prismpath agent doctor` and `status` name the three older images. Existing calls keep their verdicts, since no old rule reads either new field. The intent layer's images are regenerated from the strict starter.
- **The Lean model proves the network rule** (`Net.lean`): `connect_other_refused`, `connect_unreadable_refused`, `net_refused`, `netDestOf_model_api`, and the oracle's `--policy` mode reports `net_refused` (`netSafe`) for each image. The differential harness reads a corpus of odd hosts and ports with 0 disagreements.

### Added: the agent and its shell calls run sandboxed on Linux (2026-11-20)

- **An allowed Bash call on Linux runs under bubblewrap.** The hook answers allow with the command rewritten (`updatedInput`) to run under the bash role profile compiled from the recorded policy, and the receipt carries the profile's hash. `prismpath/agent/sandbox_exec.py` builds the bwrap command line and fails closed when bwrap is missing or never reports its sandbox up. A missing bwrap or a profile that does not compile is a deny with the new cause 129 `agent:sandbox-unavailable`. `prismpath agent init` compiles the profile once and says when it cannot.
- **`prismpath agent run -- PROGRAM [ARGS]` runs the agent itself in a sandbox (Linux only).** It stages a per run config directory with a read only `settings.json` that holds the hook entries, pins the program binary, binds the workspace control paths read only, runs the program under bwrap with the agent role profile and its network through the egress proxy, and removes what it staged on exit. Nothing reads a real login. `--credential FILE` copies one file in as the program's credential and is off unless given.
- **Under `prismpath agent run` the hook is a thin client and the decision is taken outside the sandbox.** The decider (`prismpath/agent/decider.py`) listens on a unix socket bound into the sandbox and runs the same `commands.hook` with the keys, the policy and the run directory, which stay outside. The client (`prismpath/agent/hook_client.py`) is standard library only, staged read only and run by the system Python in isolated mode. A request over 1 MiB or not read within 10 s is denied with cause 126, at most 8 connections are served at once and decisions are taken one at a time. A missing socket, a bad reply or a timeout in the client is a deny.
- **Under `prismpath agent run` an allowed Bash call runs in a per call sandbox nested in the agent's.** The launcher probes at start whether a bwrap can run inside its own. The rewritten command names the system interpreter and a runner bound read only, runs under the bash role profile, and reports what it showed over the decider's socket. Where nesting is unavailable the call is a deny with cause 129 and never runs under the outer profile alone.

### Added: sandbox observations, and approved questions run sandboxed (2026-11-20)

- **An escalated Bash call on Linux is answered ask with the sandboxed command** (`updatedInput`), so a call the person approves runs under the same bwrap profile as an allowed one. A refusal is unchanged, and a missing bwrap or a profile that does not compile is a deny with cause 129. Off Linux the call is asked unchanged.
- **Sandbox observations.** When a sandboxed command's standard error shows a stopped access, the run records an observation in `observations.jsonl`, bound to the receipt, image hash and profile hash. `prismpath agent verify` checks it. It is not a rule hit and changes no decision. `core-receipt/1` is unchanged.

### Changed: the control-file refusal closes the gaps it left open (2026-11-20)

- **A shell command outside the plain grammar that redirects onto a control file is refused with 128.** The hazard
  scan now reads a token that resolves to a control path in a command that is not read-only (a redirection to a file,
  or `rm`, `mv`, `cp`, `tee`, `sed -i`, `git add` and the like), so `echo x > .claude/settings.json` and
  `printf y >> .mcp.json` no longer ask under `default` and `review`. The scan still never allows, only adds refusals.
- **Control paths are matched case insensitively on every platform, through hard links, and more widely.** `.CLAUDE`
  names the same file on macOS and Windows; a file with the device and inode of a control file is a control path.
  `.git/hooks/` and `.git/config`, everything under `.claude/` (commands, agents, skills), `CLAUDE.md`,
  `CLAUDE.local.md` and `AGENTS.md` at any depth are control paths. Reads are unchanged. The workspace root, `.git` and
  every directory that holds control files are control targets only for a removal or a move (`rm -r .`, `rm -rf ./`,
  `rm -rf .git`, `mv . x`, `find . -delete`, `git rm -r .`, `git clean`); writing into them (`cp x .`, `tee ./new`,
  `git add .`, `pytest .`) is decided as before.
- **The written hook command no longer imports a `prismpath/` package planted in the workspace.** Claude Code runs the
  hook from the project directory, and `python -m prismpath` put that directory first on `sys.path`; the command now
  runs the interpreter with `-P` (Python 3.11 and later) or `-I` (3.10). A planted `sitecustomize.py`, `usercustomize.py`
  or `.pth` file was never loaded. Run `prismpath agent init` again to rewrite an installed hook.
- The Lean model proves the scan's control rule (`scan_control`, `scan_control_refused` in `ScanTheorems.lean`); the
  differential harness covers redirections and the new paths (0 disagreements in 20,000 generated cases), and the
  written hook inputs are now 161.

### Added: a warning for a policy recorded before the control-file rule (2026-11-20)

- **`prismpath agent status` and `prismpath agent doctor` warn when the recorded policy allows a change to the agent's own control files.** The check is the oracle's `control_refused` property (`controlSafe` in `formal/Classifier/Control.lean`) evaluated through the reference decision path over every reading with `path_control` that is a change; a policy without the field fails outright. The four shipped images from before 2026-11-19 are recognised by hash, so the message says "the default starter from before 2026-11-19" rather than `custom`, and names the fix, `prismpath agent init --policy <starter>`. Runs already sealed keep verifying, and a session still open is denied its next call. The hook decides exactly as before. `status --json` carries `policy.control.refuses_control_changes`, and the `doctor` row `policy-control` carries `refuses_control_changes`.
- `prismpath agent init` without `--policy` now keeps an older shipped starter's name (an older strict stays strict) instead of recording `default`.
- `core_reference.python_decision` is the reference's decision on a reading without the policy check beside it, which `python_reading` now calls.

### Added: the governed agent no longer changes its own controls (2026-11-19)

- **A change to the agent's own control files is refused under every starter** (`strict`, `default`, `review`), with
  the new cause 128 `agent:control-write` (appended, routing). Before this, a Write or Edit of
  `<project>/.claude/settings.json` was allowed under `default` because it is inside the workspace, which let the
  agent remove the PrismPath hook. The control files are `.claude/settings.json`, `.claude/settings.local.json`,
  anything under `.claude/hooks/`, `.mcp.json`, `.claude` itself, and the program the installed hook runs when it is
  inside the workspace. A path is matched after it resolves, so `..` and a symbolic link do not hide it. It covers
  Write, Edit, MultiEdit, NotebookEdit, the MCP file tools and the Bash commands the plain word grammar reads
  (`rm`, `mv`, `cp`, `mkdir`, `sed -i` and the rest), source or destination. Reads are decided as before; paths
  outside the workspace (`~/.claude`, `~/.prismpath`) were and stay refused as outside it.
- The classifier gains a twelfth reading field, `path_control`, a disk fact like `path_in_toolchain`, and each
  starter's rules gain one rule and the field definition; the three images are recompiled. **A policy attested by an earlier release ignores the new field, so it keeps allowing these writes (and `status` names it `custom`) until `prismpath agent init` records a starter that has the rule.**
- The Lean model of the classifier carries the field and proves the rule (`formal/Classifier/Control.lean`): a control
  path reads control, and under every `controlSafe` policy, which the oracle checks on each shipped image, a change
  that names one is refused (`control_refused` in the oracle's `--policy` output). The differential harness and the
  written hook inputs (now 132) cover it, and the refusals are receipted like any other, so they are observations a
  later policy proposal may read; they never change the policy on their own.

### Added: a rule table for the installed policy (2026-11-19)

- **`prismpath agent rules` shows each rule of the installed policy with its hits.** Like `iptables -L -v`, it lists
  the rules in order with their readable conditions, targets, hit counts and last hit time counted from the
  receipts that verify, the core's own refusals as rows of their own, the rules never matched, and the rules no
  reading can reach (decided from the policy alone over every combination of field values). It takes `--json` and
  `--since`, and writes nothing.

## [0.2.0] (2026-11-17)

The first release since 0.1.0, and the first through Trusted Publishing. 0.1.1, 0.1.2 and 0.1.3 were tagged or
staged but never uploaded, so this release carries everything listed under them below as well as the entries that
follow. It is built from the product repository's `main`, exported from research `main`.

What changed since 0.1.0, in short:

- **One command puts a governed agent under a policy.** `prismpath agent init` sets up a Claude Code project with
  keys, a starter policy and the hooks; `agent hook` decides each tool call and writes a signed receipt;
  `agent verify`, `status` and `doctor` check the result. Three starter policies ship (`strict`, `default`,
  `review`).
- **Rules are readable.** A policy is written as a `*.rules.md` file and compiled to the verified core's image, with
  `policy compile`, `render` and `skeleton`.
- **Mission Control** is one console with three interfaces, for the process owner, the operator and the assessor,
  and serves only its own page over its own host with a session token.
- **Receipts leave PrismPath as in-toto statements** in DSSE envelopes, for any tool that reads those.
- **Causes map to outside taxonomies.** The cause crosswalk relates every registered cause to OWASP Top 10 for
  Agentic Applications, MITRE ATLAS and CWE, and the regulatory mapping relates them to the frameworks it names.
- **OpenTelemetry decision attributes.** A proposal and a producer (`prismpath.agent.otel`) for the outcome, the cause
  and the receipt of a governed tool call on its span.
- **The classifier's readings are proven given its lists.** Its reading of a call is defined in Lean and held to the
  Python over the recorded inputs, the adversary probes and 20,000 generated calls, and a proven hazard scan keeps
  hazards refused when a command falls outside its grammar. This was worded "The classifier is proven" in 0.2.0,
  which overstated it: see the Unreleased fix below.
- **Every Merkle tree is RFC 6962's**, with consistency proofs, a streaming root in Python, Rust and C, and strict
  canon/2 readers. These are breaking changes and are listed below.
- **Native crates.** The four Rust crates (kernel, Facet telemetry wire, policy hot swap, preflight) are held to the
  Python reference by the frozen corpora.

The detailed entries follow.

### Changed: the hazard scan reads git, installers, globs and long paths (2026-11-17)

- The scan of a Bash command the grammar does not read gains rules for git (an unsafe option or unknown
  subcommand reads unknown, a network subcommand network, a mutating one or `reset --hard` mutating, a push a push
  to a remote that is not allowed), installers followed by a fetch word (`pip install`, `npm i`, `apt-get install`
  and the like, read as network), glob characters (`path_glob`) and tokens past the path length limit or holding a
  NUL (path scope unknown). A network word inside a path token no longer counts, so `cat ~/.ssh/id_rsa` refuses as
  outside the workspace (111), not network (106). Each rule is proved in `formal/Classifier/ScanTheorems.lean`, and
  under every shipped agent policy the scan never allows and only adds refusals (a push alone asks, as before). Of
  the 76 generated commands that still asked after the first scan, 43 refuse now; none outside the grammar is allowed.

### Changed: the classifier's syntactic reading is defined in Lean and held to it (2026-11-17)

- **`formal/Classifier/`** defines the governed agent's classifier and its Claude Code and MCP mappings over the
  call's text, with the disk's observations of each named path as inputs, and proves: the reading depends on the
  disk only at the paths the call names; a Bash command with a shell operator or a character outside the plain
  word grammar reads unknown; nothing outside the read only set is read only; a `..` component gives
  `path_traversal` and a glob character `path_glob`; every listed form of a kill by pattern is detected; and the
  core's boundary accepts every reading under the three agent policies. No unfinished proof, standard axioms
  only, enforced at build (docs/design/spec-verified-classifier.md).
- **`lake exe classifier-oracle`** and **`formal/diff/classifier_diff.py`** hold the Python to the model over the
  120 written hook inputs, the 51 adversary probes and 20,000 generated calls: no disagreement. The formal
  workflow runs it, and `tools/reproduce.sh` has the step `classifier-diff`.
- **Behaviour change (owner decision).** A Bash command is split by a plain word grammar instead of `shlex`:
  plain words and quoted text, nothing else, so a backslash, an unquoted `~ { # ! ^`, any control or non ASCII
  character reads unknown and is asked about under `agent_default`. Signals, process ids, the pkill word
  boundary and `git tag -nN` are read in ASCII, the stricter reading. A call holding a lone surrogate reads
  unknown. No written hook input or adversary probe changed answer; on 20,000 generated commands 1,177 moved to
  ask (124). The classifier's disk reads are now one function (`classifier.disk_facts`), the mapping's three
  (`claude_code._inside`, `_same_dir`, `_exists`).
- **Hazards outside the grammar stay refused (owner decision).** A Bash command that reads unknown is scanned on its
  raw text (`claude_code.hazard_scan`, `formal/Classifier/Scan.lean`): a `pkill`/`killall`/`kill` word, a network
  word or a URL scheme, a token outside the workspace, a `..` or a `.toolchain` component sets the reading fields
  the refusal rules fire on; nothing found leaves it asking. Proved: each rule as stated, and under every shipped
  agent policy the scan only ever adds refusals. Of the 605 generated commands the grammar alone moved from refuse
  to ask, 529 are refused again; no command outside the grammar is allowed. Written inputs `kill-3`,
  `shell-tilde` and `shell-brace` now refuse (105, 106, 111) where they asked.

### Added: three starter policies for the governed agent (2026-11-16)

- **`prismpath agent init --policy strict|default|review`** records the chosen starter, attested by the user's own
  authority key as `agent_default` always was. `strict` is `agent_rules` (a call it cannot read and a shell command
  that changes files are refused), `default` is `agent_default` with its bytes unchanged, and `review` is the new
  `agent_review`: reads run, every change inside the project asks, the hazards are refused as in the others. With no
  `--policy` a fresh setup records `default` and a second run keeps the starter already recorded. `status` names the
  starter in use (`custom` for an image that is none of them), and the attestation's `case` names its image.
- **`prismpath agent doctor`** takes any shipped starter as current and names it in its policy check; an older
  shipped image of a starter warns with `init --policy <that starter>` as its fix, and an attested image that is none
  of them warns as `custom`, the name `status` gives it.
- Each starter is a readable `*.rules.md` compiled to the shipped `*.core.json` byte for byte. They ship unsigned in
  the wheel: the signed `ppt-pack/1` format carries a `.ppt` table image, not a `prismpath.core/1` image, and no
  shipped pack is signed by a repository key, so `init` signs the chosen image as it did before.
- New cause 127 `agent:change-asked` (appended, routing), the review starter's escalation of a write, a delete, a
  file-changing command or a local git change inside the workspace, with its crosswalk entry.
- `prismpath/tests/test_agent_starters.py` tables each starter's answer to every Claude Code equivalent of the 51
  case adversary set and checks over every reading the classifier can give that no starter allows a hazard.

### Added: the cause crosswalk and the regulatory mapping (2026-11-16)

- **`docs/standards/cause-crosswalk.json`** maps every registered cause to OWASP Top 10 for Agentic Applications 2026, MITRE ATLAS 2026.10 and CWE 5.0, each with a one line rationale or a none with its reason. Internal routing, state and integrity causes say so and are not forced onto a taxonomy. The referee `prismpath/tests/test_cause_crosswalk.py` checks every id against a pinned list in `docs/standards/taxonomies/`, so a cause appended to the registry fails it until it is mapped.
- **`docs/standards/crosswalks/` and `regulatory-mapping.md`** map the evidence PrismPath produces to EU AI Act Articles 12, 14, 15, 19 and 26 with the dates the Digital Omnibus set, to the NIST AI RMF (reusing the AI governance crosswalk), to NIST AI 600-1 and to SP 800-53 Rev 5 AU and SI. Each edge says what the evidence does not satisfy on its own.
- **`docs/design/spec-cause-codes.md`** gains section 4.1, the registration rule. The export now carries `docs/standards/`.

### Added: `prismpath agent` puts a Claude Code session under the core (2026-11-16)

- **`prismpath agent init`** makes the authority and instance keys in the user's configuration directory
  (`prismpath/agent` under XDG_CONFIG_HOME or ~/.config, ~/Library/Application Support, %APPDATA%; files 0600,
  directory 0700, an existing key never replaced), records `agent_default` with its image attestation signed by the
  authority key, and writes a `PreToolUse` and a `SessionEnd` hook into the project's `.claude/settings.json`. The
  change is printed as a diff and written only with `--yes` or a y at the prompt; other settings are kept, and a
  second run changes nothing.
- **`prismpath agent hook`** is what Claude Code runs: it classifies the call, decides it, appends the receipt to the
  session's run and answers allow, deny or ask, the receipt's number in the reason. `SessionEnd` seals the run. It
  fails closed: input that does not read, a missing or broken key, a policy whose attestation does not verify or any
  error of its own is a deny with the new cause 126 `agent:hook-error` (appended), never an allow. It answers in
  65 to 85 ms (median) including interpreter start on the aarch64 GB10 host, under the 150 ms budget, and its
  import path loads no numpy.
- **`prismpath agent verify`** seals the open runs and verifies every run with both keys pinned, every receipt
  replayed through the reference kernel; `--tamper-demo` flips one byte of a copy and shows it refused.
  **`prismpath agent status`** names the keys, the policy hash, the project's hook entries and every run with its
  receipt count, open or sealed. Each command takes `--json`.
- **An append no longer re-reads the run.** `RunStore` keeps a validated-prefix record (`journal.prefix`) and
  validates only the journal bytes after it, so an append to a 5000 receipt run costs about 0.5 ms instead of
  about 700 ms; a record that does not match the journal validates the whole journal, and seal and verify always do.

### Added: the Claude Code adapter and the default agent policy (2026-11-16)

- **`prismpath.agent.claude_code`** reads a Claude Code `PreToolUse` hook input into the classifier's call (Read as
  `read_file`, Write, Edit, MultiEdit and NotebookEdit as `write_file`, Glob, Grep and LS as `list_dir`, Bash as
  `run_command` split by `shlex`, everything else unknown) and writes the core's decision as the hook's answer
  (`allow`, `deny` with the registered cause, `ask`). A shell operator, an unsplittable string, a `~` or brace
  word, or a working directory outside the project makes a Bash call unknown.
- **`agent_default`** is `agent_rules` with one difference: a reading whose tool or command the classifier cannot
  read asks the person (new cause 124 `agent:unreadable-asked`, appended) where the owner's rules refuse it.
  Unknown paths and unknown git operations still refuse (104), and a call that also breaks another rule still
  refuses by that rule.
- **A file-changing shell command asks.** Under `agent_default`, a command that changes files (rm, mv, mkdir, cp and the
  like) whose paths are all inside the project asks the person (new cause 125 `agent:shell-mutation-asked`, appended)
  instead of refusing with 112. The refusals for a toolchain path, a glob, a `..` component, a symbolic link, a path
  outside the project, a kill by pattern and the network apply to such a command first, and a mutating git
  operation still refuses with 112.

### Added: Mission Control is one console with three interfaces, documented from its own schema (2026-11-16)

Mission Control grew from one file of proving and observing routes into the console the guides now describe.
This entry names the whole of it, since the entries below and above each cover one change.

- **Three interfaces on one page.** Authoring (the process owner) edits flows and fixtures, draws the graph,
  runs validate, lint, test, contract and portable, proves Level M and reachability, scaffolds a flow from a
  template and reports a flow's change status. Operating (the operator) follows and controls the sprint loop,
  answers the human queue and delivers events, reads the policy a deployment runs, the lens, fan outs and
  routing quality, and reads a collector's live feed with a cause monitor. Auditing (the assessor) lists the
  trails under the evidence roots, decodes a receipt from the cause registry, checks it again in the page
  under a key the assessor pins, and verifies anchors, evidence runs, change control, policy packs and kept
  feed sessions. Every control the posture leaves out is shown as unavailable.
- **The collector** (`prismpath-ebpf/collector`) is the only privileged reader of the enforcer. The console
  reads its feed on `MC_COLLECTOR`, keeps the sessions under `MC_COLLECTOR_STORE`, and proves each seal extends
  the last, with the kept sessions bounded by `MC_COLLECTOR_KEEP_BYTES` and `MC_COLLECTOR_KEEP_DAYS`.
- **`docs/guides/mission-control-api.md`** has its route tables generated from `app.openapi()` by
  `tools/gen_mission_control_guide.py`, with a test (`prismpath/tests/test_mission_control_guide.py`) that fails
  when they differ from the app. The posture, session, roots and audit sections are written by hand and the
  generator leaves them alone. Sixteen routes that had no docstring have one, since the tables read it.
- The process owner's, operator's and assessor's guides each name their interface. The Dictionary's Mission
  Control entry names the three interfaces and the two postures, and a `session` entry is added.
  `docs/design/architecture.md` describes the package it is, not the single file it was.

### Changed, breaking: the collector feed proves each seal extends the last, and the console's kept sessions are bounded (2026-11-16)

After a `gap`, or a reconnect to the same session at a higher count, the console could not check the next
seal and took the tree up from its peaks on the collector's word. And the kept feed sessions had no bound on
their size or age.

- **RFC 6962 consistency proofs** (section 2.1.2, verified as RFC 9162 section 2.1.4.2 says):
  `root_statement.consistency_proof` and `verify_consistency` in Python, `merkle::consistency_proof`,
  `verify_consistency` and the streaming `ProofWindow` in Rust, held to each other by the new corpus
  `portable/conformance/merkle_consistency.json` (612 proofs, and the 98 consistency probes of
  transparency-dev/merkle, vendored under Apache-2.0).
- **The feed is `prismpath.collector/2`** (`prismpath-ebpf/collector/README.md`). Every seal after the first a
  connection was sent carries `consistency`: the proof from the `count` of the last seal that connection was
  sent, or `missing` with the reason (`window`, `ahead`). A client may resume a session from the count it last
  verified, and its join seal is proved from there. The collector keeps `--proof-window` leaf hashes (default
  65,536, 2 MiB) and one 2 KiB tree state per client. A `/1` subscription is refused, and the console reads
  only `/2`.
- **The console keeps two verdicts apart** (`mission_control/feed.py`): `records` (`checked`, or `unchecked`
  after a hole) and `tree` (`proven`, or `unproven` where a seal was taken up with no proof that it extends the
  tree before it, listed in `unproven` with why). The new status `unproven` sits between `holes` and `broken`;
  a proof that fails is a `seal-consistency` finding. A `gap`'s hole is read from the indexes, since its count
  is of records. The client resumes from its last verified seal on every reconnect.
- **Retention** (`feed.retain`, `MC_COLLECTOR_KEEP_BYTES` default 1 GiB, `MC_COLLECTOR_KEEP_DAYS` default 30,
  0 turns a bound off): whole oldest segments go first, never the one being written nor one another console
  may be writing, nothing outside the store and nothing through a link, and each leaves
  `feed-NNNNNN.removed.json` in its place with its size, sha256, lines, first and last seal and why it went.
  The kept layout is `prismpath.console-feed/2`, and `/evidence/feed` reports the removed segments.

### Added: an accumulator's peaks carry its tree on (2026-11-16)

`prismpath_rs::merkle::Accumulator` gains `peaks()`, the peak hashes tallest first (the order
`root_statement.MerkleAccumulator` keeps them in), and `from_peaks(count, peaks)`, which rebuilds the
accumulator from them and refuses a list that is not one peak per set bit of the count. A reader handed the
count and the peaks partway through a stream checks every later root from the leaves after that point
alone. A test holds `from_peaks(peaks())` followed by the remaining leaves to the batch tree for every cut
of 300 leaves.

### Changed, breaking: Mission Control writes its audit event before it acts, names the session that asked, and reads a deployment without writing to it (2026-11-16)

A file save and a sprint start were recorded after the effect, so an audit log that could not be written left
an unrecorded edit or process; a `file.edit` event named only a path and a byte count; every event's actor was
the literal `operator`; `/quality/lock` wrote a lockfile unaudited and outside the write lock; `/policy/pack-attest`,
documented as read only, created the state directory and appended an attestation to the deployment's own log;
and `/attest/trail` with no source was a 500.

- **Intent, then effect, then result** (`prismpath/mission_control/audit.py`): `record_intent` is written before
  the effect and `record_result` after it, under the action's name with `.result` appended, naming the intent by
  index and Merkle leaf. When the intent cannot be written the effect does not happen and the answer is a 503.
  Covers the sprint controls, `/queue/decide`, `POST /file` and `/quality/lock`; `/sprint/select` and
  `/sprint/auto` are now audited too.
- **Actor** is `console/<interface>/<session fingerprint>` (`authoring` for the file write, `operating` for the
  rest); a queue decision's `decided_by` is that actor. `audit.ACTOR` is gone.
- **`file.edit`** carries `kind` (flow or fixture), the flow's `name`, `sha256_before` and `sha256_after`; the
  result carries the sha256 read back from disk. The file is written as the exact UTF-8 bytes hashed.
- **`/quality/lock`** records the flow's and the centroid file's sha256 and the written lock's, under the file lock.
  Checking is the read route `/quality/lock-check`, mounted in the read only posture; a missing lock is a failed
  check, not a 500.
- **`/policy/pack-attest` is removed** in favour of the read route `/policy/pack-active {state_dir, last}`, which
  reads `active_policy.json`, checks the image digest and returns the `swaps.log` history and statement status
  without constructing a `PolicyHost`. Attesting is `prismpath swap attest`.
- `/attest/trail` with no source walks the console's own log. The lens labels a call's receiver from the record's
  `model` or `worker` field, else its `kind`, and names no model of its own. Dead registration comments removed.

### Changed, breaking: Mission Control serves only its own page, over its own host, with a session token (2026-11-16)

A form posted from any web page reached `/api/v1/sprint/stop` and dropped the STOP marker, a foreign
`Host` was served, a project could be selected from anywhere on disk, and the defaults followed `/tmp`.

- **Session guard** (`prismpath/mission_control/session.py`), the outermost layer: a request is refused with
  a 403 unless its `Host` is the bound port under `127.0.0.1`, `localhost` or `[::1]`, its `Origin` (when
  present) is that same origin, and, under `/api/v1`, it carries `X-PrismPath-Session` equal to the launch's
  random token. The page gets the token in a meta tag written as it is served; a script reads it from
  `mission_control-<port>.session` (mode 0600) in the state directory. Every response carries a content
  security policy, `nosniff`, `no-referrer` and `X-Frame-Options: DENY`; the page and the API are `no-store`.
  `/docs` is no longer served (it loaded a CDN script); the schema stays at `/openapi.json`.
- **Postures**: `--read-only` or `MC_READ_ONLY=1` mounts no route marked `x-prismpath-capability: write`
  and refuses each with a 403. The full posture stays the default.
- **Project roots**: `/sprint/select` and `/sprint/start` accept only a discovered sprint, the launch project
  or a directory under `MC_EVIDENCE`, and never one holding the console's own audit log. `MC_PROJ` defaults to
  `project` under the state directory (`MC_STATE_DIR`) and `MC_SCAN` to nothing, in place of `/tmp/demo` and
  `/tmp/*/status.json`.
- **One project per request**: the followed project is guarded by a lock, each request captures it once, and
  `/status` no longer moves it; following the live sprint is the event stream's job.
- `MC_HOST` other than loopback is refused unless `MC_ALLOW_NON_LOOPBACK=1`. The page reads the event stream
  with `fetch`, since `EventSource` cannot send the header.

### Added: the streaming Merkle root in every substrate, proved equal to the tree (2026-11-15)

- **One streaming form per language**, beside the batch tree and giving the same root: `root_statement.MerkleAccumulator`
  (Python, unchanged), `prismpath_rs::merkle::Accumulator` (Rust, `merkle` feature: `add`, `add_leaf_hash`,
  `root`, a fixed array of 64 peaks and a 64-bit count, no heap and no recursion), and `ppt_merkle_acc` in the
  eBPF `merkle.h` (`ppt_merkle_acc_init`, `_add`, `_add_leaf_hash`, `_root`, no `malloc`, no recursion), through
  which the batch `merkle_root` over receipts is now computed. `merkle.h`'s SHA-256 sits behind three functions a
  firmware port replaces with `PPT_MERKLE_SHA256_EXTERNAL`. The state is 64 peaks of 32 bytes (2 KiB) and a count.
- **Proved**: `formal/Core/Merkle.lean` defines the accumulator (add by carry, root by fold) over the hash as a
  parameter and proves `acc_root_eq_mth` (equal to RFC 6962's `mth` for every nonempty list) and
  `accPeaks_length_le` (at most 64 peaks below 2^64 leaves), on the three standard axioms.
- **Vectors**: `prismpath/portable/conformance/merkle_stream.json` (`gen_merkle_stream_fixtures.py`), the root
  over every prefix of three leaf sets, replayed by the Python, Rust and C accumulators; each is also held to
  its batch tree for every count from 0 to 1000 and to the RFC 6962 known answers.

### Changed, breaking: every Merkle tree is RFC 6962's, and a core run's stored flow must be its image's rendering (2026-11-14)

The first consumer of the receipts and roots (the governed agents Journeyman pack) found that the shared tree
repeated the last node of an odd layer and used no domain prefix, so [a, b, c] and [a, b, c, c] had one root
and only the stated leaf count told them apart, and that nothing held a core run's stored flow to its signed
image (SPEC.md §8 "Merkle trees"; docs/design/spec-verified-core.md, section 11).

- **The tree is RFC 6962's** (`ledger_ots.MERKLE_SCHEME`, `rfc6962-sha256`): a leaf is SHA-256(0x00 || leaf),
  a node SHA-256(0x01 || left || right), split at the largest power of two below the count, nothing
  duplicated. One implementation per language: `prismpath.ledgers.ledger_ots` (which `root_statement`, the
  audit log, the context ledger, the OpenTimestamps anchor, the telemetry transport, core runs and the
  governed harness, net and intent integrations all use), `prismpath_rs::merkle` (new `merkle` feature; the
  hot swap crate's audit log, receipt and root statement verifiers, the context ledger and the telemetry
  transport use it), and the eBPF `merkle.h` (the tracked `seal_receipts` tool is rebuilt). A one leaf
  root is now its leaf hash, not the leaf.
- **Formats bumped with it**: `prismpath-root-statement/3` (a `/2` statement is the fatal finding
  `old_merkle_scheme`, and a bundle under one is refused with that reason), `prismpath.core-run-root/2` (a
  `/1` statement is refused by name by the Python and Rust verifiers), `prismpath.intent-observation-root/2`,
  and an anchor manifest names `"merkle": "rfc6962-sha256"` (one without it is refused). Every audit log,
  epoch chain, anchor batch and core run written before is refused as old scheme and has to be written again.
- **The renderer ships**: `prismpath.kernel.core_render` (moved from `formal/diff/core_diff.py`, which imports
  it). With no random source it writes an image's canonical rendering. Core runs store it
  (`core_evidence.write_cases`), the producers refuse cases whose flow is not it, and both verifiers refuse a
  run in which a case's flow is not the canonical rendering of its signed image. The Rust twin ports the
  canonical rendering (`core_evidence render --from CASES`), held equal to the Python on every image tested.
- **Proved**: `Core/Merkle.lean`, `mth_injective` (one RFC 6962 root, one list, of any length, unless the
  hashes exhibit a collision) and `retired_collides` (the retired tree gives [a, b, c] and [a, b, c, c] one
  root for every hash).
- **Vectors regenerated** by their generators: `receipts.json` (251 cases, with retired scheme refusals),
  `host_trace.json`, `context.json`, and `prismpath/tests/fixtures/core_evidence/cases.jsonl` (canonical
  flows).

### Changed, breaking: every reader is strict, and a lock holds integers of millionths (2026-11-10)

Every reader of a hashed or signed document and of a reading accepts only its exact canonical canon/2 bytes
(docs/design/spec-verified-core.md, sections 3 and 3.2; SPEC.md §8; docs/DICTIONARY.md "not canonical"). A
document that reads as canon/2 but is spelled otherwise (whitespace, members out of key order, a needless
escape, a carriage return) is refused, never re-canonicalized; a file or a JSON Lines line may end with one
line feed and nothing else.

- **Three causes are registered**: `policy:not-canonical` (101) and `reading:not-canonical` (102) for the core's
  image and reading, `document:not-canonical` (103) for every other hashed or signed document. The registry
  hash, and so every frozen value that pins it, changed. canon/2 gains the rule name `not-canonical`
  (`Canon2Error.rule`, `Canon2Error::NotCanonical`, the JavaScript and Go `rule`, Lean `DocErr.notCanonical`).
- **The core decides with the strict reader.** `Core.verdictBytes` and the oracle read with
  `Core.readCanonical`; a respelled image refuses every reading with `policy:not-canonical`, and a respelled
  reading is refused with `reading:not-canonical`. New theorems say so, that a route is given only on
  canonical bytes, and what the canonicalize path does; `Core.verdict` and now `Core.verdictBytes`,
  `Core.writeBytes` and `Core.readCanonical` depend on `propext` only.
- **Documents.** A pack or flow manifest, or an envelope, in another spelling is `document:not-canonical`
  (was read and respelled, so `manifest_reformatted_but_unchanged_still_verifies` is now
  `manifest_respelled_but_unchanged_is_not_canonical`); an audit log line or a root statement in another
  spelling is an unreadable line or `bad_format`. Files are read without newline translation, so a log or a
  statements file with CRLF line endings no longer verifies (`crlf_log`, `statements_file_with_crlf`,
  `log_forms`). A statements file's final line is `interrupted_statement` only when it is not JSON, in Python
  as in Rust.
- **The canonicalize path** for text a person wrote: `prismpath canonicalize FILE` (`--out`, `--in-place`,
  `--check`), `canon.canonicalize_document`, `canon2.canonicalize` (which replaces `canon2.canonical`), Rust
  `canon2::canonicalize` (which replaces `canon2::canonical`) and `durable::canonicalize_document`, JavaScript
  `canon2Canonicalize`, Go `Canon2Canonicalize`, Lean `Core.canonicalize`.
- **Vectors and corpora regenerated**: `canon2.json` is version 2 (a case's `refuse` is the strict reader's
  answer, `canonical_hex` the canonicalize path's; 87 cases, 18 refused as `not-canonical`), and
  `receipts.json`, `hotswap.json`, `host_trace.json` and the telemetry receipt stream corpus follow. The
  canon/2 differential's line is `<strict> ; <canonicalize>`, and the core differential sends 8 percent of
  images and readings respelled.
- **A lock is version 2**: `delta` and `centroid_prior_weight` are written as `delta_micro` and
  `centroid_prior_weight_micro`, integers of millionths, not as decimal strings made by `repr` of a float. A
  value with more than six decimal places is refused, and Python and Rust (`Lock::from_json`) refuse a
  version 1 member, a float or a string in their place. A version 1 lock is refused; run `prismpath lock` again.

### Changed, breaking: every hashed or signed document is canon/2, and canon/1 is retired (2026-11-10)

The rest of the system follows the verified core onto canon/2, the integer only JCS profile
(docs/design/spec-verified-core.md, section 3.1; SPEC.md §8; docs/DICTIONARY.md "canon/2"). A document a
writer hashes or signs now names `"encoding": "canon/2"`, is hashed over its canon/2 bytes, and is signed
over the domain `prismpath.canon/2` and a zero byte before those bytes unless its format has a domain of its
own. canon/1, the earlier encoding, is retired in the same release: nothing writes it and nothing reads,
hashes or verifies a document under it. A document without the tag, or with another tag, is refused with a
named cause, and what was signed, hashed or anchored under canon/1 no longer verifies. Nobody had used the
system yet, so there is no migration path; a deployment that has old logs, packs or journals regenerates them.
`prismpath/tests/test_canon2_migration.py` sweeps Python, Rust, JavaScript, Go and the eBPF and hardware code
for any encoder or decoder of it, and for its corpora.

- **Audit events** carry `ts_us`, an integer of microseconds since the epoch, instead of the float `ts`, and
  `encoding`; each line is the event's canon/2 bytes, so non ASCII text is raw UTF-8 and no longer `\u`
  escaped. A data value with a float is refused (`AuditWriteError`), never converted. A log line without the tag
  is skipped with its cause (`AuditLog.skipped_causes`), the log no longer verifies (`bad_format`, `log_lines`),
  and `ledger anchor` refuses it. `trail` reads `ts_us`.
- **Root statements** are `prismpath-root-statement/2`: canon/2, `encoding`, the integer `time_us` instead
  of the ISO `time`, the domain `prismpath-root-statement/2`. A `prismpath-root-statement/1` statement, or any
  untagged line in a statements file, is `bad_format` (a complete line that is not canon/2 is never dropped as a
  torn write; only a final line that is not JSON is `interrupted_statement`), and the next link's `prev` is
  compared with `unreadable`. A receipt bundle whose receipt or statement does not name canon/2 is `invalid`
  with a `problem`.
- **Pack manifests, envelopes, flow manifests and the crypto registry** are tagged and signed over the canon/2
  domain, and their files are their canon/2 bytes. An untagged or float holding pack or flow manifest is
  `manifest:bad-format`, a registry `registry:bad-json`, an envelope `envelope:sig-invalid` (a Rust envelope
  that does not read was `envelope:missing`). The registry hash, and so every frozen `registry_hash`, changed.
- **The policy host's intent and active records**, the **epoch journal**'s chain, gap and acknowledgment
  records and data files, **attestation and OpenTimestamps manifests**, the stamp request and proof bundle
  records, and the **lock file** (its `delta` and `centroid_prior_weight` as decimal strings) are canon/2. An
  untagged one is refused: a journal does not open (`JournalCorrupt`, its lines are never truncated), a lock is
  a `LockError` that says to run `prismpath lock` again, a manifest or receipt does not verify.
  `prismpath/flows/wazuh_triage_decomposed.lock` was re-written as a canon/2 lock.
- **The acknowledgment tag** is HMAC over the canon/2 domain and the tagged pair, so an edge and a ground
  station must both be on this version. A sequence number beyond plus or minus 2^53 minus 1 has no canon/2
  form: Python raises `EncodingError`, and Rust now returns a `CanonicalError` from `ackchannel::canon`,
  `sign_ack`, `verify_ack` and `AckReceiver::on_ack` (they returned bare values and panicked), so those four
  signatures changed.
- **A float in content PrismPath hashes but did not write is refused.** A connector's ingestion and knowledge
  hashes, a decision's outcome root, a composer item id, a ledger proof, the compliance adapter's catalog,
  weight and determination hashes and Mission Control's audit data go through `canon.content_bytes`, which raises
  `FloatRefused` (Python, an `EncodingError`) and, in Rust, `durable::content_bytes` returns a `CanonicalError`
  with the same words: supply an integer of a stated unit (microseconds, basis points, bytes) or a decimal
  string. PrismPath writes no spelling of a float of its own, so the earlier rule (a float as its shortest
  decimal string) is gone, content that held a float now fails to hash, and every hash that was over such
  content changed. Mission Control's `audit.record` raises `AuditWriteError`. `connector.json` now carries
  `float_refusals`, replayed in Rust.
- **Plain JSON is named and held out of every hash.** `canon.loads`, `load` and `dumps_strict` are
  `plain_loads`, `plain_load` and `plain_dumps`, for a durable run checkpoint, the connector's JSONL sink
  lines and the version floor file; `loads_content` reads a model's reply as content. The document `plain_loads`
  reads is a `PlainDict`, and every hashing helper of `prismpath.canon` refuses one (`PlainJSONRefused`). In
  Rust, `value::parse_strict` is `parse_plain` (and `parse_content`), and `try_py_canonical_string` and
  `py_canonical_string` are `plain_dumps`, used only for the sink's line and a message.
  `prismpath/tests/test_plain_json_never_hashed.py` checks it at run time and in the source of Python and Rust.
- **Removed.** `canonical_compact`, `canonical_spaced`, `CANON1`, the `/1` root statement reader and
  `LEGACY_*` constants, `pyCanonicalString` (JavaScript), `value::parse_strict`, the `canonical` section of
  `durable.json` and the `canon` kind of `receipts.json`, and the corpora `canonical.json`,
  `receipts_canon1.json` and `hotswap_canon1.json` with `gen_canonical_fixtures.py`. `receipts.json` (245
  cases) and `hotswap.json` keep the cases built from what canon/1 wrote, as refusals.
  `host_trace.json`, `hotswap.json`, `receipts.json`, `durable.json` and `connector.json` were regenerated
  through their generators.
- **Not re-signed.** `prismpath-hw/demo/flows/*.ppt.manifest.*`, `prismpath-hw/demo-display/switch_nav.*` and the
  copies in `prismpath-hw/hyst-cert/evidence/` are pack manifests signed under canon/1 by a demo key whose
  private half is not kept (the evidence copies are named by an anchored `SHA256SUMS`), and
  `prismpath/comparisons/results/prismpath/evidence/A8/receipt_root.json` is a recorded comparison result; they
  stay as historic records and `verify_pack` refuses them (`prismpath-hw/hyst-cert/VERIFY.md`).
- **Not moved**, because it is not hashed or signed: the receipt stream's wire frames (binary Zeckendorf), a
  durable run checkpoint (state, whose values may be floats a resume must see unchanged), the flow authority's
  version floor file and the sink's JSONL records, and the comparison harnesses under
  `prismpath/comparisons/` (models of other systems).

### The product distribution of this repository

The product repository crystal-warden/prismpath is generated from this one by `tools/export_clean.py` and
carries the entries below as well. They were first written in the product repository, before it was a
generated mirror, and are recorded here so the history is in one place.

#### Added
- The four Rust crates (prismpath-rs, prismpath-telemetry-rs, prismpath-hotswap-rs, prismpath-preflight),
  each self contained: its tests read byte identical corpus copies under its own `tests/fixtures/`.
- The Facet wire in Python (`prismpath.telemetry`) with its tests and frozen corpora; the previous public
  repository carried the older adapter under `adapters/telemetry`.
- The table compiler as a package module, `python -m prismpath.kernel.ppt_compile`, with thirteen frozen
  regression references and the historical incident_severity image (`prismpath/tests/fixtures/compiler`).
- The Facet cutover verifier as a package module, `python -m prismpath.telemetry.canary_verify`.
- Mission Control with the September regroup of the package, the CLI runtime panels and file pickers.
- `COMPATIBILITY.md`, `DIVERGENCES.md`, `PROVENANCE.md`, `SHA256SUMS`, the product Dictionary subset,
  and the maintenance tools under `tools/` with their tests under `tools/tests/`.
- `tools/end_to_end.py`, one flow through the installed wheel (command line, engine, compiler, signing,
  policy host, ledger, wire, receipts, journal, preflight, Mission Control) and through the extracted Rust
  candidates, compared at every seam; a full leg acceptance gate and a release eligibility fact.

#### Fixed
- **The policy host now persists the active policy** (`<state dir>/active.ppt` and `active_policy.json`).
  `prismpath swap attest` and the console's attestation panel build a fresh host per call, so after a
  successful swap they attested `active: None`; both now report the committed policy. A record whose
  image is missing or of another digest is not restored and the ledger says so (`active_unreadable`).
  Found by the end to end run; applied to research at e28222c.
- Mission Control's model check and trail panels answered 500 on every call: the size guard read a
  constant the settings object does not have. Found by the end to end run; applied to research at e28222c.

#### Changed
- **The policy host's active image is content addressed and a rollback commits in the swap's order**, in
  Python and Rust alike. The image is `active-<sha256>.ppt`, written beside the one in use, and the record
  `active_policy.json` names it in `image_file`; the record rename is the flip point, and the superseded
  images and the intent record are removed only after it is durable. A death at any step now leaves exactly
  one policy a restarted host can restore (before: a death between the image and the record left a digest
  mismatch and no active policy). `rollback` writes its intent record (`"op": "rollback"`), then the audit
  event, then the image and the record, so a failing append raises `AuditWriteError` with the previous
  policy still active (before: the rollback had already flipped); an interrupted one is recorded as
  `rollback_incomplete`. A state directory in the old layout is read as before and moved to the new one by
  the next swap or rollback. Renames and removals are made durable with a directory fsync.
  Every file the host reads back (the record, the intent record, the audit log) is read through the strict
  readers and every file it writes through the refusing writers, so a record, an intent record or an audit
  line that holds NaN, Infinity or a number beyond the double range is damage that fails closed, and an
  event that would carry one is refused with `AuditWriteError` and the log unchanged. The host trace
  corpus holds 65 cases, among them those inputs; Rust returns `HostError::Canonical` instead of
  panicking where a record to be written has no canonical form.
- **The signed pack host commits a swap in a fixed durable order: intent record, version floor, audit
  event, then the reference flip.** Before, the flip came first, so a failure writing the floor or the
  evidence left the new policy active with the floor and the audit log behind it, against the documented
  promise. A failure now raises with the previous policy active; an interrupted commit is recorded as
  `swap_incomplete` at the next start and the same image at the same version may complete on retry
  although the floor already equals it.
- **The audit log persists before it commits.** `AuditLog.append` writes, flushes and fsyncs the event
  before adding its leaf, raises `AuditWriteError` with the log unchanged when the file refuses it, and
  `verify_persisted` answers the persistence question `verify_log` never did.
- **Telemetry retention and acknowledgment survive a restart.** `prismpath.telemetry.epoch_journal`
  is an optional durable journal around the epoch store: a fixed write order, a fixed recovery order,
  every interruption reported by name, disk limits that record a gap before the bytes go, and an
  acknowledgment receiver that persists its sequence before any deletion so a replay cannot delete
  more, before or after a restart.
- **One set of acceptance rules for Facet on both sides of the stack.** `quantizer.accept_value` and its Rust
  twin decide what a reading value is; `wire.encode_reading_checked` and `wire::encode_reading_checked`
  refuse a value with the field and the reason instead of truncating, coercing or reading it
  as zero; both preflight tools report `refused_by_field` per field and withhold READY on any
  refusal; `conformance/inputs.json` pins it in both languages. The Rust permissive path no longer
  reads a string that is not an integer literal as zero, which the Python reference never did; the
  Rust preflight's `coerced_to_zero_by_field` key is gone with the coercion.
- **The canary verifier has a strict mode.** `--id-field` correlates event identity and sequence between
  the legs, so a lost event replaced by a duplicate on the same route no longer passes; the route only
  mode stays the default for captures without an identity.
- **Acceptance refuses an unknown leg and a missing gate**, and a PrismPath flow, `tools/release_policy.md`,
  decides release eligibility over the acceptance facts with a receipt bound to the revision, the
  artifacts, the policy image and the reports (advisory; the script's exit status stays authoritative).
- Mission Control's audit log defaults to the platform state directory (`MC_AUDIT` still overrides) and
  a sprint launch runs the installed module under the console's interpreter in the followed project.
- `prismpath compile` is withdrawn: it built a bundle around the JavaScript engine, which is not carried.
  An explicit call exits 2 with a message; `prismpath portable` is unchanged.
- pyproject: the readme is `README.md`, the comparisons extra is gone, the JavaScript package data is
  gone, the fixtures ship with the tests, every URL points at this repository.

#### Removed, relative to the previous public repository (9129c27)
Adopters who used these find them in research at the adopted revision.
- The Go kernel (`prismpath-go/`), the standalone JavaScript kernel and playground
  (`prismpath/portable/*.mjs`, `playground.html`), the VS Code editor surface (`prismpath/editor/`).
- The Vector integration and the older Facet adapter (`integrations/vector/`, `adapters/telemetry/`),
  the fusion adapter (`adapters/fusion/`), the Zarf and UDS integrations.
- The comparison harness and the routing benchmark (`prismpath/comparisons/`, `prismpath/benchmark/`),
  the bypass measurement modules and their corpora (`prismpath/safety/bypass_*`, `measure_p1`,
  `gen_p1_lockfile`, `benign_corpus`; the generated `policies/p1_lockfile.json` stays), the four
  `prismpath/evals/eval_*` modules, `prismpath/measurements/`, `prismpath/deploy/`, the research
  lint tools under `tools/`, `ROADMAP.md`, `docs/decoder-ring.md`, `docs/objections.md`, the
  Gemma code nodes example and the JS and Go worker examples.
- Twenty four tests whose subjects are not carried: test_benchmark, test_comparison,
  test_comparisons_groupb, test_comparisons_matrix, test_comparisons_opa_runner,
  test_comparisons_prereg, test_comparisons_translators, test_comparisons_verdict,
  test_comparisons_toolchain, test_glue_opa_receipts, test_glue_opa_revision_floor,
  test_gate_zero_kappa, test_benign_corpus, test_bypass_corpus, test_bypass_report,
  test_gen_p1_lockfile, test_compile, test_portable_conformance, test_portable_runners,
  test_docs_health, test_evidence_check_manifest, test_mdflow_interop, test_net_swap, and the
  telemetry bench codecs test. The promotion to a0cccf8 adds three more, for the same reason:
  test_field_definitions_tables (the C interpreters), test_ebpf_table_limits (the eBPF evaluator) and
  test_arch_guard (research's architecture guard), and the declared hardware subset test in
  test_conformance_drift.

## [0.1.3] (never uploaded; released inside 0.2.0)

Was to be the first upload to PyPI since 0.1.0, and is now part of 0.2.0: it carries everything listed under 0.1.2 below, which was tagged but
superseded before any upload. It closes the gaps 0.1.2 left in its signed receipts work. Nothing here changes a format: root statements,
flow manifests, receipts and bundles read exactly as 0.1.2 wrote them, and a 0.1.2 log verifies unchanged.

### Added
- **`prismpath evidence verify RUN` checks a signed core run with no research tooling.** The verifier of a
  differential run as evidence (docs/design/spec-verified-core.md, section 11) ships in the package as
  `prismpath.ledgers.core_evidence`, with the producer, the oracle's ported policy check
  (`prismpath.kernel.core_policy`, was `formal/diff/core_policy.py`) and the reference's decision path
  (`prismpath.kernel.core_reference`, was the python leg of `formal/diff/core_diff.py`). It checks the keys
  against `--pin-authority` and `--pin-instance` (without both the root statement is `signed-unpinned`), the
  root statement, the Merkle root over the receipts, every image attestation and every receipt's hashes, and
  replays every receipt (`--sample all`) or a sample through the Python reference kernel; it exits 0 when the
  run verifies and 1 when it is refused, with the first failed check, and needs the `signing` extra and no
  numpy. `formal/diff/core_evidence.py` is the same verifier with the replay through the Lean oracle, and the
  research test holds the two replays to each other.
- **`resume` writes receipts and signs them like `run`.** It takes `--audit-log`, `--instance-key` and the
  authorization flags, looks for the deployment's key the same way (the flag, `PRISMPATH_INSTANCE_KEY`, then
  `<state dir>/instance.key`, named when used), writes a receipt for each decision taken since the
  suspension and a root statement with the trigger `resume-end`, and leaves a signed refusal receipt when
  the flow is not authorized. `seq` continues from the steps already taken, and each receipt carries
  `resumed` and `prior_steps`. A resume that cannot resume (a choice that is not an edge, a run that
  already finished) writes nothing.
- **`trail --verify-bundle FILE --pub KEY` checks a receipt bundle with no log.** Receipt, leaf, inclusion
  path, signed root, signature and key, offline. The result is `signed`, `signed-unpinned` or `invalid`
  with `trail`'s exit codes (0, 0, 1); a file that is not a bundle, or has a damaged path or hash, is
  `invalid` and not a traceback. `trail --receipt IDX --bundle-out FILE` writes the bundle, and a
  `--json` report that carries one is accepted too. `--anchor-dir DIR [--label L]` adds the
  OpenTimestamps step, which runs `ots verify` and so needs Bitcoin block data; the help says so.
- **`ledger anchor --log run.audit.jsonl` anchors an audit log from the command line.** It stamps the
  hash of the latest root statement when the log has any, otherwise the Merkle root, and the output says
  which, with how many of the log's events that statement covers. A log that does not verify, or is
  empty, is not anchored. The anchor leaves `log_<label>.json` beside the proof, and `ledger verify --log
  run.audit.jsonl --out DIR [--pub KEY]` reads it: the log verifies, still holds the anchored statement or
  root however much it has grown, and the proof verifies.
- **The authorization check is a library call, and the places that load a flow to decide use it.**
  `flow_authority.authorize_flow(path, policy)` returns what it found or raises `FlowNotAuthorized` with the
  registry causes; `load_authorized` also parses the flow; `AuthorizationPolicy` names the settings and
  falls back to `PRISMPATH_REQUIRE_AUTHORIZATION`, `PRISMPATH_AUTHORITY_PUB` and `PRISMPATH_STATE_DIR`.
  `checkpoint.run_durable`, `checkpoint.resume` and `ledger_runner.run_ledgered_loop` call it, so
  the timeout scheduler (which now skips a refused flow and carries on), `compose` and a Mission Control
  sprint that runs the sprint flow cannot step around it. `compose` takes the authorization flags,
  checks each fan-out's parent and child flow before it spawns or resumes anything, and exits 2 when one
  is refused. Mission Control refuses to start such a sprint and records `sprint.refused`.

### Changed
- **Mission Control's `/prove/audit` reports signing status** (`signing`, and `ok`): the status `trail`
  would give, the keys that signed, the events covered, the findings, and whether this console's own key
  made the statements. `valid` is unchanged.
- **Statement verification and signing are linear in the length of the log.** A log signed after every
  event rebuilt the Merkle tree once per statement, both when writing and when checking. The root is now
  kept as leaves arrive (`root_statement.MerkleAccumulator`) and the roots at every signed count come from
  one pass. On the development machine 4,000 events signed after each took 11.96 s to write and 3.14 s to
  verify before, and 4.77 s and 0.27 s now (8,000 events: 10.64 s and 0.52 s; what remains of the write is
  the signature and two `fsync` calls per event). The statement format is the same, and a test pins the new
  root equal to the old for every count to 300.
- **The policy host's active image is content addressed and a rollback commits in the swap's order**, in
  Python and Rust alike. The image is `active-<sha256>.ppt`, written beside the one in use, and the record
  `active_policy.json` names it in `image_file`; the record rename is the flip point, and the superseded
  images and the intent record are removed only after it is durable. A death at any step now leaves exactly
  one policy a restarted host can restore (before: a death between the image and the record left a digest
  mismatch and no active policy). `rollback` writes its intent record (`"op": "rollback"`), then the audit
  event, then the image and the record, so a failing append raises `AuditWriteError` with the previous
  policy still active (before: the rollback had already flipped); an interrupted one is recorded as
  `rollback_incomplete`. A state directory in the old layout is read as before and moved to the new one by
  the next swap or rollback. Renames and removals are made durable with a directory fsync.
  Every file the host reads back (the record, the intent record, the audit log) is read through the strict
  readers and every file it writes through the refusing writers, so a record, an intent record or an audit
  line that holds NaN, Infinity or a number beyond the double range is damage that fails closed, and an
  event that would carry one is refused with `AuditWriteError` and the log unchanged. The host trace
  corpus holds 65 cases, among them those inputs; Rust returns `HostError::Canonical` instead of
  panicking where a record to be written has no canonical form.

### Rust verification of signed receipts

- **`prismpath-hotswap-rs` verifies what 0.1.2 signs.** New modules `root_statement`, `merkle` and
  `flow_authority` check root statements (form, key id, Ed25519 signature over the domain prefixed
  canonical bytes, the `prev` chain, leaf counts, the root against a log's leaves, truncation, pinned
  keys, policy authority keys), whole audit trails (`verify_trail`, the Rust `AuditLog.verify_statements`),
  one receipt bundle offline (`verify_receipt_bundle`, with `pinned`), the instance and authority key
  separation (`check_separation`), and flow manifests (`verify_flow`) with the same registry causes
  (`sig:missing`, `sig:invalid`, `sig:revoked-key`, `manifest:key-id-mismatch`, `manifest:bad-format`,
  `flow:sha256-mismatch`, `flow:version-replay`) and the same version floor. Findings, statuses and
  checks carry the Python names. Verify only: nothing in the crate signs a statement or a manifest,
  generates a key or loads a private one for them. The crate's README lists where it is stricter than
  Python (small order keys, a boolean is not an integer, a flow that is not UTF-8) and what it does not
  read as Python does (integers past 64 bits, `NaN` and `Infinity`).
- **Frozen cross-language vectors**, `prismpath/portable/conformance/receipts.json`: 287 cases (56
  canonical JSON, 14 Merkle, 83 audit trails, 64 receipt bundles, 59 flow manifests, 6 version floor
  sequences, 5 key separation), each verdict produced by running the Python reference, covering a
  rewritten leaf, a truncated log, a wrong key, a broken or reordered chain, a bad signature, a flow
  edited by one byte, a version replay, a revoked key and an instance key presented as an authority.
  `prismpath/portable/gen_receipt_fixtures.py` writes them from fixed keys and clocks, so regeneration
  is byte identical; `prismpath/tests/test_receipt_vectors.py` refuses drift and replays every case
  through Python, and `prismpath-hotswap-rs/tests/test_receipt_verify.rs` replays them through Rust,
  which agrees on all 287. The bundle cases cover 0.1.3's bundle checks: the `status` (`signed`,
  `signed-unpinned`, `invalid`), the `index` check (the receipt's `idx` is the bundle's `index`), the
  `covered` check (`0 <= index < leaves`), and a bundle that is not shaped like one, which is `invalid`
  with the `problem` Python gives and no longer an error in either language (only a statement whose
  `key_id` is not text still raises, and Rust returns `Err` there).
- `prismpath_rs::durable::py_canonical_string` writes floats as Python's `repr` does (`1e-05`,
  `1.5e+20`, `1e+16`); it had used Rust's own spelling outside the range `1e-4` to `1e16`, which
  would have changed a receipt's leaf. Existing frozen corpora are unchanged.
- The hot swap crate is in CI (it already was, in `ci.yml`); its README and `docs/SYSTEM_MAP.md` said it was not.

### The engine follow-ups in Rust (2026-11-09)
- A Rust worker can name the kind of its failure: it returns `Result<Value, E>` for any `E: Into<WorkerError>`, and a
  `WorkerError { kind, message }` becomes the flow's `error_type` as Python's exception class name does (a plain
  `String` is kind `Error`, as every failure was before). `Step.error_type` carries it, an error no edge handles is
  `EngineError::Worker` with the kind and message kept, and `EngineError::reference_exception` gives the class and
  `str()` Python raises for it. A closure that never fails needs a type for its error: `Ok::<_, String>(value)`.
- An error guard that cannot be evaluated is recorded as SPEC section 5.3 says: `RunState::guard_errors` holds
  `{node, guard, error}` (persisted as `_guard_errors`, and kept from a resumed state) and `Step.guard_errors` counts the
  node's records; the `error` text is Rust's own words and is not compared.
- `parse` takes the reference's input bounds (`PRISMPATH_MAX_FLOW_BYTES`, `PRISMPATH_MAX_NODES`,
  `PRISMPATH_MAX_EDGES`, in characters, distinct node names and edge lines, with its messages and its order of
  checks); a document over one is an empty `Graph` with `parse_error` set (`Graph::refusal`), which the engine,
  `parse_checked` and the telemetry codec refuse, and `parse_with_limits` and `Limits` take the bounds as
  values. `parse_limits.json` is a new corpus from Python (49 documents under small caps, 6 built to the
  default caps, 21 environment strings) and a live Python parses 1500 random documents under random caps as the
  crate does.
- `Step.used` has Python's shape: `deterministic` with the edge in `cond`, and `embed` with `locked` true for a locked
  route (it was `deterministic: <cond>` and `locked`), `flows.json`'s `steps` hold each step's `used` and `cond`, and
  the cross language test compares each step's whole info, the scores to 1e-5, over the corpus and the sample.
- A route into an undefined node, which Python leaves as an unhandled `KeyError` and no document promises (`validate`
  reports the target as `undefined-target`), is pinned by seven `flows.json` cases (the target, the start, an empty
  flow, a capitalised target, an error edge, the last step and a resume) and is `EngineError::MissingNode` here, which
  `reference_exception` maps to the `KeyError`.
- `flows.json` has 33 more cases from Python (11 for the guard records, with `guard_errors` and `steps` now in the
  `expect` of every case that has `opts`), 15 for routing on `error_type` and for the unhandled worker error and 7
  for the undefined node, and `__raise__` outcomes take a `__kind__`; an expectation that is a refusal now carries `error_class`.

- Every test that makes a directory in the temporary directory now removes it when it ends, a failed assertion
  included (a `Scratch` value with a `Drop`, in `prismpath-rs/tests/common`, `prismpath-hotswap-rs/tests/common`
  and the preflight tests); the older hotswap host tests had left a `pp_host_*` directory for each case on every
  run, and the preflight and overflow tests an `fpf_*` and an `overflow_*` one. `test_lockfile.py` uses `tmp_path`.
  A full `cargo test --workspace` and `pytest` leave no new entry in `/tmp`.

### The engine surface in Rust (2026-11-09)
- `prismpath-rs/src/contract.rs` ports `kernel/contract.py` (derive, JSON Schema, `validate_output`, `declared_emits`,
  `describe`) with a reader of Python's whole expression grammar, since Python derives the contract with
  `ast.parse` and so reads what the sandbox refuses (`f(y)`, `x.y`, `-5` as a unary minus). `RunOpts` gains
  `type_gate` (a wrong typed field stops the run as `contract_violation`, cause 37, with the `violations` in
  `Pending`), `max_transcript` and the flow's `@state_bound(transcript=N)` (a sliding window with the dropped counts in
  `RunState.dropped`, a malformed bound refused before the run starts, the re-seeded path and steps bounded too) and
  `run_id`; `run_locked_decided` calls an observer with the routing decision record of each semantic route. A gated
  run is checkpointed, resumed and enforced by `durable`, and a checkpoint holds `_state_dropped`.
- `flows.json` has 45 cases after the 27 frozen ones for the type gate and the bound (a case with `opts`; a case per
  new stop value, per bound and per malformed bound), generated from Python (`engine_surface_fixtures.py`), and
  `contract.json` (56 flows, 21 outputs) is new. The conformance binary now reports 72/72 flows beside 1112/1112
  predicates and 8/8 locked flows.
- Both engines run 600 random flows and every corpus flow and agree on everything the surface holds, in order
  (`test_engine_cross_language.rs`); the crate also stops a stuck run's `on_step` at its node, as Python does, where it
  passed none, and a hostile `visits` or error count no longer overflows.

### Causes, receipts and the wire profiles in Rust (2026-11-09)
- `prismpath-rs/src/causes.rs` is generated from `prismpath.kernel.causes` by `prismpath/portable/gen_causes_rs.py`
  with the registry hash and the stop mapping; `RunResult.cause` carries the same code the Python engine gives on
  every flow of `flows.json` and `locked_flows.json` (their `expect` now holds `cause`); `registry_sha256` matches
  in both languages and a Rust test checks it against the live Python registry.
- `prismpath-telemetry-rs` has `receipts`, `replay`, `refresh` and `concentrator`, ported from the Python modules
  and replayed against `receipts.json` and four corpora generated from Python (`receipt_stream`, `replay`,
  `refresh`, `concentrator`); Python and Rust verify each other's receipts, datagrams and tick streams. The
  Zeckendorf codec refuses a code beyond `usize` and the encoder no longer overflows near `usize::MAX`.
- A manifest that cannot be parsed is `manifest:bad-format` with no manifest in both languages (Python raised, Rust
  answered `sig:missing`). The Python replay window no longer allocates a mask as long as a hostile tick jump.
- Open for the owner (settled 2026-11-10 below): causes 48 to 51 (`wire:no-terminator`, `wire:dangling-codeword`, `wire:symbol-overflow`,
  `wire:codebook-mismatch`) are registered and no code in either language emits them; nothing in the reference or
  its documents says where each fires, so none was invented.

### Canonical JSON refuses what it has no form for (2026-11-09)
- NaN, Infinity, -Infinity, a number beyond the double range (`1e400`) and a lone surrogate are refused
  in both languages, where canonical bytes are written and where a document that is hashed, signed or
  verified is read. Python raised nothing before and wrote `NaN` and `Infinity`; Rust refused them but
  read `1e400` as infinity. Neither converts any of them now. `prismpath.canon` has `CanonicalError`
  (write) and `CanonicalReadError` (read, a `json.JSONDecodeError`), `canon.loads`, `canon.load` and
  `canon.dumps_strict`; `prismpath-rs` has `value::parse_strict` and `durable::try_py_canonical_string`.
  An audit event that cannot be canonicalised raises `AuditWriteError` and leaves the log unchanged.
  The receipt verifiers read through the same strict readers in both languages (`root_statement` and
  `flow_authority` in Python, the `prismpath-hotswap-rs` receipt modules in Rust), so a statement, an audit
  line or a manifest holding one of those numbers is unreadable, not hashed, and `statement_hash` and
  `manifest_sha256` in Rust return `None` for a value with no canonical form. The README entry above
  that lists integers past 64 bits and `NaN` among what Rust does not read as Python does is superseded.

### Oddities closed in both languages (2026-11-10)
- A sign on an integer literal in a flow's predicate now types a number in the worker output contract: `derive_contract`
  folds the sign with `predicates.fold_unary_signs`, as every other reader of a predicate does, so `x == -3` and
  `x in [-3, -1]` give a number with the routed values -3 and -1 as `x >= -5` already gave a number. Before, they gave
  `unknown` and no values. A signed float, a signed field and a signed boolean still do not fold. Rust reads the same
  (`prismpath-rs/src/contract.rs`), and `contract.json` holds the corrected answer (58 flows, 23 outputs).
- A negative `max_transcript` is refused before the run starts, in both languages, as a negative `@state_bound` is:
  `ValueError` (`EngineError::BadStateBound` in Rust) with `max_transcript=-2: must be >= 0 (0 is no bound)`. Before,
  Python took -2 as a window that emptied the transcript and counted 14 dropped over a four step run. Zero is still
  no bound. `RunOpts::max_transcript` is an `Option<i64>` so the Rust caller can be refused as well; `flows.json` has
  two more cases (107 flows).
- Causes 48, 49 and 51 now have emitters, beside the decoders' own refusal strings and not in place of them
  (`docs/design/spec-cause-codes.md` section 6.1 has the table). A receipt decode, `concentrator.demux`,
  `wire.decode_reading` and the Rust strict stream decode report the registry code as `cause` where the refusal is
  exactly the registry's meaning: `wire:no-terminator` (48) for a non empty frame with no complete codeword,
  `wire:dangling-codeword` (49) for a partial codeword with data bits after a complete one, and
  `wire:codebook-mismatch` (51) for a symbol count that is not the policy's field count. A frame cut where only
  zero bits remain, an empty frame and an unknown stream id carry none. The results are still the plain pairs they
  were (`DecodedReceipt` and `Demuxed` are tuple subclasses with a `cause`); in Rust `DecodedReceipt.cause`,
  `concentrator::demux_cause`, `StrictDecodeError` and `WireRefusal` carry it. `receipt_stream.json` and
  `concentrator.json` list `registry_cause` per decode and demux case. Cause 50 (`wire:symbol-overflow`) still has
  no emitter, since no decoder here is handed a cell range, and the pin test keeps that for it alone.

### The verified policy core: evidence gaps closed (step 4, 2026-11-10)
Research line, `docs/design/spec-verified-core.md` sections 3.1, 7 and 11. Packs, envelopes, audit log
receipts, their root statements, anchored roots and every frozen corpus read and verify as before.
- **A differential run is canon/2 end to end.** Its root statement is a new format, `prismpath.core-run-root/1`,
  signed over its own domain prefix, integers and strings only, the signer's clock as `time_us` (microseconds,
  an integer) in place of an ISO string; Python and Rust write it and verify each other's. Only the `core-run`
  log moved: `prismpath-root-statement/1` and its verifiers are unchanged, and a run's verifier refuses a
  statement in that format.
- **A run excludes a case as `engine-counter` only when the oracle refuses its image for reading a counter.** The
  oracle's own check of an image (Lean `loadPolicy`, named `counterRefusal` for this use in `formal/Core/Scope.lean`)
  is ported to `formal/diff/core_policy.py` and to the Rust example, so producing a run needs no oracle; `core_evidence.py
  scope-check` holds both ports to the oracle on every image (100,000 of 100,000 for each, cause, code, field and
  reason). On the 100,000 case run the exclusion drops from 7,505 images that mention a counter to the 1,310 the oracle
  refuses for one, and 361,984 receipts are written (352,564 before), every one replayed and agreeing. Lean proves an
  excluded image refuses every reading with `policy:engine-counter` (`counter_excluded_refused`).
- **Lean ties a run's evidence to the semantics** (`formal/Core/Evidence.lean`). Over a model of a run and of its
  verifier with every receipt replayed (`verifyRun`), every accepted receipt records `Core.verdict` on the image and
  reading whose hashes it carries (`verified_receipt_is_verdict`), on any bytes with those hashes that collide with no
  document of the run (`receipt_is_verdict_of_hashes`); every reading of every case not excluded has its receipt;
  a recorded refusal is the verdict's registered nonzero code; and `evidence_sound` adds the root statement under
  unforgeable signatures and collision free hashing, each stated per object as an explicit hypothesis. No `sorry`; in
  the axiom audit.
- **`docs/research/verified-core-summary.md`** states for a reviewer what of the verified policy core is proven (each
  theorem in words), what is tested (the seven differential legs and their counts on the 100,000 case run, the
  frozen vectors, the evidence round trip), what is assumed (Ed25519, SHA-256, the Lean kernel and compiler, the C
  compiler, the hardware, the verifiers) and what is out of scope.

### The verified policy core: one cause per refused policy, runs as evidence, the eBPF leg (2026-11-10)
Research line, `docs/design/spec-verified-core.md` sections 4, 7, 9 and 11. Nothing here changes a format
already signed: packs, envelopes, receipts, root statements and every frozen corpus read as before.
- **A policy with several problems is refused for the first, in every implementation (D7).** The order of the
  spec's section 4 is normative: every rule decoded (each atom its name, operator and constant, a rule's depth
  after its condition), then the definitions in code point order, then every atom against its definition, then
  rule 6. `field_definitions.apply_definitions` and the Rust `apply_definitions` run `core_problems`, which
  enumerates the problems in that order before any text is lowered; the refusal is the first, with the field and
  reason the oracle names (`FieldDefinitionError.field` and `.reason`, Rust `Graph.field_error_field` and
  `field_error_reason`, new), and `problems` and `field_error_causes` keep the whole list, equal in the two
  languages. `definitions_of` parses in code point order. Before, the reference and the port named whichever
  problem their own phases met first. Lean proves the core's refusal is the head of the same order
  (`formal/Core/Order.lean`, `loadPolicy_first_problem`, in the axiom audit). The frozen field definition vectors
  gain seven `d7_*` policies (44 refused), and the Rust replay now checks the port's whole problem list.
- **A differential run is evidence.** `formal/diff/core_evidence.py` and `prismpath-hotswap-rs/examples/core_evidence.rs`
  produce a run: each image's canon/2 bytes signed with the authority key, a canon/2 receipt per decision binding
  the image hash, the reading hash and the registered cause, and one root statement (log `core-run`) over the
  receipts signed with the instance key and binding the run's manifest. Their `verify` re-checks the statement,
  every receipt and attestation, and replays a sample (or all) through the oracle; each language verifies the
  other's run (100,000 cases, 352,564 receipts, every one replayed, none differing). Keys are test keys generated
  per run.
- **The eBPF table target is a differential leg** on its userspace path (`formal/diff/ebpf_batch.c`): the in-kernel
  evaluator's own text, `prismpath-ebpf/ppt_eval_bpf.h`, over a shim of its maps and `bpf_loop`, behind the
  loader's parser. Loading in kernel needs CAP_BPF; the kernel certification stays the CI job's. The 100,000 case
  run shows no finding on any of the seven legs.

### The eBPF evaluator carries what the C interpreter carries (2026-11-10)
Research line, `docs/design/spec-verified-core.md` section 9 (D6, step 4). Nothing here changes a table format, a
signed image or a frozen corpus: the 147 of 147 in kernel are the same vectors.
- **An operand stack of 64 and no per program or per node bound short of the maps.** The 86 readings the 100,000
  case run counted as outside the eBPF subset were edge programs past 64 words and operand stacks past 4, both of
  which `interp.c` runs. The stack is now one `__u64` (`st_get` and `st_put` are a shift by a masked amount, not a
  `switch` an arm a slot), `STACK_MAX` is 64, and `MAX_PROG_PER_EDGE` and `MAX_EDGES_PER_NODE` are the map
  capacities. `prog_word_cb` shrank from 423 to 332 instructions. The 32 bit limit is unchanged and stays a
  compile time refusal on every table target (the spec says why). The 100,000 case run shows the eBPF leg agreeing on
  146,673 readings as `c-interp` does, no subset refusal, no finding on any of the seven legs.
- **The verifier's acceptance is checked in the kernel job and, as far as it can be, without one.**
  `prismpath-ebpf/verifier_budget.py` holds each built object to the combined stack of 512 bytes, no cycle in the
  evaluator outside `bpf_loop` and its shape; `cert_corpus.py --boundary` writes 35 records of the evaluator's bounds
  that the `ebpf_kernel` job loads and replays in kernel; `prismpath/tests/test_ebpf_evaluator_bounds.py` runs the
  same tables natively. `formal/diff/core_diff.py` takes the oracle's path from `PRISMPATH_CORE_ORACLE`.

### The JavaScript and Go kernels decide the verified core (2026-11-10)
Research line, `docs/design/spec-verified-core.md` D5. Nothing here changes a format already signed or a frozen
corpus: a flow that defines no field parses and runs as before.
- **Both kernels implement field definitions (SPEC section 4.5) and no longer refuse a flow that defines its
  fields.** `parse` reads the `field.<name>` definitions with Python's whitespace, checks the policy in the
  core's order (the problems of the spec's section 4, one cause for a refused policy), and lowers every decimal
  threshold compared with a `fixed` field to its canonical integer from its source span, exactly (`BigInt` in
  `prismpath/portable/prismpath.mjs`, `math/big` in `prismpath-go`). A refusal is a `FieldDefinitionError` (both)
  with the registered cause 89 to 100 or 74 to 76, the field and the reason, and every problem in order; the
  Go graph keeps every edge disabled and `Run` refuses it. New: `systemBoundary` and `policyCheck`
  (`SystemBoundary`, `PolicyCheck`), `canonicalValue`, `acceptCanonical`, and a canon/2 reader and writer
  (`canon2Read`, `canon2Write`; `Canon2Read`, `Canon2Write`) with the frozen vectors replayed in
  `run_vectors.mjs` (`canon2.json` 73 of 73, `field_definitions.json` 156 of 156) and in
  `prismpath-go/conformance_test.go`.
- **Evaluator corrections the core needed.** JavaScript no longer counts a bracket as predicate depth and
  refuses more than 200 open brackets, as the reference and the Rust port do; Go reads `and` and `or` as one
  n-ary node (a flat chain of operands is one level, as Python's syntax tree holds it) and `\xNN` in a string as
  the code point rather than the byte; both read front matter with Python's whitespace, so U+FEFF is not
  stripped.
- **The differential harness has no refusing kernel and no reader gap.** `core_diff_js.mjs` and
  `prismpath-go/cmd/core_diff` compose the kernels' own functions as the Python and Rust legs do, read canon/2,
  and speak the cause registry. The 100,000 case run shows no finding on any of the seven legs.

## [0.1.2] (tagged, superseded before upload; never on PyPI)

### Summary since the 0.1.0 upload to PyPI

The 0.1.0 files on PyPI were built on 2026-08-17 from commit `6cafd86`, which is 179 commits after the
`v0.1.0` tag (`990f493`, 2026-08-05); RELEASING.md has the evidence. This summary covers the 368 commits
after `6cafd86`, grouped by what a user of the package meets. The detailed entries below it are the
record, and some of them predate the upload.

- **Installing and extras.** The README, the getting started guide, the PyPI page and the guides now say
  which extra each feature needs (`embeddings`, `signing`, `control-plane`, `llm-local`) and that the
  ledger commands call the external `ots` client. The wheel ships every package under `prismpath` by
  discovery, so `prismpath.comparisons` and `prismpath.portable` are no longer missing from it, and the
  package metadata carries an SPDX license expression and the documentation and issue links.
- **Command line.** `--help` groups the commands by the four people who run them (process owner,
  engineer, operator, assessor). New: `prismpath trail` reads an audit log, `swap attest` shows an
  overlay, `facet quantize` and `encode` refuse a bad payload with the field and the reason and exit 2,
  and the ledger commands return the OpenTimestamps client's exit code. `run --worker` replaces
  `--agent` (the old flag still works, hidden).
- **Package layout.** The flat layout became eight subpackages (`kernel`, `routing`, `safety`, `hotswap`,
  `ledgers`, `workers`, `orchestration`, `evals`); the 67 old module names still import and now warn.
  The Facet wire ships in the package as `prismpath.telemetry`.
- **Flow format and engine.** Field definitions (SPEC section 4.5) let a flow sign the meaning of every
  value it routes on, with one acceptance rule on every encoder that refuses a value rather than
  truncating it. Receipts carry a cause from the refusal and deviation registry. An error edge guard that
  cannot be evaluated is recorded, the embedding router's cache is bounded, the type gate survives a
  crash resume, and an unparseable audit log line fails `verify_log` rather than vanishing.
- **Signed packs and hot swap.** A durable commit protocol, an explicit audit persistence step, and an
  active policy that survives a new process, so `swap attest` reports what a real swap left running.
- **Signed roots and authorized flows.** A deployment's instance key (`ledger keygen`) signs a chained
  root statement over its audit log, so a receipt verifies offline back to a root the deployment
  signed and `trail` names a log cut short, a rewritten receipt, a foreign key or a broken chain. The
  policy authority key signs an ordinary Markdown flow (`authorize sign`), and `run
  --require-authorization` refuses a flow that is unsigned, edited after signing, signed by an unknown
  or revoked key, or older than a version already accepted. Before this, nothing bound a receipt to
  the deployment that wrote it, and a flow with semantic edges could not be authorized at all.
- **Facet wire.** The refresh, tick replay, concentrator, receipt stream and spiral packing profiles
  (PROTOCOL.md sections 2.7 to 2.10) and a durable epoch journal.
- **Mission Control.** Panels for inspect, quality, proof and policy, and a file picker instead of a
  typed path.
- **Documentation.** The public position (docs/POSITION.md), the Decision Dictionary, the operator's
  guide and system map, METHODOLOGY.md, and README front doors for the crates. Install snippets in the
  guides now import from the grouped module paths.
- **Not in the wheel.** The compliance adapter (OSCAL and CycloneDX output, the SSDF and Cyber Resilience
  Act catalogs, VEX, the pack SBOM), the Vector integration and Wireshark dissector, the hardware, eBPF,
  FPGA and firmware work, the Lean proof of Figueroa quantization, the pre registered comparison and the
  evidence ledger live in the repository.
- **Command line errors.** A missing or unreadable file, a flow that does not parse, malformed JSON, a
  worker that does not answer and a missing optional extra now end in one line on stderr naming the
  command, with exit code 2, instead of a traceback; `PRISMPATH_DEBUG=1` shows the traceback. A missing
  extra names the install line (`pip install 'prismpath[embeddings]'` and so on). The ledger, `ci-report`
  and RFC 3161 commands check for `ots`, `git` and `openssl` before they start. `calibrate`, `label` and
  `trail` refuse a missing log rather than reading it as empty. `init NAME` writes `NAME.md` and
  `NAME.tests.md`.
- **Found by running every documented capability.** The browser playground, the first path in the
  getting started guide, showed empty panels because the portable kernel imported `node:crypto`, which no
  browser resolves; the kernel now carries its own SHA-256 and imports nothing, so the playground and the
  bundles from `prismpath compile` load in a browser. `prismpath ledger anchor --repo` died on the
  Flow-Ledger's `sha256:` output hashes; `verify --forbid` or `--reach` with a node name the flow does not
  have said "proven unreachable" and passed, and now refuses; `test --emit-labels` records the embedder's
  margin so `calibrate` has something to read, and `calibrate` refuses a log with no margins instead of
  printing a threshold with a guarantee over nothing; `annotate` names a benchmark row that lacks `flow`
  or names a node the flow does not have, and stops cleanly when its input ends; `facet decode` ends a
  bad frame in one line; `prismpath --version` exists. `swap` takes the envelope by its `.json` file name
  as well as its base path. Mission Control starts a sprint by module (the path it ran was an alias that
  never started anything), answers a bad `queue/decide` with a 400, follows the flow and not its
  `.tests.md` fixtures, and says which extra a missing `uvicorn` belongs to. The wheel carries the `.md`
  flows its shipped examples run. Guides that named old module paths or an unquoted `@spawn` now match
  the code.

### Added
- **Root statements, signed with the deployment's instance key** (`prismpath/ledgers/root_statement.py`).
  A statement is one JSON line in the file beside the audit log (`run.audit.jsonl` beside
  `run.audit.roots.jsonl`) giving the Merkle root, the number of receipts it covers, the hash of the
  statement before it, the time, the key id and public key, and the policy in force, with an Ed25519
  signature over a domain prefix and the canonical bytes. `prismpath ledger keygen` writes the instance
  key (private half 0600, never replaced once it exists). `run --audit-log PATH` writes one receipt per
  decision and one for a refusal or park with its cause, and with `--instance-key` or
  `PRISMPATH_INSTANCE_KEY`, or by default with the deployment's own key at `.prismpath/instance.key` (the state
  directory), which it names when it uses it, signs a statement at the end of the run; without a key it says
  the receipts are unsigned. The policy host, the crypto host and Mission Control sign after every audit event when
  the variable is set, and the durable epoch journal signs each seal when given the key. `trail` reports signed, unsigned
  or invalid; `--pub` pins the key, so a log with its statements deleted is invalid rather than
  unsigned, and `--receipt IDX` checks one receipt through its inclusion path to the signed root.
  `ledger anchor --statements` stamps the statement hashes, so the timestamp covers the signatures.
  Logs written before this have no statements and still read and verify, reported as unsigned. The
  signature checks are offline; an OpenTimestamps proof still needs Bitcoin block headers to verify.
- **Flow manifests: the policy authority authorizes a Markdown flow** (`prismpath/hotswap/flow_authority.py`).
  `prismpath authorize sign FLOW --priv authority.key --pub authority.pub --version N` writes
  `FLOW.manifest.json` and `.sig` (the flow's sha256, name, version, field dictionary when defined,
  key id, time); `authorize verify` checks it. `run --require-authorization --authority-pub PUB` (or
  `PRISMPATH_REQUIRE_AUTHORIZATION` and `PRISMPATH_AUTHORITY_PUB`), and `resume` with the same flags,
  refuse with exit 2 and the cause: `sig:missing`, `sig:invalid`, `sig:revoked-key`,
  `manifest:key-id-mismatch`, `manifest:bad-format`, and two appended registry rows,
  `flow:sha256-mismatch` (87) and `flow:version-replay` (88), the version floor kept in `--state-dir`.
  The refusal is itself a receipt. Without the requirement a manifest that is present is verified and
  reported. Receipts and root statements record the flow manifest hash, authority key id and version,
  or `unauthorized`. The instance key and the authority key are kept apart: a host and `run` refuse an
  instance key that is also a trusted authority key, and `authorize sign` refuses the key
  `PRISMPATH_INSTANCE_KEY` names.
- **Parity note, not ported.** The Rust hot swap host (`prismpath-hotswap-rs`), the Rust epoch chain
  (`prismpath-telemetry-rs`), the eBPF receipt sealing (`prismpath-ebpf/seal_receipts.c`), the mesh
  firmware receipts (`prismpath-hw/mesh/`), and the Rust, Go and JavaScript kernels and compiled bundles
  write or carry receipts and roots without root statements, and none of them checks a flow manifest.
  Their roots can still be anchored as before. *Since this note was written (Unreleased, above):*
  `prismpath-hotswap-rs` now verifies root statements, audit trails, receipt bundles and flow manifests
  the Python engine produces, against frozen vectors; none of the ports writes a root statement or
  signs a flow manifest, and the other ports still neither verify nor check them.
- **A CycloneDX 1.6 SBOM for a signed policy pack, from the compliance emitter**
  (`adapters.compliance.emit.pack_sbom`, `python -m adapters.compliance.emit --pack-sbom`), beside its
  OSCAL and CycloneDX attestation output and validated with the same cached schemas. It restates the
  verified manifest (image SHA-256, version, signing key, envelope, WCET bound, field dictionary, and
  the authored flow's hash when the pack recorded one), is written only for a pack that verifies and a
  document the schema accepts, and is the same document for the same pack. Zarf's own SBOM of a policy
  package lists no artifacts and no files (Zarf 0.87.0), so the Zarf demos now ship this one beside the
  policy.
- **`integrations/zarf-kernel/`: delivery through activation.** Zarf delivers the signed pack, the
  host verifies and swaps it, and `activate.sh` loads the host's accepted copy into the in-kernel
  evaluator only after its hash matches the attestation, then checks the kernel's path for a probe
  reading against the host reference and writes `deployed/activation.json`. A tampered package
  stops at verification; a copy replaced on disk after acceptance is refused before the kernel is
  touched. The probe reading is encoded with the compiler's binding of the same flow, which the pack
  does not yet sign; `make_probe.py` refuses unless the flow recompiles to the delivered image.
- **Supply chain catalogs and a policy delivery assessment in the compliance adapter.** Two new
  selectable standards: `nist_ssdf` (NIST SP 800-218 v1.1, 19 practices and 42 tasks) and
  `eu_cra_annex_i` (the Cyber Resilience Act's Annex I, Parts I and II, 22 requirements), with text
  verbatim from the publication and the Official Journal. `assess_policy_delivery.py` runs its own
  checks on a deployed pack and emits OSCAL Assessment Results, POA&M and CycloneDX attestations for
  each. On the Zarf kernel deployment it finds SSDF PS.2 met, PS.3 and PW.4 partially met, and Annex I
  (2)(f), (2)(l), Part II (1) and (7) partially met, with everything else reported not assessed.
- **The emitter names the standard its records were assessed against** (`standard=`, default NIST SP
  800-171 Rev 2 with unchanged output), and takes `not_assessed=` for a scoped assessment: the OSCAL
  result then reviews only the assessed controls and lists the rest in its remarks, and the CycloneDX
  attestation map leaves them out.

### Deprecated
- **`agent` as the name for whatever does a node's work; the word is `worker`.** `run(agent=...)`
  is `run(worker=...)`, `prismpath.workers.cli_worker.cli_agent` is `cli_worker`,
  `prismpath.plugins.registry.worker_agent` is `worker_for`, and the `prismpath run --agent SPEC`
  flag is `--worker SPEC`. Every old spelling still works and still reaches the same code: the three
  Python names raise a `DeprecationWarning`, and the flag is a hidden alias on the same destination,
  so a script that passes `--agent` is undocumented rather than broken. They go away in a later
  release. The dictionary's **worker** entry lists all four as deprecated synonyms; `WorkerFn` was
  already the right name for the type.
- **The flat module names under `prismpath/`** (`prismpath.policy_pack`, `prismpath.ledger_ots`, `prismpath.analysis` and the other 64 aliases left by the September regroup into `kernel/ routing/ safety/ hotswap/ ledgers/ workers/ orchestration/ evals/`) now emit a `DeprecationWarning` on import and go away in a later release. Every first party import already uses the grouped path; adopters should import from it too.

### Changed
- **The readability refactor: the big files are split, the vocabulary is one word per thing, and no
  public name moved.** What moved: `cli.py`'s embedded 193 line JavaScript engine left for
  `prismpath/portable/bundle_engine.mjs`, where it reuses the kernel's tiers instead of disagreeing
  with them, and one `scriptedAgent` exported from `prismpath.mjs` replaced three hand kept copies;
  `prismpath/mission_control/core.py` became a facade over one module per job, with every path, port
  and cap on one `Settings` object; the connector's six ports became six mixins behind an unchanged
  `BaseConnector`, and `deferral.py`'s `__main__` self test became `prismpath/tests/test_deferral.py`;
  the fusion and compliance adapters, the fusion bench and the Vector integration became packages, so
  29 `sys.path` inserts went and the quantizer's four private helpers went public; `prismpath-rs`
  split `lib.rs` into `parser`, `engine`, `condition`, `level_m`, `reach`, `value`, `compose`,
  `connector`, `durable` and `crypto_agility`, all re exported from the crate root; the eBPF loader
  split into `ppt_image.c` (read, validate and evaluate an image on the host, no libbpf) and
  `ppt_maps.c` (fill the maps, stamp the policy hash, carry the selector's resident state across a
  swap) under a `loader.c` that is now one command table; the four XDP programs include one evaluator,
  `ppt_eval_bpf.h`, instead of four copies kept in step by hand; `rtl-tb/gate.mk` gave eleven
  ungated cocotb testbenches a real pass or fail target; and six companion walkthrough documents
  landed beside the code they explain (`prismpath-hw/EVALUATOR_WALKTHROUGH.md`,
  `PPT_FORMAT_WALKTHROUGH.md`, `esp-vision-node/FRONT_END.md`, `esp-vision-c6/RELAY_WALKTHROUGH.md`,
  `rtl-tb/README.md`, `prismpath-ebpf/EVALUATOR_WALKTHROUGH.md`). What was renamed, all of it against
  `docs/DICTIONARY.md`: the routing outcome is a `route` and the GRC outcome is a `determination`; a
  wire struct field holding an edge's declared destination is `target`; `nid` is `device_id`; a
  selector's `posture` is its `resident_node`; the receipt decoder's two senses of cause are
  `cause_code` and `refusal_cause`; the persona who reads receipts is the **assessor** and the build
  loop is **orchestration**, not "the control plane"; the per node callable is a **worker**; and the
  single letter locals across Python, the tests, telemetry, the compliance and fusion adapters, the
  hardware harnesses, the firmware C, the eBPF sources, Rust, Go and JavaScript took dictionary
  names, as did the vision firmware's one letter geometry macros (`FRAME_W`, `FRAME_H`). What a
  caller must do: nothing. Every import path, CLI verb, wire byte, frozen corpus and signed image is
  unchanged; the four renamed call surfaces keep their old spellings as deprecated aliases (see
  Deprecated above); the certified bytes (`interp.c`, the RTL,
  the eBPF programs, the cause registry) did not move, and the walkthrough documents exist because
  they cannot.
- **The README is restructured around the public position.** `docs/POSITION.md` is the canonical
  statement (one sentence, problem, prove/enforce/prove, capability status, what the comparison
  established, vocabulary contract, claims made and not made); the README, the site, and the package
  docstring are views over it. The hero says what PrismPath is, a control plane for autonomous systems,
  one of many, and the approach is what is unusual; Figueroa quantization and Facet move out of the
  hero into their own section; the comparison verdict is on the front page as the claim that did not
  survive. `prismpath.__init__` describes the grouped layout and the reading order.
- **`Graph.validate()` is gone; use `analysis.errors(graph)`.** The parser no longer imports the
  analyzer (it was the one cycle in the kernel), the Level M classifier lives in its own module
  `prismpath.level_m` (re exported from `model_check`, so `ppt_compile` and every caller keep their
  names), and the shared parse and traversal helpers moved down to `predicates.expr_ast` and
  `parser.reachable`. `prismpath.canon` holds the byte level helpers that were copied across
  modules; nothing persisted or signed changed bytes (the frozen corpora regenerate identically).
- **The Facet wire ships in the package as `prismpath.telemetry`** (moved from `adapters/telemetry`).
- **The package is grouped by concern.** `prismpath/kernel/` (parser, predicates, engine, causes,
  contract, analysis, level_m, model_check, lint, graph_export, flow_context, flow_test),
  `routing/`, `safety/`, `hotswap/`, `ledgers/`, `workers/`, `orchestration/`, `evals/`, beside
  `telemetry/`. Every old flat name (`prismpath.engine`, `prismpath.checkpoint`, ...) stays
  importable and is the same module object, so `from prismpath.checkpoint import _atomic_write`
  and monkeypatching keep working; new code should use the grouped paths. `python -m` entry points
  moved with their modules (`prismpath.safety.fuzz_predicates`, `prismpath.routing.prefilter`,
  `prismpath.orchestration.run_sprint`).
- **Crate renamed: `facet-preflight` is now `prismpath-preflight`.** The `facet-*` prefix on
  crates.io belongs to the facet reflection ecosystem; the collision was flagged by r/rust and the
  crate moved out of that namespace the same day (same code, same contract, binary renamed to
  match; `facet-preflight 0.1.0` deleted outright, inside the 72 hour window, so nothing of ours remains in that prefix). The Python twin identifies
  itself as `prismpath-preflight` too. The Facet *wire protocol* keeps its name in the papers and
  `PROTOCOL.md`, namespaced in prose as PrismPath Facet: a protocol and a crates.io prefix are
  different namespaces, and only the latter was trespassed.

### Added
- **`prismpath-preflight --privacy`: the privacy claim as a measurement, not an adjective.** Adds
  a per-field reconstruction bound (numeric fields report worst-case cell width + unbounded/
  singleton counts, booleans leak their bit, categoricals are exact on enumerated values and
  collapse the rest) and, for fusion policies, an aggregation-privacy report: how many joint input
  cells produce each verdict (a verdict made by many input cells hides which inputs made it,
  information-theoretically, even against a policy holder; one made by a single cell pins them).
  Opt-in, so the default report and the Python/Rust differential are unchanged; three new tests.
  Turns "decision-lossless, not data-lossless" into a printable number per policy.
- **Million decision soak** (`integrations/vector/soak/`, evidence #105 staged): two native codec
  Vector pipelines ran unattended for 31 and 27 hours, 1,043,442 decisions decoded, zero errors
  of any kind, flat memory, route distributions stable to a tenth of a point across inputs
  spanning nine orders of magnitude; total wire for the entire run ~1.8 MB (2.000 and 1.466
  B/event framed).
- **C2a: the wire encoder measured on bare metal** (`prismpath-hw/codec-bench/`, evidence #104
  staged). A portable C Zeckendorf encoder (78 entry table covering 2^53, 624 B constant data),
  verified byte for byte on device against reference generated wire bytes before timing, then
  measured on all four MCU instruction sets that decide policies: typical 4 field events in
  4.6 to 9.3 us on the 32 bit cores and 463 us on the 8 bit AVR floor tier (stress 1,000 cell
  codebook: 13.7 to 27.9 us and 1.76 ms). The FQ paper's §5.5 codec cost model is now a
  measurement; Merkle and the FPGA shift register half stay modeled and named.
- **`prismpath-telemetry-rs 0.1.1`: fallible twins for the spiral (Tier 6) API.** Every panicking
  spiral method now has a `try_` variant returning `Result` (`try_cell`, `try_index`,
  `try_band_id`, `try_route_of`, `try_reconstruct`, `try_reconstruct_band`,
  `try_encode_decision`, `try_encode_progressive`), std indexing style: the panicking form is the
  documented convenience, the fallible form is the total function. Purely additive, behavior of
  the existing API unchanged (two new tests pin `try_` == panicking on every frozen corpus probe,
  and Err instead of panic on missing fields and out of range indices). One internal cleanup:
  the quantizer's remaining guarded `unwrap` became `is_none_or`. The codec path was already
  panic free; this closes the gap on the optional tier.
- **prismpath-preflight, the adoption gate for the Facet codec** (now `prismpath/telemetry/preflight.py`; in the package it runs as `python -m prismpath.telemetry.preflight`).
  One command takes a policy flow plus a sample of real events (NDJSON) and reports the derived
  codebook, exactly which events encode and why the rest do not (missing fields, unmapped nested
  paths via `--map`, out of partition values, float truncation), projected bytes per event next to
  the raw JSON, and the route distribution at every branch point. Every encodable event is replayed
  through the full round trip (quantize, Fibonacci-code, decode, reconstruct) and checked to route
  identically to the original at every decision node, so decision preservation is verified on the
  integrator's own data. Flags mirror the Vector codec exactly (`--map` = `field_paths`,
  `--on-missing` = `on_missing`, one byte aligned reading per frame); exit 0 only when nothing needs
  attention, so it drops into CI. Seven-case test suite; the stale Vector run commands in
  `integrations/README.md` were corrected to the native two instance pipeline at the same time.
- **prismpath-preflight in Rust** (`prismpath-preflight/`, new workspace member; binary
  `prismpath-preflight`). The same contract as the Python tool (flags, report sections, JSON schema,
  exit codes) running on the exact crates the Vector codec is built from, so its report is what
  the codec will do by construction and it speaks the upstream audience's language
  (`cargo run -p prismpath-preflight`). The two are deliberate twins: Python = the independent
  reference oracle, Rust = the codec's own path; running both on one sample is a differential
  test of the stack, and on the clean corpus their JSON reports are identical. The port also
  surfaced a real value-model divergence the Python tool cannot see: the crates coerce a
  non-numeric string on a numeric field to 0 (the reference errors instead), so the Rust tool
  reports COERCED TO 0 per field and withholds READY. Seven integration tests against the
  compiled binary, including the coercion case; clippy clean. Published to crates.io as
  `facet-preflight 0.1.0` on the owner's go; the registry-installed binary verified end to end
  (`cargo install facet-preflight`, the name at publish time; since renamed, and the old crate
  deleted, see Changed above).
- **facet-init, the migration drafter** (now `prismpath/telemetry/facet_init.py`; in the package it runs as `python -m prismpath.telemetry.facet_init`). Reads the
  `vector.toml` an integrator already runs, transcribes every route and filter condition that is
  Level M expressible (`field OP const` under and/or/not, `includes([..], .field)` as `in`) into a
  DRAFT flow with the transforms chained as nodes, maps nested event paths to codec `field_paths`
  suggestions, and verifies the draft end to end through the preflight tool on the sample. Conditions
  that do not transcribe (function calls, regex, VRL variables, field vs field, null, float
  thresholds) are reported verbatim with the reason. No condition is ever learned from the sample:
  the tool drafts and the author signs, preserving the derived-from-authored-policy property the
  quantization paper's §3.4 rests on. Skeleton mode (no `vector.toml`) annotates discovered fields
  and writes zero conditions. Six-case test suite covering transcription, refusal reasons, chain
  stitching, and the end to end preflight-ready loop.
- **Canary recipe for cutting over to Facet** (`integrations/vector/CANARY.md` +
  `canary_verify.py`). Run Facet beside the pipeline you trust: one source fans out to the
  existing sink unchanged and to a Facet sink, an aggregator decodes the wire, and the verifier
  replays every raw event through the reference implementation to prove the decoded leg routes
  identically (counts, every position, per route distributions; encoder dropped events keep
  positions synchronized). Exit 0 only on parity, so the check drops into CI during the soak.
  Live proven with the fork build: 400 events across seven routes, exact parity; a single
  tampered threshold crossing is named by position and fails the run. The doc covers policy
  pinning via `policy_sha256`, `field_paths`, cutover and rollback (the raw leg is the
  parachute), and honest scope (representatives not magnitudes, ordering assumptions, the 2^53
  bound). Five-case test suite.

### Removed
- **Pruned two unvalidatable adapters and the redundant native crate; genericized fusion.** The
  `adapters/soc/` and `adapters/compliance/` adapters and the `prismpath-fusion-rs` crate were archived
  out of the shipped repo (preserved on device), along with the fusion adapter's `live_capture.py` live
  capture harness and the `cw-triage` systemd poller units. The fusion adapter is reframed as **the
  decision fusion plane**: it joins any N decision sources into one Level M decidable, provable fused
  decision carried on the Facet wire, with the cyber plus IMU pairing kept as its v1 worked example and
  the SIEM source demoted to one example connector (archived). The reference adapters are now telemetry
  and fusion; CI drops the soc and compliance test steps and the fusion suite stays green. The removed
  adapters' historical evidence rows are retained and annotated, not rewritten.

### Changed
- **The eBPF live hot swap is now double buffered and proven atomic under concurrency** (evidence
  #93), closing the "still element-wise (not double-buffered)" caveat from #88. The `ppt_net`
  program's four table maps are doubled into two banks; a packet reads a single `__u32` bank
  selector (`bank_map`) once (an aligned load, atomic against the loader's aligned store) and
  evaluates entirely within that bank. `netupdate` writes the inactive bank in full, then commits
  with ONE update to `bank_map`; a failed inactive-bank write is never committed, so the active
  policy is untouched on any error. New `loader netstorm <a> <b>` proof: a thread flips banks
  0↔1 while another hammers `BPF_PROG_TEST_RUN`; **200,000 evaluations under ~500k concurrent
  flips, TORN=0** on both aarch64 and x86_64, verdicts split ~50/50 between banks (the race was
  real). The conformance program `ppt_xdp` is single bank and untouched; **124/124 unchanged on
  both architectures**.

### Added
- **Crypto-agility control plane; govern *which* crypto suite is authorized to be live, provably**
  (`prismpath/crypto_registry.py`, `crypto_agility.py`, `crypto_host.py`; spec
  `docs/design/spec-crypto-agility.md`; evidence #94). A crypto-suite-selection policy is a Level M
  match action flow whose terminal nodes are the suites, so five machine checked proofs turn
  governed crypto-agility from a claim into a property: **P1** no reachable state selects an
  unapproved suite, **P2** every context routes to a defined suite (no silent default cipher),
  **P3** a data class never routes below its floor suite, **P4** once past a migration phase no
  classical-only suite is reachable (algorithm-level anti-rollback, proven *statically*; the
  matrix `crypto_migration.json` confirms P4 holds ⇔ floor ≥ gate in all 12 cells), **P5** the
  policy is decidable. The runtime `CryptoHost` accepts a swap only when Authorized (signed pack) +
  Envelope-bounded (declared suites ⊆ approved AND the pack's `registry_hash` matches the live
  signed registry, so a swap can't re-point a suite id at a weaker primitive) + monotonic (version
  floor) + provider-available, and **provider absence refuses rather than downgrades**: on a host
  whose vetted `cryptography` lacks ML-KEM, the CNSA-2 policy swap is refused and the live classical
  policy stays put, never silently weakened. Every attempt is one Merkle-logged audit event. 26
  tests; four deliberate-fail conformance cases keep the proofs falsifiable. **Control plane, not
  cipher:** PrismPath governs selection/proof/attestation and delegates every operation to a vetted
  provider; ML-KEM/ML-DSA registry rows are inert-until-a-provider-ships-them, disclosed as prior
  art now. Rust mirror + JS twin of the proofs, and the image-native eBPF/FPGA/MCU tiers, are named
  follow-ons.
- **OTLP baseline for the decision wire** (`adapters/fusion/bench/otlp_baseline.py`; evidence #95),
  closing the named follow-on in #84. Encodes the same fused decision as a genuine, round-tripping
  `opentelemetry.proto` LogRecord (OpenTelemetry; the wire observability pipelines actually speak)
  and measures it against the decision stream: OTLP-faithful is **101.4 B/decision** vs the decision
  wire's **1.5** → **67.6×**, and **4.8×** even against zstd batched OTLP. Honest finding baked in:
  OTLP is **1.49× larger than minimal JSON** for this payload (per record timestamps + typed
  attributes + repeated keys), so the win over it is structural; self framing streamability,
  tamper evidence, decidability; not a compression trick. Test `importorskip`s `opentelemetry`, so
  the bare adapters CI job skips it cleanly.
- **Crypto-agility proofs ported to the Rust and JS kernels** (`prismpath-rs/src/crypto_agility.rs`,
  proofs in `prismpath/portable/prismpath.mjs`; evidence #96), closing the cross language follow-on
  named in #94. Both replay the two frozen fixtures (`crypto_agility.json` + `crypto_migration.json`)
  byte for byte against the Python reference: Rust `test_crypto_agility` gates in `cargo test`
  (`durable` is default), and the JS twin (`node run_crypto_agility.mjs`) is a CI port-job step. So
  provable crypto-agility is now conformance-gated across Python, Rust, and JS.
- **RP2350 cross ISA substrate** (`prismpath-hw/rp2350/`; evidence #97, staged). The byte exact
  interpreter (`ppt_rp2350.c`, a USB-CDC port of the AVR's `ppt_uno.c`) decides the frozen corpus
  **124/124 on BOTH cores of the RP2350 from one source**: the ARM Cortex-M33 and the Hazard3
  RISC-V; with byte identical exclusion reasons. One `.ppt`, two ISAs of one die, same decision:
  cross ISA conformance, not just cross language. Built from a single Pico SDK CMake project
  (`make arm` / `make riscv`); the ISA tag is chosen by the compiler.
- **ESP32 Xtensa substrate** (`prismpath-hw/esp/`; evidence #98, staged). The same byte exact
  interpreter certifies **124/124 on an ESP32 (ESP-WROOM-32, Xtensa LX6)** over its UART, adding
  **Xtensa** as a third MCU ISA; so 8-bit AVR, ARM, RISC-V, and Xtensa now all decide the signed
  policy identically. One ISA-generic ESP-IDF project (ident + UART pins chosen at compile time from
  `CONFIG_IDF_TARGET`) targets esp32 or esp32c6.
- **On-device sensor → decision demo** (`prismpath-hw/rp2350/ppt_tof.c` + `vl53l0x.c`; evidence #99,
  staged). The RP2350 reads a real **VL53L0X** time-of-flight sensor over I2C, forms the field vector
  itself, and runs a signed Level M proximity policy **on device**: distance routes to
  contact/near/mid/far live, no host in the loop, the decision flipping exactly at the authored
  100/300/800 mm thresholds. The first physical-input demonstrator since the FPGA fabric; the policy
  `.ppt` is baked into flash from the same compiler every substrate uses.
- **Coordinated fleet policy swap over ESP-NOW** (`prismpath-hw/mesh/`; evidence #100, staged). Three
  ESP32 nodes swap policy **together**: one table is broadcast, **re verified on every node before it
  is staged** (each follower re-hashes it and checks the id against a baked allowlist; a mismatch is
  refused, not swapped), committed only after a quorum ACKs, and applied at a shared tick so the fleet
  flips within **0.7 ms** (host-observed, serial jitter included). The multi node analogue of the
  single-node hot swap (#87/#88); same verify-then-swap / refuse-don't-downgrade contract, extended
  across a mesh with a two phase commit so no node flips alone. FNV-1a id/allowlist stands in for the
  signature (Ed25519-on-the-mesh is the named follow-on).
- **Context ledger; attest what a frozen model was conditioned on** (`prismpath/context_ledger.py`,
  mirrored in `prismpath-rs::durable::ContextLedger`; evidence #91). For a hardwired/frozen-weights
  model the context is the only mutable state, so it is the governance surface: an append only
  ledger commits each context segment by content hash (salted via `salt_leaf` for low entropy
  text), chains them (order-binding), Merkle-roots them (per segment inclusion proofs), and binds
  the root into the standard provenance manifest (context root = manifest root, segment leaves =
  ingestion hashes, chain head in the label, model identity = knowledge hash). Hashes only;
  content never enters the artifact. Cross-language byte parity gated by a new frozen corpus
  (`portable/conformance/context.json`); the in-lab demonstrator's per-token receipts now carry
  `context_root`, tying every verdict to exactly the user text and rendered template it was made
  over.

### Fixed
- **Level M classifier soundness: float constants are no longer mis-classified as table-compilable.**
  `field OP <float>` (e.g. `when score >= 0.9`) was reported as Level M, but the match action fragment's
  value domain is `i32` (there is no float on the table, in silicon, or in the kernel) so the condition
  is genuinely outside the fragment. `is_level_m` / `capability_report` (Python and the JS kernel
  `prismpath.mjs`) now reject it (`disallowed-or-unparseable`), and SPEC §4.3 says "**integer**, boolean,
  or string literal" where it previously said the imprecise "numeric". This removes **11 float over-claims**
  from the classifier's Level M count over the frozen corpus; the FPGA/eBPF runnable subset (114) is
  unchanged; the compiler already rejected floats, so no certified number moves. Corpora gain a
  `float_const` case. (Python↔JS agree bit for bit on floats incl. `1e3`, `.5`, `2.0e1`, floats-in-lists.)

### Changed
- **Negative (and unary-plus) integer literals are now inside the predicate language and the Level M
  fragment.** `when x >= -1282` was rejected everywhere; the sandbox flagged the `USub` node as
  disallowed syntax, and the classifier/compiler never saw a constant; even though the `.ppt`
  format already stores `val` as a signed `i32` and both `interp.c` and the RTL compare signed. The
  gap was purely front end. A single normalization, `predicates.fold_unary_signs`, folds
  `UnaryOp(USub|UAdd, Constant(int))` into a signed `Constant` right after parse, applied at the one
  place check / eval / the Level M classifier / the PPT compiler all share, so they accept the same
  language (SPEC §4.4). Scope is deliberately narrow and the sandbox stays exactly as tight: only
  **integer** operands fold, so `-<float>` (e.g. `-0.0`) keeps its pre existing rejection and
  `-field` (arithmetic on a name, e.g. `-x`) stays outside the language; the bare `USub` node never
  reaches the allowlist walk. Mirrored bit for bit in the JS (`prismpath.mjs`) and Rust
  (`prismpath-rs`) kernels; **all three conformance runners CONFORMANT** on the regenerated corpus.
  **Measured effect:** the frozen predicate corpus goes **v1 → v2** (1067 → 1079 cases; one existing
  vector `when -1 < x` flips from `ERROR` to `True`; the bug being fixed); Level M cases 126 → 136,
  distinct Level M conditions 119 → 126; the **C-target declared subset re certifies 114 → 124/1079,
  zero divergence**, and a negative-literal table (`x >= -1282`) was **proven on the Zynq-7020
  fabric** deciding correctly at the exact boundary (−1283 → low, −1282 → high). Nothing on the board
  changed; the circuit already compares signed `i32`. SPEC §4.3 updated. Pins moved (fragment count,
  corpus version). **eBPF re certified same day: 124/124 in kernel on BOTH aarch64 and x86_64 with
  the hardened loader** (`BPF_PROG_TEST_RUN`, table-per-vector), and the held `loader.c` hardening
  smokes passed on a live attach (drop_mask survives `netupdate`; an over-`MAX_*` image is rejected
  with the running table untouched); the cross substrate headline reconciles at **124** (evidence
  #90). The **RTL re-sweep** to 124/1079 remains pending a hardware retest.
- **Chained comparisons are normalized into the Level M fragment, not excluded; one shared desugaring.**
  SPEC §4.3 said chained comparisons (`when 1 < x < 5`) "SHOULD be desugared by tooling" but the
  classifier (`verify --level-m` / `capability_report`) reported them as *outside* the fragment while the
  PPT compiler desugared and accepted them; a real gap between "is this hardware-compilable?" and what the
  compiler actually did. Now both **desugar-then-classify** through a single `model_check._desugar_chains`
  (the compiler imports it; the JS kernel mirrors it): `a < b < c` → `a < b and b < c`, exact under
  §4.1 to §4.2 (pure operands, total comparisons). A chained comparison is Level M iff each conjunct is;
  `1 < x < 5` is in fragment, `1 < a < b` is not (`a < b` is field-vs-field, now reported with that precise
  reason instead of a blanket "chained"). Net effect over the corpus: classifier **= compiler = 126 cases /
  119 distinct, 0 disagreements** (pinned by `test_classifier_compiler_gap_pinned`); the 114 runnable
  subset is unchanged (the compiler already desugared, so no certified number moves). SPEC §4.3 updated
  (chained moved from "Excluded" to a normalization rule); conformance corpora `level_m.json` /
  `capability.json` flip the `chained` case to Level M → **spec-vector version 1 → 2**.

### Added
- **Secure policy hot swap: a live policy replacement that is authorized, envelope bounded, attested,
  and audited; published in full as prior art.** A `.ppt` policy now ships as a *pack*: the
  byte identical image plus a detached Ed25519 signed manifest (`prismpath/policy_pack.py`), so the
  image hash the FPGA/eBPF evidence rows cite never changes. `PolicyHost`
  (`prismpath/policy_host.py`) runs the swap pipeline; signature → envelope-conformance
  (counts ≤ caps, fields ⊆ envelope, an image-native opcode-whitelist walk re verifying Level M
  membership at load time) → monotonic-version anti-rollback → shadow-stage → single atomic reference
  flip; and writes every attempt, accepted or **rejected**, to the Merkle rooted `audit_log`
  (OTS-anchorable), so "policy X was live from T1 to T2" is provable. Any failure at any stage leaves
  the prior policy active (fail safe), and `rollback()` restores last-known-good. Crypto is the
  optional `signing` extra with **loud absence** (verification unavailable → refuse with the install
  message, never a silent pass); a demo `--allow-unsigned` path stamps `unsigned: true` into the
  ledger rather than hide it. CLI: `prismpath swap {keygen,pack,verify,envelope,swap,attest}`. The
  mechanism is specified and disclosed as prior art in
  [`docs/design/spec-secure-hotswap.md`](docs/design/spec-secure-hotswap.md) (no patent sought). This
  is the software reference tier; FPGA/MCU are named follow-ons under the hardware-retest rule.
- **eBPF trusted pre loader for the hot swap (`prismpath-ebpf/net_swap.py`).** Puts the authorization
  and envelope gates in front of the kernel `netupdate`: it verifies the signed pack against its
  signed envelope and the version floor on the host, and execs the loader **only** on success; a
  verification failure never reaches the kernel. Privilege-free up to the loader exec, so the whole
  gate is tested without root (the loader call is injected; 5 tests, including "tampered/replayed
  images never reach the loader").
- **Cyber-physical fusion proven on the live rig: real IMU + real SIEM fused in real time, with the
  sensor's own on chip fusion classifier as an independent cross-check.**
  `adapters/fusion/live_capture.py` runs the BNO086 (via `prismpath-hw/bridge/field_bridge_multi.py`,
  decision fields byte identical to the committed pipeline + on chip quaternion/orientation and the
  chip's own stability classifier at 10 Hz) and the live SIEM in the same window, joining each alert
  to the coincident device posture and routing it through `fusion_triage`. Across 3 live sessions
  (**4,369 real readings + 90 real SIEM alerts**, incl. a self-triggered level-10 auth-failure event
  as authorized detection-validation), the chip's AI classifier agreed with our derived posture
  **96.3%** of the time, and the multi-modal-to-decision bandwidth was **~252 B vs ~6 bits per
  reading (333×), live**. Honest scope: `tandem_watch`/`coincident_critical` stayed empty across all
  sessions (no high severity cyber event coincided with the right posture; the rare signal, honestly
  unlit); the full six-channel suite saturates the MCP2221A HID pipe (10 Hz trio is the sustainable
  rate; the case for wiring the sensor directly to the FPGA). Evidence row #85; aggregate artifacts
  are aggregate-only (privacy-tested).
- **Cyber-physical decision fusion adapter (`adapters/fusion/`): one Level M flow joins IMU posture
  and SIEM verdicts; proved, tessellated, censused, and bandwidth-measured on real data.**
  `flows/fusion_triage.md` fuses `{stability, dev_mg}` (the sensor bridge's own fields; thresholds
  150/500/2500 are its DEADBAND/MOVE_DEV/SHAKE_DEV constants) with `{rule_level, soc_action}` (7/12
  are the SIEM's triage floor and the wazuh_triage containment edge) into 7 verdicts;
  escalation default, coincidence checked first, `else` last. `flow_level_m` → `(True, [])`
  asserted in suite; the 108-cell / 7-band Tier-6 tessellation is frozen
  (`conformance/spiral_fusion.json`, flow sha256 pinned, 34 boundary probes decisions-preserved
  three ways; the first mixed numeric/categorical spiral corpus, no telemetry change needed).
  `census.py` weights the bands with the real month scale backlog (64,483 triage alerts of
  2,498,693 total) + 10,421 real IMU session rows; pairings labeled (`assume_still`,
  `independence_expected`; NOT time coincident; the empty coincident bands are the finding), and
  the committed artifact is aggregates-only (privacy regression test enforced).
  `bench/bandwidth.py` measures the full population, overheads itemized and included:
  **O1 1.516 B/alert vs raw 3,020 B/alert (1,992×; 45× vs minimal 4-field JSON); the band-ID
  stream is 0.516 B/alert (~4.1 bits/decision)**: gate PASS, with the buffered-batch-compressor
  caveat stated in the results before anyone else can state it. Honest scope: software proof only
  (substrate cert + hardware retest is a named follow-on), the census projection is decidable (not
  an adjudicator verdict), and the live coincident capture is the only future true-joint artifact.
  Evidence rows #82 to #84.
- **eBPF target: real packet classification on live traffic + measured latency + live policy hot swap.**
  `ppt_net.bpf.c` reuses the verified eval back end with a real packet front end (parses on wire
  Ethernet/IPv4/TCP-UDP into a fixed canonical register file) and classifies each packet with a Level M
  table, observe only. Attached to `span0` (the home-traffic mirror) it classified thousands of real
  packets in kernel with a sensible TLS-dominant distribution. Per-packet latency measured via
  `BPF_PROG_TEST_RUN`: **132 to 182 ns/packet, ~5.5 to 7.6 Mpps/core**: sub microsecond, earned not asserted.
  `netupdate` **hot swaps the policy of a running program in place** (repopulates the table maps via the
  program's map-IDs; no detach, no reload); demonstrated live by editing `net_triage.md`, recompiling,
  and swapping a 7-class table for an 8-class one while classification continued uninterrupted. New:
  `ppt_net.bpf.c`, `net_triage.md`, `net_compile.py`, loader `netattach`/`netstats`/`netdetach`/
  `netbench`/`netupdate`. Honestly bounded (README §9): observe only (no inline drop yet), generic/SKB
  XDP, latency is program compute cost not end to end wire latency.
- **eBPF target: in kernel conformance + whole-flow execution.** The `prismpath-ebpf` loader gained
  `certify` / `run` / `runbatch` modes that drive the actual verifier accepted XDP program in kernel via
  `BPF_PROG_TEST_RUN`. The eBPF target now **certifies 114/114 of the declared subset** (the same
  114/1067 filter `prismpath-hw`'s C-target uses; in fragment condition + read fields i32-representable)
  of the frozen `predicates.json` corpus in kernel, byte matching `interp.c`; the other 953 vectors are
  excluded and itemized, none an eBPF limit. Real
  multi node flows execute in kernel: the 12-node `adapters/soc/flows/wazuh_triage.md` routed a **live
  Wazuh alert stream** (real LLM verdicts) 27/27 identically to the reference. New harness:
  `cert_corpus.py`, `cert_vectors.py`, `run_flow_demo.py`, `run_stream_demo.py`, `run_incident_demo.py`.
  Framing: the Level M corpus is the cross substrate standard; richer tiers are named, never a lump "+X."
  Not yet done (stated honestly in the target README): live line-rate deployment, a real packet parser
  front end, and measured performance.
- **`prismpath context <flow.md>`** (`prismpath/flow_context.py`); emits the kernel's own *verified*
  facts about a flow (nodes, edges, declared fields, reachability, Level M status, capability tiers) as
  grounding for an agent authoring/editing it. Composes `model_check` primitives; JSON or prose.

### Changed
- **Sprint-engine hygiene: it never deletes your files, and the game-flavored "council" is gone.**
  `run_sprint.py` no longer auto-wipes `SPRINT_PROJ`; the old `SPRINT_FRESH=1` default ran
  `shutil.rmtree`, one typo from erasing a real project. Greenfield now requires an empty dir (or
  `SPRINT_EXTEND=1` to build on an existing tree), else it errors clearly; choosing and clearing the
  location is the user's call. The **council** deliberation subsystem (`prismpath/plugins/council/`,
  the `prismpath/dice.py` shim, `council_next`, the role lenses) is **deleted**: the swarm backend
  uses the `review` role. Game-flavored language ("player", "gameplay", "one more run", "world object",
  …) is removed from the core: PrismPath itself carries no game flavor; that lives only in
  ports/adapters/examples.

### Added
- **eBPF/XDP target; a decidable PrismPath table runs in the Linux kernel** (`prismpath-ebpf/`). A
  third certified substrate beside the Python reference and the FPGA C-table (`prismpath-hw/`): a
  Level M / PPT table image is loaded into BPF maps and executed by an XDP program whose interpreter
  (nested `bpf_loop` for the edge + prog machines, a constant-indexed operand stack, a per-CPU-map
  register file) is **accepted by the kernel verifier** and computes verdicts **byte identical to the
  C reference `interp.c`** on real packets; proven end to end (`sudo make smoke`) at full 32/64/64
  bounds on kernel 6.17. Declared subset: operand-stack depth ≤ 4. The PPT format + reference
  interpreter stay canonical in `prismpath-hw` (referenced, not duplicated). `prismpath-ebpf/README.md`
  has the full verifier analysis, including the approaches that failed and why.
- **Portability matrix + reachability, now in the portable kernel and provably in sync**: two
  analyses that used to be Python-only are ported to `prismpath/portable/prismpath.mjs`:
  `capabilityReport` (which targets a flow compiles to; python / portable JS-Rust-Go / Level M
  hardware; and, for the ones it doesn't, the blocking edges) and `checkReach` (three-valued
  yes/may/no bounded-model-checking reachability with `assume`/visit-caps/witnesses). Each is a faithful
  port of its `model_check` reference and is **certified against a frozen corpus** so the CLI and the
  browser can never disagree: `capability.json` (6 cases) and `reach.json` (11 cases), checked from
  Python (`test_capability_conformance.py`, `test_reach_conformance.py`) and JS
  (`run_capability.mjs`, `run_reach.mjs`). New CLI subcommand `prismpath capability <flow>` prints the
  matrix (`--json` for machine output). The website playground gains a live **Targets** matrix and a
  **Prove reachability** panel (node picker + optional `assume`, verdict + witness path), all
  client-side.
- **Code nodes; governed workers with a capability-scoped sandbox** (`prismpath/code_nodes.py`,
  `prismpath/sandbox.py`). A node's worker can be plain code; the flow still governs the routing
  (branching stays on the edges). Each code node declares an `@code(net, fs, timeout_s, mem_mb)`
  capability envelope; statically checkable (`check_code_nodes`, verifiable like Level M); and runs
  **fail-closed**: no undeclared code, no invalid envelope, and (via `SandboxRunner`) a `bwrap`
  subprocess whose profile is derived from the envelope, **refusing rather than degrading** when the
  sandbox is unavailable. Guide: [`docs/guides/code-nodes.md`](docs/guides/code-nodes.md); 14 tests.
- **Security posture clarified** ([`docs/design/spec-guard-onion.md`](docs/design/spec-guard-onion.md)
  §1.5): PrismPath owns provable **routing** and governed code **execution** (the code-node sandbox);
  **content** safety is delegated to the model or an opt-in guard; the routing layer is the wrong place
  for a content filter. The content guard is therefore an **optional**
  floor (`guard.py`, Journeyman's `guard.ts`), deliberately **not** embedded in the portable Rust/Go/JS
  kernels; each kernel's `CONFORMANCE.md` now states "a conformant kernel is not a content-guarded one."
- **Mission Control rebuilt as a proving + observability command center**
  (`prismpath/mission_control/`, now a FastAPI package; run `python -m prismpath.mission_control`).
  A single-user, loopback console over a **versioned JSON API** (`/api/v1`, OpenAPI at `/docs`): the
  flow topology (vendored Cytoscape) with live run-state over SSE; **text-in proving**: `POST
  /prove/level-m` and `POST /prove/reach` run the real `model_check` against a posted flow document,
  never a server path (closing the old arbitrary-read surface); audit self-verify; RAG-retrieval
  visibility (`/retrievals`, per node); a **buffered/unbuffered** launch toggle. The proving/
  observability API is the driving adapter other services connect to; the browser console is its
  first client. It runs **no models**: inference belongs to the worker tier. Needs the
  `control-plane` extra (fastapi/uvicorn/pydantic). Guide:
  [`docs/guides/mission-control-api.md`](docs/guides/mission-control-api.md); 13-test TestClient suite.
  **Removed** with the old multi-user scope: Tailscale identity, the Gemma chat, RAG doc-upload, and
  the AGY tab; the stdlib `http.server` console (`python -u prismpath/mission_control.py`) is retired.
- **The sprint engine goes language-agnostic**: a **pysprint gate** plugin
  (`prismpath/plugins/pysprint/`) runs pytest as the definition-of-done, so a sprint can build Python
  targets, not just web; plus a **feature-extend mode** (`SPRINT_EXTEND`; skip greenfield ideate to
  extend an existing tree) and an **uncheatable frozen gate** (tests read from a read only dir outside
  the sandbox). `run_sprint.py` now honors the gate plugin's `FILE_EXTS`.
- **mdflow interop** (`prismpath/examples/mdflow_interop/`): mdflow tasks run as PrismPath workers
  behind the routing kernel ("PrismPath governs the routing; mdflow provides the action"), via mdflow's
  `--json` envelope; gated example + tests.
- **The Level M hardware target ([`prismpath-hw/`](https://github.com/crystal-warden/prism-path/blob/40a9b05b3523cb4943b583b77c6fb86f93d795ee/prismpath-hw/README.md))**;
  a Level M flow compiles to a binary table image (`wazuh_triage`, unmodified: 302 bytes)
  interpreted by one fixed FPGA circuit on a Zynq-7020; C and RTL interpreters certified on a
  **declared subset** of the frozen corpus (114/1,067 predicate + 6/27 engine vectors, zero
  divergence, machine readable exclusion reasons; deliberately *not* SPEC §8 conformance);
  timing clean at 50 MHz (1,064 LUTs = 2.0% of the part, WCET 100 to 420 ns/decision); 2,985 live
  sensor samples routed in fabric; evidence hashes OTS-anchored. Gates: `make cert` + the cocotb
  suites under `prismpath-hw/`; evidence ledger rows #72 to #76. Built off to the side, landed as
  a top-level target directory beside `prismpath-rs/` and `prismpath-go/` after clearing the
  repo's gates (the CLI integration, `compile --target c-table`, stays open on the roadmap).
- **Four conformant kernels**: `prismpath-go` joins Python / JS (`prismpath/portable/prismpath.mjs`) /
  Rust (`prismpath-rs`): a dependency free Go P0 kernel at 1,067/1,067 predicates and 27/27 flows
  against the frozen vectors. Conformance is now a refereed sport with three independent referees.
- **`prismpath verify`: formal model checking** (`prismpath/model_check.py`): "state X can never be
  reached under condition Y", answered by adversarial-worker reachability with first-match
  semantics. Exact verdicts with concrete witness outcomes over the **Level M match action
  fragment** (SPEC §4.3 membership is now reported per edge, and `portability_tier` carries a
  `level_m` flag); sound over-approximation outside it (semantic/error/event hops labeled "may");
  `visits` modeled with saturation so UNREACHABLE is proven for all bounds. `--reach/--forbid/
  --assume/--bound/--level-m/--json`.
- **`prismpath lsp`: a Language Server, stdlib only** (`prismpath/lsp.py`): live diagnostics (the
  full validate check set, anchored to the offending edge line), completion (targets, derived
  predicate fields, tier keywords, annotations), hover, document symbols, and a `prismpath/graph`
  Mermaid request; for Neovim, JetBrains (LSP4IJ), VS Code, and any LSP editor. Client setup in
  `prismpath/editor/README.md`.
- **Fan out debugging + live visualization**: `composer.fanout_tree()` (read only composition
  trees: all child stop states, join progress with the gate-aware done-criterion, `child_error`
  reasons, nested fan-outs) behind Mission Control's new **Flows tab** (`/api/fanouts`,
  `/api/fanout/ckpt` queue-dir-confined).
- **The Connector SDK, complete** (`prismpath/connector.py`): all six hexagonal ports;
  Adjudicator (callable-driven, never assumes an LLM; flat prompts via `PayloadFlattener`;
  optional `guard.guarded_exchange` routing), Deferral (`DeferralStore` wiring), an idempotent
  JSONL sink default, `checkpoint.flow_hash()` (public) as the attestation policy hash, and the
  proven one-line plugin pattern `WORKERS = MyConnector().get_workers()`.
- **Production SIEM integrations** (`adapters/soc/siem.py`): a `SIEMSource` ingestion port with
  `ElasticSource` (any Elasticsearch/OpenSearch-compatible indexer; env-configured, TLS
  verification on by default), `WazuhSource` (lazy, opt-in legacy credentials), `NDJSONFileSource`
  (air-gap/replay), and a best-effort `SplunkSource`. The SOC agent now rides the Connector SDK
  (`WazuhTriageConnector`) with env seams matching the compliance adapter, plus `cw-triage`
  systemd units.
- **Automatic prefilter tuning**: `prefilter.tune()` derives the cache's operating point from
  evidence: a (threshold × min_conf) sweep with a **Wilson upper bound** certifying the
  reuse-error rate ≤ `--risk` (the `calibrate` pattern applied to reuse); refuses to choose when
  the evidence can't clear the bound. `tuning.json` slots under explicit args and env in
  precedence; the SOC adapter's `labels` command feeds the tuner its own adjudication history.

- **`prismpath ci-report` + the PR comment**: the money demo as a living product: for every flow a
  PR changes, one sticky comment with validate findings, fixture verdicts, and the routing topology
  **before → after as live Mermaid diagrams** (GitHub renders them in the conversation). The Action
  gained a `comment` input (needs `pull-requests: write`); the command works locally too
  (`prismpath ci-report --base origin/main`). Gate semantics: errors and failing fixture rows exit 1;
  advisories inform. Fixture tables needing the embedding tier report "skipped" on kernel-only
  runners instead of failing. Flow detection requires front-matter, so prose docs that embed flow
  snippets are never misreported.
- **URL-shareable playground flows**: 🔗 Share encodes the whole flow (+ scripted outcomes) into
  the URL fragment (base64url; nothing leaves the page; there is no server). Every flow is now a
  link: click it, watch it route, edit the rules live. Cold-load and hashchange both verified in a
  real browser, unicode round-trips.
- **`prismpath run --agent ollama:MODEL`** (and `openai:MODEL@BASE` for vLLM / LM Studio /
  llama.cpp); a real local model as the worker, one flag after clone (`chat_agent.py`, stdlib
  only). JSON replies feed `when` predicates; endpoint failures ride the flow's `on error` edges.
  Verified live against a local OpenAI-compatible endpoint and pinned by 7 stub-server tests.
- **Three more gallery templates**: `pr_review` (approval with a human gate + the visits-cap
  idiom), `fanout_review` (parent + `review_one` child; `prismpath init --template` now copies a
  template's whole working set, so `@spawn` children travel), `support_triage` (semantic
  classification + deterministic money/severity guard rails). All validate clean; all fixture
  tables green with no model installed.
- **The editor surface** (`prismpath/editor/vscode/`): a VS Code extension, all thin wrappers over the
  repo's own tooling: a TextMate *injection* grammar coloring edge lines by tier (deterministic /
  semantic / error / event / always) + `@annotations` inside plain Markdown; a live preview webview
  hosting the SAME `prismpath/portable/playground.html` + JS kernel as the browser playground (seeded from the
  buffer, re-fed on every edit; tier badges, checks, ▶ Run, Mermaid; **no Python needed**); and
  optional validate-on-save diagnostics mapped to `## node` lines. The playground gained a
  postMessage embedding hook any host page can use. Grammar tier-classification is pinned by tests.
- **`prismpath init --template <name>`**: every gallery entry doubles as a starter (`--template list`);
  copies the flow AND its routing tests, and the model free `validate → test` loop works immediately.
- **`prismpath plugins --new <name>`**: scaffold a pip-installable **worker pack** (pyproject with the
  `prismpath.plugins` entry point, `WORKERS` module with a pure example + the `CliWorker` bridge
  comment, pytest, README). Verified end to end: `pip install -e` → appears in `prismpath plugins` as
  `[entry-point]` → `@worker(<name>.<worker>)` resolves.
- **The plugin ecosystem** (`prismpath/plugins/registry.py`): harness-side extension with the engine's
  purity untouched. Plugins (bundled, or pip-installed via the ``prismpath.plugins`` entry-point group)
  provide **workers** (tools a flow binds in the document with `@worker(plugin.name)`), **gates**
  (build targets), and **CLI** subcommands. Auditable end to end: `prismpath plugins [--json]`
  lists what's installed and what each provides; `prismpath plugins --check flow.md` verifies every
  binding resolves (CI gate); `registry.worker_agent(graph, default=…)` resolves bindings at
  construction (fail-fast) and stamps dispatched outcomes with `_worker` provenance.
- **The council plugin** (`prismpath/plugins/council/`): the deliberation *expansion* (optional; the
  exception, not the default): `council.roll` (seeded, replayable Oblique-Strategies dice) and
  `council.tally` (coverage/balance-weighted vote tally, deterministic tie-break). `dice.py` moved
  in; a root shim keeps existing imports working.
- **`prismpath init`**: scaffold a starter flow + routing-test table; `init → validate → test` is a
  zero-config, model free first success (the starter's semantic edges light up once
  `[embeddings]` is installed).
- **`@state_bound(transcript=N)`**: a flow-declared sliding-window bound on persisted run state,
  closing the papers' last open critique (unbounded state growth). The engine windows the transcript
  on append and the re-seeded path/step history on resume, so a long lived run's checkpoint payload
  stays flat across unlimited resumes; drops are counted deterministically in `_state_dropped`
  (engine stays pure). Routing is unaffected by construction; predicates read fields plus per node
  `visits`/`error_count` counters, which are never windowed. Malformed bounds fail loudly at run
  start. Engine override: `run(..., max_transcript=N)`.
- **Gate zero delivered**: a human maintainer blind-relabeled all 301 benchmark cases (gold hidden)
  at **Cohen's κ = 0.961 vs gold** ("almost perfect", every stratum ≥ 0.945); an independent
  cross family model (Gemini) agrees with the human at **κ = 0.682** ("substantial"), with 90% of its
  disagreements concentrated where the model dissents alone against human+gold; mostly the polarity
  stratum (44%), the negation trap the benchmark is built to probe. Write-up:
  `prismpath/benchmark/gate_zero/findings.md`; papers and benchmark README updated from "future work" to
  delivered.
- `prismpath/benchmark/make_blind.py`, `prismpath/benchmark/collect_blind.py` (with explicit, audited
  `--drop-invalid` and `--split-compound FLOW/NODE` modes), `prismpath/benchmark/parse_annotate_transcript.py`
 ; the reproducible second-annotator pipeline around `prismpath annotate` / `prismpath kappa`.

- **`docs/decoder-ring.md`: the glossary and repo map.** Every term the papers borrow from
  statistics, formal methods, and distributed systems, explained in plain language: the Wilson
  interval (and why it is read from both ends), selective classification and abstention, δ vs τ,
  Learn-Then-Test and why this is *not* conformal prediction, James-Stein shrinkage, Cohen's κ,
  the match action fragment and one-sided soundness, hexagonal ports, Merkle batching. Plus an
  A to Z glossary, an index of every document / kernel / CLI command / module, and ordered reading
  paths. Caveats travel with their concepts; the κ entry states that 0.961 is the author agreeing
  with the author's own labeling process, not inter-annotator reliability; so a reader who never
  opens a paper still can't over-claim from it.

### Changed
- **Documentation consolidated into a top-level `docs/` tree**: the 12 standalone documents were
  scattered across the repo root, the package dir, and `prismpath/docs/papers/`; they now live in
  `docs/{guides,design,research}/` with kebab-case names. Deliberately *not* moved: files tooling
  reads at the root only (README, LICENSE, CITATION.cff, action.yml), the community-health files
  GitHub surfaces in its UI, SPEC/GETTING_STARTED/ROADMAP as normative text and entry points,
  subsystem READMEs (a README documents its own directory), and program data that merely looks
  like docs (`flows/`, `gallery/`, `nudges/`, `policies/statutory_floor.md`,
  `tests/fixtures/broken/`). `prismpath/docs/` is gone, so the package dir holds only code and
  runtime data. All 12 moves preserve `git log --follow` history; every relative link re-resolved
  (0 broken across 108 files) and 53 bare-path prose citations rewritten.
- **Docs ship in the wheel** under `share/doc/prismpath/`, mirroring the repo layout rather than
  flattened; flattening collides `README.md` with `docs/README.md` and dangles every relative
  cross-doc link. New `MANIFEST.in` carries the same set into sdists.
- **The roblox plugin is gone** (deep excision): the game-dev-origin gate plugin (~9 MB incl. its
  RAG index) was never meant to fuse into PrismPath. The sprint control plane is now fully
  target-generic; the council deliberation expansion stays. `plugins.load_gate` no longer aliases
  `luau`.
- **APP_ARCHITECTURE.md → `prismpath/nudges/`**: it is a coder-prompt contract, not a doc; all
  reference sites now resolve it `__file__`-relative (CWD-independent).

### Fixed
- **The Level M classifier accepted `is`/`is not`; the evaluator rejects them**
  (`prismpath/model_check.py`): `_atom_reason` never checked the comparison operator against the
  evaluator's allowed set, so `verify --level-m` could call an edge table-compilable that
  `eval_condition` refuses as unsafe (the corpus records such predicates as ERROR). Found by the
  hardware target's compiler (the classifier's first external consumer) on its first day.
  Operator gate added + regression rows; check, eval, and classify accept the same language again.
- **CI red on Python 3.10/3.11; a backslash inside an f-string expression** (`prismpath/lsp.py`).
  Legal only on 3.12+, a `SyntaxError` on the older interpreters CI tests against, which aborted
  the entire collection. The expression is hoisted to a variable; the full suite now passes under
  3.11 (verified locally) and the whole package compiles clean under `python3.11 -m compileall`.
- **The wheel was missing files shipped code opens**: `package-data` omitted
  `prismpath/policies/statutory_floor.md` (loaded by `guard`, `measure_p1`, `bypass_report` and
  three test modules) and `prismpath/tests/fixtures/broken/*.md` (read by `test_analysis`). Present
  in the repo, absent from an installed wheel. Both now declared, along with `policies/*.json`.
- **`tools/docs_health.py` failed silently on a stale path**: the evidence-ledger location was
  hardcoded behind an `if os.path.exists(...) else ""`, so a wrong path degraded into reporting
  *every* task and artifact as a coverage gap with no error. Repointed, and it now asserts loudly
  rather than degrading.
- **`tools/arch_guard.py` recreated the directory the reorganization removed**: it wrote its
  scorecard into `prismpath/docs/`. Now writes `docs/design/arch-scorecard.md`, git-ignored, with
  `tools/arch_scorecard.json` remaining the committed artifact. Also caught a genuine **Signal-1
  HARD FAIL** it had not been run against: a Connector SDK docstring used "FPGA", a registered
  sensor-domain noun, inside core. Reworded; Signal-1 passes with 0 violations.
- **The README's headline example did not compile**: the front-page `support_triage` flow routed
  to `billing`, `retention`, and `general` without defining them: three `undefined-target` errors,
  in the showcase for a project whose headline feature is "your flow compiles." The three terminal
  nodes are now present, and the Mermaid beside it is verbatim `prismpath graph` output rather than
  a hand-drawing captioned as tool output. A sweep now validates every self-contained flow snippet
  in the docs; the two paper excerpts it also caught are fixed, and the annotated anatomy diagrams
  in SPEC.md / authoring.md are correctly exempt.
- **The mdflow → prismpath rename had corrupted both papers**: a blanket substitution overwrote a
  *third party's* project name in Related Work ("Lindquist's `prismpath` task runner, unrelated to
  this system"), destroying the attribution and inverting the disambiguation. Restored to `mdflow`
  with a note that explains itself. Also 11 uncopyable commands (`python -m PrismPath.cli`, the
  whitepaper's entire CLI reference block) and two article artifacts ("an PrismPath author"). The
  research paper had been using the correct lowercase form 12 times elsewhere.
- **OTS anchoring read the wrong ledger**: `ledger_ots.from_ledger()` defaulted to the
  pre-rename `refs/mdflow/runs` namespace and `Mdflow-Output-Hash` trailer key, which the ledger
  writer never produces; `prismpath ledger anchor` always found nothing. Now matches `ledger.py`
  exactly (verified against a real ledger). Part of a repo-wide mdflow-leftover sweep that also
  restored the seven `research/` scripts and the compliance adapter's tooling paths.

## [0.1.0] · the initial baseline (pre-release)

The baseline is the whole system; highlights rather than an exhaustive list. (Released
2026-08-06, OpenTimestamps-anchored in Bitcoin block 961224; see the README's "The launch is
anchored"; with a Zenodo DOI in `CITATION.cff`. On the *next* release, [Unreleased] folds
forward into its notes.)

### The format
- **SPEC.md v1 (draft)**: document grammar, the four edge tiers (deterministic / semantic /
  error / event), normative predicate semantics, engine contract, portability levels P0/P1/P2,
  and the synthesizable **match action fragment** (Level M).
- **Frozen conformance vectors** (`prismpath/portable/conformance/`): 1,067 predicate cases + 27 engine
  fixtures, generated deterministically from the reference implementation, enforced in both
  directions in CI. Any runtime that passes them is conformant, by definition.

### The reference implementation
- Pure engine with the routing spectrum; safe predicate evaluator (fuzz-gated: ~20k adversarial
  inputs, zero exec, zero uncaught crash); hybrid embed→LLM routing with margin escalation.
- **Data-plane toolchain**: `validate`/`lint` (16 in graph + 4 cross-flow decidable checks),
  Markdown flow tests, routing lockfile (+ composition-tree pinning, learned-centroid pins),
  risk controlled calibration (Wilson-bound τ), prototype/centroid routing, Mermaid export,
  OTel spans, LangGraph importer, routing-decision label workbench, portability tiering.
- **Durable execution**: atomic checkpoints with flow-hash-bound resume, human queue,
  wait-for-event + reference timeout scheduler, fan-out/sub-flow composition (`@spawn`,
  deterministic child identity, join policies), git Flow-Ledger proof-commits with
  resume-from-ledger.
- **Prefilter cache** with continuous shadow-sampled reuse-error monitoring, windowed drift
  quarantine, and policy hash invalidation.
- **CLI workers** (`cli_worker`): any command-line program as a worker; JSON-on-stdout feeds
  predicates; failures ride the error tier.

### The portable kernel
- `prismpath/portable/prismpath.mjs`; parser + predicate sandbox + engine for the ML-free subset in one
  dependency free ES module (browser/edge/Node), certified against the vectors; the
  **playground** (`prismpath/portable/playground.html`) runs it client-side.

### Measured
- N=300/301 labeled routing suite + reproducible head to head vs LangGraph / CrewAI /
  LLM-router; **hybrid-over-centroids**: 90.0% @ 160 LLM calls/1k, 95.3% @ 360, 98.0% @ 507
  (5-fold CV, shared LLM pass; `prismpath/benchmark/hybrid_sweep.py`); polarity 0.52 → 0.92. Prefilter
  reuse audited live (97% oracle agreement, zero unsafe downgrades).
