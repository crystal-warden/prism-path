# SPEC: Policy distribution

*Design spec, work package D1 of D1 to D10. It defines how one signed policy reaches every enforcement
point and stays true there. Companion to `spec-secure-hotswap.md` (the swap on one host),
`spec-cause-codes.md` (the refusal registry) and `PROTOCOL.md` section 2.6 (Facet). Python is the
reference implementation and Linux the reference platform. Crystal Warden Labs, 2026-11-22.*

Every rule below has an identifier. Section 20 lists the conformance cases, and each case names the rules
it tests. A rule with no case, or a case with no rule, is a defect in this document.

## 1. Scope and decisions taken as given

A policy enforcement point (PEP) is any place that decides under a signed policy. The kinds are in
section 3. A controller is the service that stores signed artifacts and hands them out. This spec defines
the signed envelope every distributed artifact travels in, the messages, the state machine of a PEP and of
a controller, revocation, rotation, the widening rule, clocks, first key provisioning, the heartbeat and
the refusal causes.

The owner decided these, and the rules below carry them out.

| Decision | Where it is enforced |
|---|---|
| The transport is untrusted and the signature carries trust | S1 to S7, B1, B9, B10, F1 |
| Never downgrade. The floor only rises and a rollback never lowers it | Q1 to Q5, RB1 to RB3, L2 |
| Fail closed everywhere | V1, X1 to X3, R5, Q5, D1 |
| At expiry a `mesh` or `cfs` deployment may choose HOLD. REFUSE is the default and hosts always refuse | X6 to X10, H8 |
| Authority keys and instance keys stay separate | K2, H2, O4 |
| Never widen silently | W1 to W7 |
| Hosts pull over HTTP. Push only where the medium is a broadcast | B1 to B8 |
| One signed envelope for every distributed artifact | E1 to E9, L1 to L4 |
| Escape hatches only in dev builds | D1 to D4 |
| The cFS lost floor response is a mission choice and LOCK is the default | Q5 |

Out of scope. A PEP that has been compromised can lie in its state record, because the record says what
the PEP claims. Hardware attestation would say more and is not designed here. A signature threshold above
one is not in this version, though the format carries up to four signatures (S2) so it can be added
without a new format.

Stated limits. An authority key in the wrong hands can sign a `seq` so high that the stream cannot
advance. TUF calls this a fast forward attack (TUF section 1.5.2) and recovers by having root rotate the
key and the client forget the versions. This spec keeps the rule that no message lowers a floor, so the
recovery is the provisioning step (P3) after the key is rotated and revoked. A controller in the wrong
hands can withhold releases and revocations and can choose among unrevoked releases at or above a PEP's
floor. It can do nothing else, and the longest it can freeze a PEP is the time left on that PEP's
envelope (X2).

A note on the word envelope. The repository already uses it twice. `spec-secure-hotswap.md` section 3.2
has the qualification envelope, the caps and fields a pack must stay inside, named by `envelope_id`.
`spec-intoto-receipts.md` has the DSSE envelope. The object defined here is always written **distribution
envelope**, and its format tag is `prismpath.dist/1`.

## 2. Terms

| Term | Meaning |
|---|---|
| Authority key | An Ed25519 key that says which policy may run. Its key id is the SHA-256 of its 32 raw public bytes, in lower case hex. |
| Instance key | An Ed25519 key one PEP makes for itself. It signs what that PEP reports and never authorizes anything. |
| Trust store | What a PEP holds about authority keys. The trusted keys, the retired keys, the revocation list, the trust sequence and the threshold. |
| Stream | A named line of policy that one group of PEPs follows, for example `agent/default` or `mesh/demo`. A name is 1 to 64 characters of `a-z 0-9 . _ / -`. The reserved stream `@trust` carries revocations and rotations. |
| Policy hash | The SHA-256 of the policy document every artifact of a release derives from. It is the `prismpath.core/1` image bytes when the policy has one, and the `.ppt` image bytes otherwise. |
| Distribution envelope | The canon/2 document of section 4 that names one artifact body by hash. |
| Envelope id | The SHA-256 of the envelope's canon/2 bytes, in lower case hex. Signatures are not part of it. |
| Sealed envelope | The envelope bytes with their signature block (section 4.3). |
| Release | Every sealed envelope that shares one stream, one `seq` and one policy hash. A PEP commits a release whole. |
| Floor | The highest `seq` a PEP has committed on a stream, with the envelope ids committed at it. |

### 2.1 The roles in standard terms

| Here | NIST SP 800-207 section 3.1 | RFC 9334 section 4.1 | TUF and Uptane |
|---|---|---|---|
| The authority, who signs what may run | The source of the data access policies. It is not the policy engine | Reference value provider | The root and targets roles (TUF 2.1.1, 2.1.2), the Image repository (Uptane 5.3.1) |
| The decision under the signed policy, made inside each PEP | Policy engine | | |
| The controller | Policy administrator, the part that reaches PEPs over the control plane. It makes no decision and holds no authority key | Verifier and relying party for state records | A mirror (TUF 2.1.5). It is weaker than the Uptane Director (5.3.2), which signs |
| The PEP | Policy enforcement point | Attester | A client, an ECU (Uptane 5.4) |
| A relay (B10) | Part of the control plane | | A Primary that only forwards (Uptane 5.4.2.6) |
| State records and receipts | Network and system activity logs, and the asset state a CDM system gathers | Evidence | The ECU version report (Uptane 5.4.2.1.2) |

800-207 assumes a protected control plane. This spec does not, because every control message that
matters is signed.

## 3. Target kinds and artifact kinds

A target kind names a kind of PEP. An artifact kind names a kind of body. Both are closed lists in this
version. An implementation holds them in one table so that a new kind is one row.

| Target | The PEP | Artifacts it needs before it commits | Can it decide "larger" itself |
|---|---|---|---|
| `host` | The software tier of `prismpath/hotswap/policy_host.py` | `policy.ppt`, and `policy.spiral` when the `policy.ppt` envelope's `meta` has `packing` | No |
| `agent` | One agent home. The hook, the decider, the sandbox profile, the egress proxy and the MCP proxy all read it (`prismpath/agent/commands.py`, `load_checked`) | `policy.core`, `egress.hosts` | Yes |
| `gateway` | One gateway home (`prismpath/gateway/proxy.py`) | `policy.core`, `gateway.routes` | Yes for the policy. A changed route table is always a widening |
| `xdp` | The host preloader in front of the XDP loader (`prismpath-ebpf/net_swap.py`) | `policy.core`, `net.dests`, `net.edge` | Yes |
| `mesh` | One ESP32 node (`prismpath-hw/mesh/main/ppt_mesh.c`) | `policy.ppt` | No |
| `cfs` | The cFS app (`integrations/cfs/prismpath_app`) | `cfs.table` | No |

The hook, the sandbox, the egress proxy and the MCP proxy are one target because they read one home. One
home holds one release, so they cannot hold different versions of one policy.

| Artifact | Body | `meta` members | Check beyond the hash (V11) |
|---|---|---|---|
| `policy.core` | A `prismpath.core/1` image in canon/2 bytes with no trailing line feed | none | The image loads (`prismpath.agent.policy.Policy`) and its SHA-256 is `policy_sha256` |
| `policy.ppt` | A `.ppt` image | `fields`, `counts`, `wcet_cycles`, `qualification`, and when present `packing`, `flow_sha256`, `overlay_of`. They mean what the same members of a `ppt-pack/1` manifest mean, and `qualification` is its `envelope_id` | `validate_image`, the counts, the recomputed WCET and the qualification envelope gate, with their existing causes. A `mesh` target runs its own table parser and ignores `meta` |
| `policy.spiral` | The spiral sidecar bytes (`<name>.ppt.spiral`) | none | Its SHA-256 is the `sidecar_sha256` in the staged `policy.ppt` envelope's `meta.packing`. A missing one is `spiral:sidecar-missing` at commit and a wrong one `spiral:sidecar-hash-mismatch` |
| `sandbox.profile` | A sandbox profile in canon/2 bytes (`Profile.canonical`) | `compiler` | The PEP compiles the profile from the staged `policy.core` and the bytes must be equal. Optional for `agent`, and checked when present |
| `egress.hosts` | A canon/2 array of lower case host names, sorted, without repeats. It may be empty | none | Each name is one the egress proxy can read |
| `gateway.routes` | A route table document in canon/2 bytes | none | `Routes.from_doc` accepts it |
| `net.dests` | A `prismpath.net_dests/1` destination table in canonical form | none | The table is one the edge can use |
| `net.edge` | The edge `.ppt` image | `flow_sha256`, `names_sha256`, `qualification` | The table recompiled from the staged `policy.core` and `net.dests` is byte for byte the body |
| `cfs.table` | The `PP_PolicyTable_t` bytes before `ImageSig` | none | The kernel check, and the SHA-256 of the core image inside the table is `policy_sha256` |
| `grant` | A grant document (section 13) | none | Section 13 |
| `trust.widening` | A widening statement (section 9.4) | none | Section 9.4 |
| `trust.revocation` | A revocation list (section 10) | none | Section 10 |
| `trust.rotation` | A rotation statement (section 11) | none | Section 11 |

## 4. The distribution envelope

### 4.1 The document

**E1.** A distribution envelope is a canon/2 object with exactly these fifteen members. A missing member,
an extra member or a value outside the stated form is refused with `dist:bad-format`.

| Member | Form | Meaning |
|---|---|---|
| `artifact` | one artifact kind of section 3 | What the body is |
| `body_sha256` | 64 lower case hex digits | SHA-256 of the body bytes |
| `body_size` | integer, 0 to 16777215 | Length of the body in bytes |
| `encoding` | `canon/2` | As every signed document names it |
| `expires` | integer, Unix seconds | The envelope stops counting at this second. 0 only on a trust kind (X4) |
| `format` | `prismpath.dist/1` | |
| `meta` | object of the members section 3 lists for the artifact, strings and integers and one level of object | Facts about the body that are signed with it |
| `not_before` | integer, Unix seconds | The envelope does not count before this second |
| `policy_sha256` | 64 lower case hex digits | The policy hash. On a `@trust` envelope it is 64 zeros |
| `release` | 64 lower case hex digits | The release id (E10). On a `@trust` envelope it is 64 zeros |
| `replaces` | 64 lower case hex digits, or the empty string | The policy hash the signer compared against when setting `widens` |
| `seq` | integer, 1 to 2^53 - 1 | The sequence number on the stream |
| `stream` | a stream name | |
| `targets` | array of target kinds, sorted, at least one, no repeats | The PEP kinds this envelope is valid for |
| `widens` | `true` or `false` | The signer's statement that the release allows something `replaces` did not |

**E2.** The envelope bytes are the canon/2 bytes of that object (`prismpath.kernel.canon2.dumps`). A reader
that parses bytes which are canon/2 but not canonical refuses with `document:not-canonical` and never
writes them again in another spelling.

**E3.** The envelope id is the SHA-256 of the envelope bytes.

**E4.** An envelope names exactly one body. The body travels beside the envelope and is never changed to
carry it, so every certified image hash stays what it was.

**E5.** `expires` is greater than `not_before`, except on a trust kind where it is 0.

**E6.** An envelope is at most 2,048 bytes. A PEP may set a lower bound for the body and refuses a larger
one with `dist:too-large`. The `mesh` bound is 640 bytes (`TBL_MAX`) and the `cfs` bound is the table
size.

**E7.** Every envelope of one release carries the same `stream`, `seq`, `policy_sha256`, `release`,
`replaces` and `widens`.

**E8.** A reader ignores nothing. An unknown artifact kind or target kind is `dist:bad-format`.

**E9.** A PEP on a constrained target reads the envelope with a strict scanner that accepts the members in
canonical order and skips the value of `meta`. It runs the scanner only on bytes whose signature it has
already checked (V3 comes before V4).

**E10.** The release id is the SHA-256 of the canon/2 bytes of the array of `[artifact, body_sha256]`
pairs of every artifact in the release, sorted. The signer computes it over the whole release, so two
envelopes belong to one release only when the authority signed them as one set. A PEP does not need the
other bodies to use it. It requires the same `release` on every envelope it stages together (E7) and
reports it (H1), and that is what stops a mix of artifacts that were never released together (TUF's mix
and match, section 1.5.2).

### 4.2 What is signed

**S1.** A signature is Ed25519 over the DSSE pre-authentication encoding of the envelope bytes with the
payload type `application/vnd.prismpath.dist+json`. The signed bytes are the 46 bytes
`DSSEv1 35 application/vnd.prismpath.dist+json ` (ending in a space), the envelope length in ASCII
decimal, one space, and the envelope bytes. `prismpath/ledgers/intoto.py` already has this encoding
(`pae`). No canonical form is needed to check a signature, since the bytes that were signed are the
bytes that travel.

**S7.** A sealed envelope maps to a DSSE JSON envelope and back with no loss. `payload` is the envelope
bytes in base64, `payloadType` is the one above, and each entry is a `signatures` member whose `keyid` is
the key id in hex and whose `sig` is the signature in base64. Any DSSE verifier that holds the authority
public key can check it.

### 4.3 The sealed envelope

**S2.** A sealed envelope is one byte string, the same on every transport. The signatures come first, so
a small PEP can check one signature in a single pass over the envelope without holding it in memory.

```
offset     size  field
0          4     magic "PPDE"
4          1     container version, 1
5          1     k, the number of signatures, 1 to 4
6          96*k  k entries, each a 32 byte key id followed by a 64 byte signature
6+96k      2     n, the envelope length, little endian, 1 to 2048
8+96k      n     the envelope bytes
```

Any other length, magic or version is `dist:bad-format`. Entries are sorted by key id and no key id
repeats.

**S3.** An entry counts when its key id names a key the trust store holds in the role the artifact needs
(K4), that key is neither revoked nor retired, and the signature verifies. A key id is a hint for finding
the key and decides nothing by itself. An entry that does not count is skipped, as DSSE skips it.

**S4.** An envelope is signed when the number of counting entries is at least the trust store's
threshold. The threshold is 1 in this version.

**S5.** An envelope that is not signed is refused with one cause, the first of these that applies.
`sig:revoked-key` when an entry verifies under a revoked or retired key. `sig:invalid` when an entry
names a key the store holds and does not verify. `dist:unknown-key` otherwise.

**S6.** The signature block is not signed. Adding, removing or reordering entries never changes the
envelope id and never makes an unsigned envelope signed.

## 5. Keys and the trust store

**K1.** A PEP holds a trust store with the trusted authority keys, the retired key ids, the current
revocation list, the trust sequence and the threshold. It is durable, and a PEP that cannot read it
refuses every envelope with `dist:unknown-key` and decides nothing (X3). Its durable form is a canon/2
document with format `prismpath.dist-trust-store/1`.

**K2.** A PEP holds its own instance key. An instance key that is also a trusted authority key is refused
at start, as `root_statement.check_separation` refuses it today. A PEP under distribution holds no
authority private key.

**K3.** The trust store changes only by first key provisioning (section 14), by a `trust.rotation` and by
a `trust.revocation`. No other message changes it.

**K4.** Every key in the trust store has a role. This version has one role, `authority`, and every
artifact kind needs it. A key in a role this version does not know is kept and never counts.

## 6. Sequence numbers and the floor

**Q1.** A PEP keeps one floor per stream. It is the highest `seq` it has committed and the envelope ids it
committed at that `seq`. The floor is durable before the release is active (C4).

**Q2.** An envelope whose `seq` is below the floor is refused with `dist:seq-replay`.

**Q3.** An envelope whose `seq` equals the floor is accepted only when its envelope id is one committed at
the floor, which implies the committed release id. It changes nothing and the PEP reports its state. Any other envelope at the floor is
`dist:seq-replay`.

**Q4.** Nothing lowers a floor. A `trust.revocation` may raise one (R4).

**Q5.** A PEP whose floor cannot be read is locked. It admits no release, decides nothing and reports
`dist:floor-lost`. Only a provisioning step clears it. On cFS the mission chooses the response with
`PRISMPATH_APP_PLATFORM_LOST_FLOOR`, and `PP_LOST_FLOOR_LOCK` stays the default.

## 7. Clocks

The trust assumption is stated once. A PEP trusts its own clock to be within 300 seconds of true time
(`SKEW`). The transport and the controller are not time sources.

**T1.** A PEP keeps a durable time floor. It is the highest `not_before` of any envelope whose signature it
has verified. The PEP's time is the larger of its clock and the time floor, so a clock set back cannot
bring an expired envelope back.

**T2.** A PEP with no real time clock, such as a `mesh` node, counts from its time floor with its
monotonic timer and saves the result at least once an hour. Such a PEP can run slow by the time it spent
without power and never runs fast. Its expiry is late by at most that time, and this is the stated limit
of T2. It catches up by V13, since every envelope the authority signed is evidence of a later time.

**T3.** A PEP with a clock refuses an envelope with `dist:not-yet-valid` when its time is more than
`SKEW` before `not_before`. A PEP with no clock has no ground to call an envelope early and does not
apply this rule. For that PEP the authority's `not_before` is the time source, as the attested time is
for an Uptane ECU without a clock (Uptane 5.4.1).

**T4.** An envelope is refused with `dist:expired` when the PEP's time is at or past `expires`. There is no
grace after expiry.

## 8. Messages and the two bindings

### 8.1 The messages

| Message | From | Carries | Meaning |
|---|---|---|---|
| `offer` | controller | envelope id, stream, `seq`, artifact kind, sealed length, body length | A sealed envelope exists for this PEP |
| `fetch` | PEP | a SHA-256 | Send the bytes with this hash. HTTP binding only |
| `stage` | controller | the sealed envelope and the body | Verify these and hold them |
| `stage-ack` | PEP | a state record with event `staged` or `refused` | The result of verifying one envelope |
| `commit` | controller | stream, `seq`, policy hash, delay in milliseconds | Make the staged release active |
| `abort` | controller | stream, `seq`, policy hash | Drop the staged release |
| `state` | PEP | a state record | The heartbeat, and the report of every transition |
| `epoch` | controller | an epoch id | The controller's name for the present, echoed in state records (H9) |
| `revoke` | controller | a sealed `trust.revocation` and its body | Applied when verified, with no commit |
| `rotate` | controller | a sealed `trust.rotation` and its body | Applied when verified, with no commit |

**B1.** No message is trusted for who sent it. `offer`, `fetch`, `commit` and `abort` are not signed. A
forged `commit` can only make active a release the authority signed for that PEP, and a forged `abort`
can only delay one. Staging a release is therefore consent to run it, and a release the owner no longer
wants is revoked (section 10), not aborted.

**B2.** `revoke` and `rotate` are `stage` of a trust kind. A PEP applies a trust envelope as soon as it
verifies and sends a state record with event `trust-applied` or `refused`.

### 8.2 The HTTP binding, for hosts

**B3.** A host PEP pulls. It opens every connection itself, and the controller never connects to a PEP.
The default poll interval is 30 seconds.

| Request | Answer |
|---|---|
| `GET /dist/v1/offers/<pep id>` | A JSON object with `epoch`, `offers` (a list of offer objects), `commit` and `abort` (lists of `{stream, seq, policy}`) |
| `GET /dist/v1/blob/<sha256 hex>` | The bytes whose SHA-256 that is. A sealed envelope is asked for by its envelope id and a body by `body_sha256` |
| `POST /dist/v1/state` | Body is one state record. The answer is 204 |

**B4.** A PEP checks the hash of every blob it fetched before it reads it. A sealed envelope fetched by
envelope id must contain an envelope with that id. A mismatch is `dist:body-mismatch`.

**B5.** The JSON of `offers` is not signed and is read as a hint. A wrong hint costs a fetch and a refusal
and nothing else.

### 8.3 The frame binding, for a broadcast medium

Used on ESP-NOW and on the cFS software bus, where one sender reaches every PEP at once. Integers are
little endian. A frame is at most 250 bytes on ESP-NOW (`ESP_NOW_MAX_DATA_LEN`).

```
all frames   0  1  type      1 offer, 2 chunk, 3 state, 4 commit, 5 abort, 6 epoch
             1  1  version   1
             2  2  transfer  chosen by the sender, one per sealed envelope

offer        4  16 first 16 bytes of the envelope id
             20 2  sealed length
             22 4  body length
chunk        4  1  part      0 sealed envelope, 1 body
             5  4  offset
             9  2  length, then that many bytes
commit       4  16 first 16 bytes of SHA-256 of the stream name
             20 8  seq
             28 16 first 16 bytes of the policy hash
             44 2  delay in milliseconds
abort        as commit, without the delay
state        4  n  one state record
epoch        4  8  the epoch id
```

**B6.** A PEP assembles the chunks of a transfer into the lengths the offer gave. A chunk outside those
lengths, a chunk for a transfer with no offer, or an assembled part whose hash is wrong drops the
transfer with `dist:frame-invalid`. Chunks may arrive in any order and may repeat.

**B7.** A PEP holds at most one transfer per part at a time and a transfer that is not complete after 5
seconds is dropped silently, so lost frames cost a retry and never a partial stage.

**B9.** A PEP never reads more than it was promised. It reads at most 2,440 bytes for a sealed envelope
(the largest S2 allows) and at most the signed `body_size` for a body, and it reads the body only after
the envelope verified through V8. An `offers` answer over 64 kilobytes is dropped. This is the bound
against endless data (TUF section 1.5.2).

**B10.** A relay passes frames between a medium and a PEP that has no radio of its own, such as an
ESP32-C6 in front of a board on a serial line. A relay holds no key, verifies nothing, and is not a PEP.
It is part of the untrusted transport, so what it drops or changes is caught by the PEP behind it. The
frame binding runs unchanged on the link behind a relay, with that link's own frame limit.

**B11.** A link may be declared ordered. On an ordered link the sender sends the chunks of a part in
offset order without repeats, and the PEP drops a transfer whose chunk is out of order with
`dist:frame-invalid`. This lets a PEP that cannot hold a sealed envelope check it as it arrives.

**B8.** A `commit` with a delay makes the release active at the PEP's own monotonic time plus the delay, so
a group flips together without a shared clock, as the mesh does today with `FLIP_DELAY`.

## 9. The PEP state machine

A PEP runs one machine per stream it follows. The states are these.

| State | Meaning |
|---|---|
| `no-policy` | Nothing is active. Every decision is a refusal with `dist:policy-lapsed` or the PEP's own fail closed cause |
| `active` | One release is active |
| `staged` | A release is verified and held beside whatever is active. It is a sub state of the two above |
| `locked` | The floor is lost (Q5) |

### 9.1 Verify

**V1.** A PEP verifies every sealed envelope in the order V2 to V12. The first rule that fails is the only
cause reported and nothing is staged.

| Rule | Check | Cause when it fails |
|---|---|---|
| V2 | The sealed container reads (S2) and the envelope and body fit the PEP's bounds (E6) | `dist:bad-format`, `dist:too-large` |
| V3 | The signatures (S3 to S5) | `dist:unknown-key`, `sig:invalid`, `sig:revoked-key` |
| V4 | The envelope reads (E1, E2, E5, E8) | `document:not-canonical`, `dist:bad-format` |
| V5 | `targets` holds this PEP's kind, `artifact` is one this kind uses or a trust kind, and `stream` is this PEP's stream or `@trust` for a trust kind | `dist:target-mismatch` |
| V6 | Time (T3, T4, and X4 for a trust kind) | `dist:not-yet-valid`, `dist:expired` |
| V7 | The envelope id and the policy hash are not on the revocation list | `dist:revoked` |
| V8 | The sequence (Q2, Q3, or R1 and O1 for a trust kind) | `dist:seq-replay`, `dist:trust-replay` |
| V9 | The body has `body_size` bytes and hashes to `body_sha256` | `dist:body-mismatch` |
| V10 | The envelope agrees with what is already staged at this `seq` (E7) | `dist:incomplete` |
| V11 | The artifact's own check, from the table in section 3 | The check's existing cause, or `dist:derived-mismatch` when a recompiled artifact differs |
| V12 | The widening rule (W1 to W7) | `dist:widening-unsigned` |

**V13.** After V6 passes, the PEP raises its time floor to `not_before` (T1).

### 9.2 Stage, commit and abort

**G1.** An envelope that passes V2 to V12 is staged. The PEP writes it and its body durably and sends
`stage-ack` with event `staged`. A refusal sends `stage-ack` with event `refused` and the cause. Both are
written to the PEP's audit log.

**G2.** A staged release is replaced by a staged envelope with a higher `seq` on the same stream. A lower
`seq` than the staged one is `dist:seq-replay`.

**C1.** A `commit` that names no staged release is answered with a state record whose cause is
`dist:not-staged`, and nothing changes.

**C2.** A PEP commits only when every artifact its target kind needs (section 3) is staged with one
stream, one `seq` and one policy hash. Otherwise the cause is `dist:incomplete` and nothing changes.

**C3.** At commit the PEP checks time (T3, T4) and revocation (V7) again for every staged envelope, since
both can change after staging. A failure drops the staged release and reports the cause.

**C4.** A commit is durable in a fixed order, each step synced before the next. The intent record, the
floor, the audit event, the artifacts under content addressed names, the active record that names them,
then the cleanup. This is the order `policy_host.py` uses today. A death before the active record flips
leaves the previous release active, and a death after it leaves the new one. A restart finishes or
reports an interrupted commit and never reads an artifact the active record does not name.

**C5.** After a commit the PEP sends a state record with event `committed`.

**A1.** An `abort` that names the staged release drops it and sends a state record with event `aborted`.
An `abort` that names anything else changes nothing. Abort never touches the active release or the floor.

### 9.3 Local rollback

**RB1.** A PEP may keep the release it replaced and return to it on a local operator command, as
`PolicyHost.rollback` does. A rollback never lowers the floor.

**RB2.** A rollback is refused unless every envelope of the kept release still passes T4 and V7.

**RB3.** A rollback to a release that allows more than the active one is a widening and falls under W1 to
W7. A PEP that cannot decide refuses it unless it holds a widening statement that covers it.

### 9.4 The widening rule

A release is **larger** than another when some request is treated more permissively. For a policy the
order is refuse, then escalate, then allow, and a release is larger when any reading of the finite reading
domain moves up that order, or when the two policies do not have the same fields. For `egress.hosts` and
for the address set of `net.dests`, larger means not a subset. For `gateway.routes` any change is larger,
because a path that loses its route reads as another class. Going from no policy to any policy is larger.

**W1.** A PEP that can decide (section 3) computes whether the staged release is larger than the active
one. It does not trust `widens` for that.

**W2.** A PEP that cannot decide treats the release as not larger only when `widens` is `false` and
`replaces` is the policy hash it has active. In every other case it treats the release as larger.

**W3.** A release that is larger is staged only when a `trust.widening` envelope of the same release is
staged with it. Otherwise the cause is `dist:widening-unsigned`.

**W4.** A widening statement is an envelope with artifact `trust.widening`, the same `stream`, `seq` and
`policy_sha256` as the release, and this canon/2 body.

```json
{"encoding":"canon/2","format":"prismpath.dist-widening/1","from":["<policy hash>", "..."]}
```

`from` is sorted. It lists the policy hashes the release may replace. An empty list means any, including
none. The statement covers a PEP when `from` is empty or holds the PEP's active policy hash.

**W5.** A widening statement is signed by the authority. In this version every envelope is, so the rule
asks for a second, separate signed statement. That is what makes a widening an act the owner takes on
purpose and what the audit log records.

**W6.** A PEP that can decide and finds `widens` is `false` on a release it computes as larger refuses it
with `dist:widening-unsigned` even when a statement is present, because the signer's claim is wrong.

**W7.** A controller checks W1 itself before it offers a release to a target that cannot decide, and
refuses to offer one whose `widens` is `false` and which it computes as larger.

## 10. Revocation

A revocation list is cumulative. Each one replaces the one before.

```json
{"encoding":"canon/2","envelopes":["<envelope id>"],"floors":{"<stream>":7},
 "format":"prismpath.dist-revocation/1","keys":["<key id>"],"policies":["<policy hash>"]}
```

Each list is sorted and holds at most 64 entries, and `floors` at most 16 streams. An old entry is retired
by raising a floor past it.

**R7.** A list with more entries than that is refused with `dist:too-large`.

**R1.** A `trust.revocation` travels on the stream `@trust`. Its `seq` is the trust sequence. A PEP accepts
one only when its `seq` is exactly the PEP's trust sequence plus one, as TUF takes root version N+1 and
no other (TUF 5.3.5). The same envelope again changes nothing. Any other is `dist:trust-replay`, so an
older list cannot replace a newer one and no trust statement is skipped. A controller offers the trust
statements a PEP lacks in order.

**R2.** After a revocation is applied, an envelope signed only by keys in `keys` is refused with
`sig:revoked-key`, and an envelope whose id is in `envelopes` or whose policy hash is in `policies` is
refused with `dist:revoked`.

**R3.** A revocation is applied as soon as it verifies. It is durable before the PEP reports it.

**R4.** Each stream in `floors` raises that stream's floor to the number given when the number is higher.
A release below it is `dist:seq-replay`.

**R5.** When a revocation removes the ground the active release stands on, the PEP goes to `no-policy` and
reports event `lapsed` with `dist:revoked`. That is the case when an active envelope's id or policy hash
is listed, when its `seq` is below a raised floor, or when it no longer has a counting signature. A staged
release is dropped on the same test. The owner avoids an outage by order of work. Rotate, release under
the new key, commit, then revoke the old key.

**R6.** A revocation list never restores trust. Removing an entry from a later list does not make a
refused key or envelope acceptable again unless a floor has passed it, and a key id once in `keys` stays
refused for the life of the trust store.

## 11. Rotation

```json
{"add":"<64 hex digits, the new public key>","encoding":"canon/2",
 "format":"prismpath.dist-rotation/1","retire":"<key id, or the empty string>"}
```

**O1.** A `trust.rotation` travels on `@trust` and its `seq` follows R1. Revocations and rotations share
the one trust sequence, so their order is total.

**O2.** A rotation is accepted only when its sealed envelope is signed under the store as it is now and
also under the store as the rotation would leave it, which is TUF's rule for a new root (TUF 5.3.4). With
a threshold of 1 that means a counting signature by a key the store trusts now and a valid signature by
the key in `add`. A rotation signed only by keys the store does
not know is `dist:unknown-key`. One that lacks the new key's signature is `dist:rotation-invalid`.

**O3.** On acceptance the PEP adds the new key. When `retire` names a trusted key, that key is retired.
A retired key's signatures no longer count (S5), and a release already active under it stays active
until it expires or is replaced. `retire` that names an unknown key is `dist:rotation-invalid`.

**O4.** `add` is never the PEP's own instance key, and never a key id on the revocation list. Either is
`dist:rotation-invalid`.

## 12. Expiry

**X1.** A PEP checks the `expires` of every envelope of its active release at least once a minute and
before it reports state. When one has passed, the PEP goes to `no-policy` and reports event `lapsed` with
`dist:expired`, unless X6 and X7 put it on hold.

**X2.** This is fail toward expiry. A PEP that is cut off from the controller, and so from any
revocation, keeps deciding under its last release until that release expires and not after. The longest a
revoked release can keep deciding at a cut off PEP is the time left on its envelope, plus the limit of T2
on a PEP without a clock. A deployment that chose HOLD (X6) has given this bound up for that PEP and
keeps only what X8 and X9 state.

**X3.** A PEP in `no-policy` or `locked` allows nothing. The cause on its receipts is
`dist:policy-lapsed`, or `dist:floor-lost` when locked.

**X4.** A trust kind carries `expires` 0 and never expires. A revocation that could expire would restore
trust on its own.

**X5.** The owner keeps a fleet alive by renewing. A renewal is a new release with a higher `seq`, the same
bodies and a later `expires`. A PEP that already holds a body does not fetch it again.

**X6.** The response to expiry is a setting of the deployment on the `mesh` and `cfs` targets, as the cFS
lost floor response is. Its values are REFUSE and HOLD, and REFUSE is the default. The `host`, `agent`,
`gateway` and `xdp` targets have no such setting and always follow X1.

**X7.** Under HOLD a PEP whose active release expires keeps deciding under that release and no other. It
reports event `held` with `dist:held`, sets bit 5 of `status` in every state record while the hold lasts,
and marks every receipt it writes in that time as held. A hold is therefore visible in everything the PEP
signs.

**X8.** A held PEP still applies every other rule. A revocation that reaches the active release ends the
hold in `no-policy` (R5). The floor, the trust store, the verifier and the widening rule are unchanged, so
a replayed or expired envelope is refused as before. A lost floor still locks (Q5).

**X9.** A hold never widens. A held PEP refuses a local rollback with `dist:held`, and the only way out
of a hold other than X8 is the commit of a release that passes every rule, which clears bit 5 and
reports `committed`.

**X10.** The setting is fixed when the PEP is built or provisioned. No message changes it, and a PEP that
is given HOLD on a target X6 does not allow refuses to start.

## 13. Grants

A grant is carried by a client and read on the request path, so it stays small. From this version a grant
is a sealed envelope with artifact `grant`, target `gateway`, the gateway's stream, `seq` 1 and a body of
the classes it covers.

```json
{"encoding":"canon/2","format":"prismpath.dist-grant/1","method_classes":["read"],"path_classes":["admin"]}
```

**GR1.** The header value is the sealed envelope and the body, each base64url without padding, joined by
a dot. `policy_sha256` is the policy the grant was issued under, `not_before` and `expires` are its
lifetime, and the lifetime is at most 30 days.

**GR2.** A gateway reads a grant with V2 to V7 and V9. It does not apply the floor (a grant is not a
release) or the widening rule (a grant is the owner's signed widening for one scope). The reading is
`valid`, `expired`, `invalid` or `none`, as `prismpath/gateway/grants.py` defines them.

**GR3.** A grant is revoked by its envelope id in a `trust.revocation`. A gateway under distribution reads
no other revocation list.

## 14. First key provisioning

The first authority key cannot arrive over the transport, because nothing yet says whom to believe.

**P1.** A PEP with an empty trust store refuses every envelope with `dist:unknown-key`. No message installs
a first key.

**P2.** The procedure is five steps.

1. The owner makes the authority key away from every PEP and keeps the private half there.
2. Each PEP makes its own instance key. The private half never leaves it.
3. The owner installs the trust anchor on the PEP by a channel the owner already trusts. On a host that is
   a file copied by the operator, on a `mesh` node it is compiled into the firmware that is flashed, and
   on `cfs` it is the key file the ground provisioning writes. The anchor is a canon/2 document
   (`prismpath.dist-trust/1`) with the trusted public keys, the threshold, the PEP's target kind and its
   stream.
4. The PEP prints the fingerprint of the anchor and the operator compares it with the one the owner's
   tool printed. A host PEP does not start following a stream until the operator confirms.
5. The owner enrolls the PEP's instance public key, target kind and stream at the controller.

**P3.** Provisioning sets the trust sequence, the floor and the time floor to their starting values and is
the only step that clears `locked`. It is written to the audit log as its own event.

## 15. The heartbeat and the fleet view

### 15.1 The state record

**H1.** A state record is this byte string. Integers are little endian.

```
offset  size  field
0       4     magic "PPSR"
4       1     version, 1
5       1     event     0 beat, 1 staged, 2 refused, 3 committed, 4 aborted,
                        5 trust-applied, 6 lapsed, 7 rolled-back, 8 provisioned, 9 held
6       1     status    0 no-policy, 1 active, 2 locked. Bit 7 set when a release is staged.
                        Bit 6 set when this is a dev build (D3). Bit 5 set while the PEP is
                        on hold past expiry (X7)
7       1     cause     a registered cause code, 0 for none
8       16    PEP id, the first 16 bytes of SHA-256 of the instance public key
24      8     counter
32      8     the PEP's time, Unix seconds
40      8     epoch, the latest epoch id the PEP has seen from the controller, 0 for none (H9)
48      16    first 16 bytes of SHA-256 of the stream name
64      16    first 16 bytes of the active policy hash, zeros for none
80      16    first 16 bytes of the active release id, zeros for none
96      8     active seq
104     8     floor
112     16    first 16 bytes of the staged release id, zeros for none
128     8     staged seq
136     8     trust sequence
144     2     m, the Facet body length, 0 to 1024
146     m     the Facet body
146+m   2     x, the extension length, 0 to 512
148+m   x     the extensions (H10)
148+m+x 64    Ed25519 signature by the instance key over the DSSE pre-authentication encoding
              (S1) of bytes 0 to 148+m+x with the payload type
              application/vnd.prismpath.dist-state
```

**H2.** The record is signed by the instance key and by no other. An authority key never signs one.

**H3.** `counter` rises by at least one with every record and is durable, so a record is never sent twice.

**H4.** A PEP sends a record after every transition (the events above) and a `beat` at least every 30
seconds on a host. A `mesh` node and the `cfs` app send theirs with their existing status line and
housekeeping packet.

**H5.** The Facet body is a grouped spiral stream of `PROTOCOL.md` section 2.6.1 at the band tier. Its
frames are the decisions the PEP made since its previous record, at most 64, the oldest dropped first. The
stream is built from the canonical flow text of the active policy, so its 42 byte preamble carries that
policy's hash and layout hash. A PEP that does not encode Facet sends a body of length 0. The `mesh` and
`cfs` targets send length 0 in this version. Section 2.6.1 is added to `PROTOCOL.md` by the grouped spiral
profile change (pull request 107), which lands before the heartbeat does.

### 15.2 How a mismatch is detected

A PEP on the wrong policy is found by comparing hashes, never by a decode that happens to fail.

**H6.** The controller checks a record in this order and files the first finding.

| Step | Check | Finding |
|---|---|---|
| 1 | The record reads, the PEP id is enrolled and the signature verifies under the enrolled instance key | `fleet:state-invalid` |
| 2 | `counter` is above the last one accepted from this PEP, and `epoch` is the controller's current epoch id or the one before | `fleet:state-replay` |
| 3 | The active policy hash prefix, release id prefix and `seq` are the ones the controller expects for this PEP | `fleet:policy-mismatch` |
| 4 | When the body is not empty, its preamble's policy hash and layout hash equal the ones the controller computes from the expected policy | `fleet:policy-mismatch` |
| 5 | The body decodes under the expected policy | `wire:codebook-mismatch` |

**H9.** A controller names the present with an epoch id, a number that rises at least once per heartbeat
interval. It rides in the `offers` answer as `epoch` and in a frame of type 6 (bytes 4 to 11). A PEP puts
the highest epoch id it has seen in every record. This is the epoch id of RFC 9334 section 10.3. It tells
the controller that a record was made after that epoch began, which the PEP's own clock cannot prove. An
epoch id is not signed, changes nothing but that field, and a PEP never lowers the one it holds.

**H10.** The extensions are a run of entries, each a type byte, a two byte length and that many bytes.
The instance key's signature covers them. Type 1 is an Entity Attestation Token (RFC 9711) whose
`eat_nonce` is the SHA-256 of bytes 0 to 146+m of the record, so hardware evidence is bound to one state
record. Type 2 is reserved for the record of a member a PEP speaks for. A PEP in this version sends none.
A controller skips a type it does not know and never treats an extension as a signature on the record.

**H7.** A PEP with no accepted record for three intervals is filed as `fleet:silent`.

**H8.** A PEP whose record has bit 5 set is filed as `dist:held` for as long as its records carry the bit.
A record with bit 5 from a target that has no HOLD setting is filed as `fleet:state-invalid`.

### 15.3 The controller

**F1.** A controller holds no authority private key. It stores sealed envelopes and bodies and cannot make
one. It runs the same verifier a PEP runs (V2 to V11, with the target taken from the envelope) before it
offers anything, and refuses to store what does not verify.

**F2.** A controller keeps, per PEP, the enrolled instance key, the target kind, the stream, the group,
the expected policy hash and `seq`, the last accepted record and the open findings.

**F3.** Per group and release the controller runs this machine.

| State | Leaves when | To |
|---|---|---|
| `offered` | the first `stage-ack` arrives | `staging` |
| `staging` | the group's rule is met | `committing` |
| `staging` | a member refuses, or the stage window (default 120 seconds, 500 milliseconds on the mesh) ends, under rule `all` | `aborted` |
| `committing` | every member that staged reports `committed` | `committed` |
| `committing` | the commit window ends first | `partial` |

A group's rule is `each` or `all`. Under `each` the controller sends `commit` to a member as soon as that
member staged, and a single PEP is a group of one. Under `all` it sends `commit` only when every member
staged and `abort` otherwise, which is the mesh's two phase commit.

**F4.** `partial` and every finding of H6 and H7 stay open until a later record clears them. The fleet
view shows, per PEP, the expected and the reported policy hash and `seq`, so a mixed fleet in mid swap is
bounded by the windows of F3 and visible while it lasts.

**F5.** The controller writes every offer, ack, commit, abort, finding and trust statement to its own
audit log, signed with the controller's instance key.

## 16. Dev builds and escape hatches

**D1.** An escape hatch is any switch that skips a check of this spec or of `spec-secure-hotswap.md`.
The hatches are `PPT_NET_ALLOW_UNVERIFIED=1` in the XDP loader, `--allow-unsigned` on a swap, an attach or
an edge verify, and a verify of evidence or of in-toto envelopes without both keys pinned. In a production
build a hatch is refused with `dist:hatch-refused` and the check runs.

**D2.** Whether a build is a dev build is a fact of where the code runs from and never of its environment
or its configuration, and no build of any tracked tree is a dev build. In Python a dev build is a source
checkout that holds the marker file `.prismpath-dev-build` beside its `pyproject.toml`, one directory
above the `prismpath` package. The marker is outside the package, so no wheel and no sdist can carry it.
It is not tracked, it is in `.gitignore`, and only the command `python tools/dev_build.py on` writes it.
An installed package has no `pyproject.toml` beside it and is never a dev build. In C it is the compile
time macro `PPT_DEV_BUILD`, set only by the `dev` make target. In Rust it is the cargo feature
`dev-hatches`, which is off by default. The `mesh` and `cfs` targets have no hatch in any build.

**D3.** A dev build says so. Every audit event a hatch produces carries `dev_build` true, and a state
record sets bit 6 of `status`. A controller files a production PEP that reports the bit.

**D4.** The release check fails when the marker is tracked, when `.gitignore` does not list it, or when
a wheel built straight from the checkout, the sdist or the export tree holds it. It builds the wheel with
the marker present in the checkout to show that.

## 17. The older signed forms

Today each substrate has its own signed form. They are `ppt-pack/1` (packs), the `prismpath.core-image/1`
attestation (agent and gateway homes, and `ImageSig` in the cFS table), `prismpath.net_dests_pack/1`
(destination tables), `prismpath.grant/1` (grants), `prismpath.cfs-table/1` (`TableSig`) and the mesh's
`PPTM1` message. Each has its own revocation or none.

**L1.** From package version 0.3.0 every writer emits only distribution envelopes. The bodies are the same
bytes as before, so an image, a table or a core image keeps its hash.

**L2.** A PEP that has committed any distribution envelope on a stream refuses the older forms for that
stream from then on with `dist:legacy-refused`. This holds whatever the package version is, so the older
forms are never a way around a floor, an expiry or a revocation.

**L3.** A reader accepts the older forms on a PEP that L2 does not cover through the 0.3 series, and
writes a `legacy_form` audit event each time. From 0.4.0 the older forms are refused everywhere with
`dist:legacy-refused`.

**L4.** The flow manifest (`prismpath-flow-manifest/1`), the qualification envelope, the crypto registry
and root statements are not distributed artifacts in this version and keep their forms.

## 18. Refusal causes

These rows are appended to `prismpath/kernel/causes.py` after 134, the highest code on main when this was
written. If another change lands first the numbers move up together and the names do not change.

| Code | Name | Class | Meaning |
|---|---|---|---|
| 135 | `dist:bad-format` | authority | A sealed envelope, an envelope or a trust body that does not read as its format |
| 136 | `dist:unknown-key` | authority | No signature by a key the trust store holds, or fewer than the threshold |
| 137 | `dist:target-mismatch` | authority | The envelope is not for this PEP's kind, artifact set or stream |
| 138 | `dist:body-mismatch` | authority | A body or a fetched blob whose size or SHA-256 is not the one named |
| 139 | `dist:seq-replay` | authority | A `seq` below the floor, or at it with another envelope |
| 140 | `dist:not-yet-valid` | authority | The PEP's time is more than the skew before `not_before` |
| 141 | `dist:expired` | authority | The PEP's time is at or past `expires` |
| 142 | `dist:revoked` | authority | The envelope id or the policy hash is on the revocation list, or the active release's seq is below a raised floor |
| 143 | `dist:widening-unsigned` | authority | A release that is larger, or cannot be shown not to be, without a covering widening statement |
| 144 | `dist:trust-replay` | authority | A revocation or rotation whose `seq` is not the trust sequence plus one |
| 145 | `dist:rotation-invalid` | authority | A rotation without the new key's signature, or that names a key it may not |
| 146 | `dist:legacy-refused` | authority | An older signed form where a distribution envelope is required |
| 147 | `dist:hatch-refused` | authority | An escape hatch asked for in a production build |
| 148 | `dist:too-large` | envelope | An envelope, a body or a list beyond the PEP's bound |
| 149 | `dist:derived-mismatch` | envelope | A derived artifact that is not what the PEP compiles from the policy |
| 150 | `dist:frame-invalid` | wire | A frame or chunk outside its transfer, or a part that does not assemble |
| 151 | `dist:not-staged` | state | A commit that names no staged release |
| 152 | `dist:incomplete` | state | A release that lacks an artifact its target needs, or whose envelopes disagree |
| 153 | `dist:policy-lapsed` | state | A decision asked of a PEP with no active release |
| 154 | `dist:floor-lost` | state | The floor cannot be read, so the PEP is locked |
| 155 | `fleet:state-invalid` | wire | A state record that does not read, is from no enrolled PEP or is not signed by its instance key |
| 156 | `fleet:state-replay` | wire | A state record whose counter is not above the last accepted |
| 157 | `fleet:policy-mismatch` | wire | A PEP reports a policy hash, `seq` or Facet preamble other than the expected one |
| 158 | `fleet:silent` | wire | No accepted state record from a PEP for three intervals |
| 159 | `dist:held` | state | A PEP deciding under an expired release because its deployment chose HOLD, or an action refused because of that hold |

Reused as they are. `sig:invalid` (2), `sig:revoked-key` (3), `wire:codebook-mismatch` (51),
`document:not-canonical` (103), and the causes of the artifact checks of section 3.

## 19. Implementations and parity

Python holds every part. Rust (`prismpath-hotswap-rs`) holds the sealed envelope, the verifier, the trust
store with revocation and rotation, the PEP machine for the `host` target and the state record. C holds
the sealed envelope, the strict scanner, the verifier, the trust store and the PEP machine for the `mesh`
and `cfs` targets, compiled natively for tests and unchanged for the targets. The controller, the HTTP
binding and the `agent`, `gateway` and `xdp` targets are Python only.

**I1.** One corpus, `prismpath/portable/conformance/distribution.json`, holds the cases of section 20 as
bytes in and results out. It is generated by the Python reference with fixed test keys and replayed by
Python, Rust and C. Each case names the implementations that must pass it and the target kind of the PEP
it runs on. A case marked `C` runs on `mesh` or `cfs`, the only kinds the C core has.

## 20. Conformance cases

Each case names the rules it tests. `P` is Python, `R` Rust, `C` the C core. A case passes when the PEP
reports exactly the cause given, or none, and its state after is the one given.

| # | Case | Expect | Rules | Runs on |
|---|---|---|---|---|
| 1 | A well formed envelope round trips through seal and read with the same envelope id | accepted | E1, E2, E3, S1, S2 | P R C |
| 2 | An envelope with a member missing | `dist:bad-format` | E1, V4 | P R C |
| 3 | An envelope with an extra member | `dist:bad-format` | E1, V4 | P R C |
| 4 | An envelope with members out of canonical order, signed as written | `document:not-canonical` | E2, V4 | P R C |
| 5 | An envelope with an unknown artifact kind, and one with an unknown target kind | `dist:bad-format` | E8 | P R C |
| 6 | `expires` not above `not_before` on a policy kind | `dist:bad-format` | E5 | P R C |
| 7 | An envelope of 2,049 bytes, and a body over the PEP's bound | `dist:bad-format`, `dist:too-large` | E6, V2 | P R C |
| 8 | A sealed container with a wrong magic, a wrong version, a short tail, unsorted entries, a repeated key id, zero entries and five entries | `dist:bad-format` each | S2, V2 | P R C |
| 9 | A signature made over the envelope bytes alone, and one made with another payload type | `sig:invalid` each | S1, S5 | P R C |
| 10 | Signed only by a key the store does not hold | `dist:unknown-key` | S3, S5, V3 | P R C |
| 11 | One good entry by a trusted key and one entry by an unknown key | accepted | S3, S4 | P R C |
| 12 | One good entry by a trusted key and one failing entry by another trusted key | accepted, the failing entry is skipped | S3, S4 | P R C |
| 13 | Signed only by a revoked key, and only by a retired key | `sig:revoked-key` each | S5 | P R C |
| 14 | A tampered envelope byte under a signature that was good, read by the strict scanner | `sig:invalid`, and the scanner is never reached | E9, V1, V3 | C |
| 15 | An envelope whose body travels unchanged, and the body's hash is the certified image hash | accepted | E4 | P |
| 16 | A PEP whose trust store file is unreadable | `dist:unknown-key`, and it allows nothing | K1, X3 | P R |
| 17 | A PEP started with an instance key that is a trusted authority key | refused at start | K2 | P R |
| 18 | A host PEP started with an authority private key in its home | refused at start | K2 | P |
| 19 | `commit`, `abort`, `offer` and a state record each fail to change the trust store | unchanged | K3 | P |
| 20 | `seq` below the floor | `dist:seq-replay` | Q1, Q2, V8 | P R C |
| 21 | `seq` at the floor with the committed envelope id | accepted, nothing changes | Q3 | P R C |
| 22 | `seq` at the floor with another envelope id | `dist:seq-replay` | Q3 | P R C |
| 23 | After a rollback and after an abort the floor is what it was | unchanged | Q4, RB1, A1 | P R |
| 24 | A floor that cannot be read | locked, `dist:floor-lost`, nothing admitted | Q5, X3 | P R C |
| 25 | The cFS app with the store lost, under LOCK and under MINIMUM | LOCK admits nothing, MINIMUM admits from the minimum up | Q5 | C |
| 26 | The clock is set back past an expiry after an envelope with a later `not_before` was verified | `dist:expired` | T1, V13 | P R C |
| 27 | A PEP with no clock restarts and still refuses an envelope that expired before its saved time | `dist:expired` | T2 | C |
| 28 | `not_before` 301 seconds ahead, and 299 seconds ahead | `dist:not-yet-valid`, accepted | T3, V6 | P R C |
| 29 | The PEP's time equals `expires`, and is one second before | `dist:expired`, accepted | T4, V6 | P R C |
| 30 | A forged `commit` for a staged release, and a forged `abort` | the release goes active, the release is dropped, and nothing unsigned ever runs | B1 | P |
| 31 | A `trust.revocation` staged without a commit | applied, event `trust-applied` | B2, R3 | P R C |
| 32 | A host PEP stages and commits with the controller never opening a connection | committed | B3 | P |
| 33 | A blob whose bytes do not hash to the name asked for, and a sealed envelope whose id is another | `dist:body-mismatch` | B4, V9 | P |
| 34 | An offer that names an envelope the controller does not hold | a failed fetch, nothing changes | B5 | P |
| 35 | Chunks out of order and repeated | staged | B6 | P C |
| 36 | A chunk past the offered length, a chunk with no offer, and an assembled part with a wrong hash | `dist:frame-invalid` | B6 | P C |
| 37 | A transfer left incomplete for 5 seconds, then sent again whole | dropped silently, then staged | B7 | P C |
| 38 | A commit with a delay of 120 milliseconds | active at the PEP's time plus the delay, not before | B8 | C |
| 39 | An envelope that fails two checks reports only the earlier one | the earlier cause | V1 | P R C |
| 40 | An envelope for another target kind, for an artifact the kind does not use, and for another stream | `dist:target-mismatch` each | V5 | P R C |
| 41 | An envelope whose id is revoked, and one whose policy hash is revoked | `dist:revoked` each | V7, R2 | P R C |
| 42 | A body one byte short, and a body with one byte changed | `dist:body-mismatch` each | V9 | P R C |
| 43 | A second envelope at the staged `seq` with another policy hash | `dist:incomplete` | E7, V10 | P R |
| 44 | A `policy.ppt` whose `meta` counts differ from the image, one over a qualification cap, and one with a wrong WCET | `manifest:count-mismatch`, `image:caps-exceeded`, `manifest:wcet-mismatch` | V11 | P R |
| 45 | A `net.edge` that is not the table compiled from the staged policy and destinations, and a `sandbox.profile` that is not the compiled profile | `dist:derived-mismatch` each | V11 | P |
| 46 | A good envelope is staged, acked and in the audit log, and a refused one is acked and in the audit log | staged, refused | G1 | P R C |
| 47 | A higher `seq` replaces a staged release, and a lower one is refused | staged, `dist:seq-replay` | G2 | P R C |
| 48 | A commit that names nothing staged | `dist:not-staged` | C1 | P R C |
| 49 | An `agent` PEP with `policy.core` staged and no `egress.hosts` is committed | `dist:incomplete`, the old release stays active | C2 | P |
| 50 | A staged release expires, and one is revoked, before its commit | `dist:expired`, `dist:revoked`, the staged release is dropped | C3 | P R C |
| 51 | The process is killed at each step of a commit and restarted | the old release before the flip, the new one after, never a mix | C4 | P R |
| 52 | A commit is followed by a state record with event `committed` and the new hash | as stated | C5, H4 | P R C |
| 53 | An abort for the staged release, and an abort for another | dropped with event `aborted`, unchanged | A1 | P R C |
| 54 | A rollback to a kept release that has expired, and to one that is revoked | refused with `dist:expired`, `dist:revoked` | RB2 | P |
| 55 | A rollback to a kept release that allows more, without and with a covering statement | `dist:widening-unsigned`, rolled back | RB3 | P |
| 56 | An `agent` PEP is offered a policy that allows one more reading with `widens` false and no statement | `dist:widening-unsigned` | W1, W3, W6, V12 | P |
| 57 | An `agent` PEP is offered a policy that allows less | committed on its ordinary signature | W1 | P |
| 58 | An `agent` PEP is offered a policy that moves a reading from refuse to escalate | `dist:widening-unsigned` | W1 | P |
| 59 | An `agent` PEP is offered a host list with one more host, and a `gateway` PEP a changed route table | `dist:widening-unsigned` each | W1 | P |
| 60 | A `mesh` PEP is offered `widens` false with `replaces` equal to its active hash | committed | W2 | P C |
| 61 | A `mesh` PEP is offered `widens` false with `replaces` another hash, and `widens` true, each without a statement | `dist:widening-unsigned` each | W2, W3 | P C |
| 62 | A widening statement whose `from` holds the active hash, one whose `from` is empty, and one whose `from` holds only another hash | committed, committed, `dist:widening-unsigned` | W4, W5 | P R C |
| 63 | A first install with no statement, and with one | `dist:widening-unsigned`, committed | W2, W3 | P R C |
| 64 | A statement is present and a deciding PEP computes larger while `widens` is false | `dist:widening-unsigned` | W6 | P |
| 65 | A controller is given a release for `mesh` that it computes as larger with `widens` false | it refuses to offer it | W7 | P |
| 66 | A revocation with `seq` one above the trust sequence, the same one again, an older one, and one that skips a number | applied, unchanged, `dist:trust-replay`, `dist:trust-replay` | R1 | P R C |
| 67 | After a key is revoked, a pack signed by it | `sig:revoked-key` | R2 | P R C |
| 68 | A revocation raises a stream's floor to 9, then a release at 8 | `dist:seq-replay` | R4, Q4 | P R C |
| 69 | A revocation lists the active envelope, the active policy hash, the only signing key, and a floor above the active `seq` | `no-policy`, event `lapsed`, `dist:revoked`, each time | R5 | P R C |
| 70 | A later revocation drops a key id an earlier one listed | the key is still refused | R6 | P R C |
| 71 | A revocation list with 65 entries | `dist:too-large` | R7 | P R C |
| 72 | A rotation signed by the old and the new key, then a pack under the new key | applied, committed | O1, O2, O3 | P R C |
| 73 | After a rotation that retires the old key, a pack signed by the old key, while the release active under it keeps deciding | `sig:revoked-key`, still active | O3, S5 | P R C |
| 74 | A rotation signed only by an unknown key, and one without the new key's signature | `dist:unknown-key`, `dist:rotation-invalid` | O2 | P R C |
| 75 | A rotation whose `retire` is unknown, whose `add` is the PEP's instance key, and whose `add` is revoked | `dist:rotation-invalid` each | O3, O4 | P R |
| 76 | A rotation and a revocation with the same `seq` | the second is `dist:trust-replay` | O1 | P R C |
| 77 | The active release passes `expires` with no message at all | `no-policy`, event `lapsed`, `dist:expired`, and every decision refused with `dist:policy-lapsed` | X1, X2, X3 | P R C |
| 78 | A cut off PEP holds a revoked release it never heard was revoked | it decides until `expires` and not after | X2 | P |
| 79 | A trust envelope with `expires` other than 0, and a revocation read years after it was made | `dist:bad-format`, applied | X4, E5 | P R C |
| 80 | A renewal with the same bodies and a later `expires` | committed with no body fetched | X5 | P |
| 81 | A grant envelope that is valid, expired, for another policy, out of scope, tampered and revoked by id | `valid`, `expired`, then `invalid` four times | GR1, GR2, GR3 | P |
| 82 | A PEP with an empty trust store is sent a rotation that adds a key | `dist:unknown-key`, the store stays empty | P1 | P R C |
| 83 | A host PEP provisioned with an anchor whose fingerprint the operator has not confirmed | it follows no stream | P2 | P |
| 84 | Provisioning a locked PEP | unlocked, event `provisioned` in the audit log | P3, Q5 | P R |
| 85 | A state record round trips, and one with a byte changed | accepted, `fleet:state-invalid` | H1, H2, H6 | P R C |
| 86 | A state record signed by an authority key, and one from a PEP that is not enrolled | `fleet:state-invalid` each | H2, H6, F2 | P |
| 87 | The same record sent twice | the second is `fleet:state-replay` | H3, H6 | P |
| 88 | A PEP on the expected policy with a Facet body | decoded, no finding | H5, H6 | P |
| 89 | A PEP on another policy, with a body and with none | `fleet:policy-mismatch` each, from the hash and before any decode | H6 | P |
| 90 | A record with the expected header hash and a body whose preamble is another policy's | `fleet:policy-mismatch` | H6 | P |
| 91 | A record with the expected hashes and a body cut inside a code | `wire:codebook-mismatch` | H6 | P |
| 92 | A PEP that sends nothing for three intervals | `fleet:silent` | H4, H7 | P |
| 93 | A controller is handed an envelope with a bad signature to store | it refuses and offers nothing | F1 | P |
| 94 | A group of three under `all` where one member refuses | `aborted`, none commits | F3 | P |
| 95 | A group of three under `each` where one refuses a downgrade and one a bad signature | one `committed`, two findings, three audit trails | F3, F4, F5 | P |
| 96 | A commit window ends with one member silent | `partial`, open until that member reports | F3, F4 | P |
| 97 | Each hatch of D1 in a production build | `dist:hatch-refused` and the check runs | D1, D2 | P R C |
| 98 | Each hatch in a dev build | it works, the audit event says `dev_build`, and the state record carries the bit | D2, D3 | P |
| 99 | With the marker written in the checkout, a wheel built straight from it, the sdist and the export tree, and `git ls-files` | none holds the marker, and it is ignored and not tracked | D2, D4 | P |
| 100 | A writer at 0.3.0 asked for each older form | it writes a distribution envelope | L1 | P |
| 101 | A PEP that committed an envelope is given a valid `ppt-pack/1` pack with a higher version | `dist:legacy-refused` | L2 | P R |
| 102 | A PEP with no envelope yet is given each older form | accepted with a `legacy_form` audit event | L3 | P |
| 103 | A flow manifest, a qualification envelope and a root statement | verified as before | L4 | P |
| 104 | The corpus replays with the same results in all three implementations | equal | I1 | P R C |
| 105 | One policy offered to a `host` PEP, an `agent` PEP and a simulated `cfs` table | one policy hash in all three state records | E7, H1, F4 | P C |
| 106 | A `mesh` and a `cfs` PEP with the setting left alone see their release expire | `no-policy`, event `lapsed`, `dist:expired` | X6, X1 | P C |
| 107 | The same with HOLD set | still deciding under the same release, event `held` with `dist:held`, bit 5 in every record and the hold mark on every receipt until the hold ends | X6, X7 | P C |
| 108 | A held PEP is sent a revocation of its active release, and one that raises the floor past it | `no-policy`, event `lapsed`, `dist:revoked`, each time | X8, R5 | P C |
| 109 | A held PEP is sent a release below the floor, an expired one, a larger one without a statement, and its floor is then lost | `dist:seq-replay`, `dist:expired`, `dist:widening-unsigned`, then locked with `dist:floor-lost` | X8 | P C |
| 110 | A held PEP is told to roll back, then is sent a release that passes every rule | `dist:held` and nothing changes, then `committed` with bit 5 clear | X9 | P C |
| 111 | A `host`, an `agent`, a `gateway` and an `xdp` PEP are each configured with HOLD | each refuses to start | X6, X10 | P R |
| 112 | A held and a not held PEP are sent every message type in turn | the setting is what it was built with | X10 | P C |
| 113 | A controller receives records with bit 5 from a `cfs` PEP, then a record without it, and a record with bit 5 from a `host` PEP | `dist:held` open then cleared, and `fleet:state-invalid` | H8 | P |
| 114 | Two envelopes at one `seq` and policy hash with different `release`, staged together | `dist:incomplete` | E7, E10, V10 | P R C |
| 115 | The signer's release id for a release of three artifacts, and for the same three with one body changed | the first is the SHA-256 E10 gives, and the second differs | E10 | P R |
| 116 | A sealed envelope is written as a DSSE JSON envelope and read back, and a stock DSSE check of the JSON form | the same sealed bytes, and the signature verifies | S7, S1 | P |
| 117 | Entries are added to, removed from and reordered in the signature block of a signed and of an unsigned envelope | the envelope id is unchanged, the signed one needs its counting entry, and the unsigned one stays refused | S6 | P R C |
| 118 | A key held in a role this version does not know signs a release | `dist:unknown-key`, and the key is still in the store | K4, S3 | P R C |
| 119 | A PEP with no clock that lost a month without power is sent a current envelope, and a PEP with a clock is sent the same one a month early | accepted and its time moves to `not_before`, `dist:not-yet-valid` | T2, T3, V13 | P C |
| 120 | A body longer than `body_size`, a sealed envelope of 2,441 bytes, an `offers` answer of 65 kilobytes, and a body offered for an envelope that fails its signature | no more than the bound is read, and the body is never read in the last | B9 | P C |
| 121 | A release sent through a relay that drops, repeats and corrupts frames, then passes them | nothing is staged until the frames are whole, then staged, and the relay holds no key | B10 | P C |
| 122 | On an ordered link, chunks in order, and a chunk out of order | staged with the envelope never held whole, `dist:frame-invalid` | B11 | C |
| 123 | A rotation with `seq` two above the trust sequence, then the one it skipped, then the first again | `dist:trust-replay`, applied, applied | O1, R1 | P R C |
| 124 | A record with the controller's current epoch id, the one before, and one three epochs old, and a PEP sent a lower epoch id than it holds | accepted, accepted, `fleet:state-replay`, and the PEP keeps the higher | H9, H6 | P |
| 125 | A record with a type 1 extension whose `eat_nonce` matches, one with an unknown type, and one whose extension was changed after signing | read, skipped, `fleet:state-invalid` | H10 | P |
| 126 | A `host` release whose `policy.ppt` declares `packing`, with no `policy.spiral`, with a wrong one and with the right one | `spiral:sidecar-missing`, `spiral:sidecar-hash-mismatch`, committed | V11, C2 | P R |
