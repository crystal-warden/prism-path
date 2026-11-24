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
| Never widen silently | W1 to W7, IS12, H13 |
| Hosts pull over HTTP. Push only where the medium is a broadcast | B1 to B8 |
| One signed envelope for every distributed artifact | E1 to E9, L1 to L4 |
| Escape hatches only in dev builds | D1 to D4 |
| The cFS lost floor response is a mission choice and LOCK is the default | Q5 |
| Where refusing is not the safe answer, the engineer who installs PrismPath signs what a target always allows, what it falls back to and what no release may allow, on any kind. Refusal stays the default | IS1 to IS12, AF1 to AF10, FB1 to FB9, CL1 to CL4, OP1 to OP3, RC1 to RC4, H11 to H13, P4 |

Out of scope. A PEP that has been compromised can lie in its state record, because the record says what
the PEP claims. Hardware attestation would say more and is not designed here. A signature threshold above
one is not in this version for the authority, though the format carries up to four signatures (S2) so it
can be added without a new format. The install role has a threshold of its own (IS2).

Stated limits. An authority key in the wrong hands can sign a `seq` so high that the stream cannot
advance. TUF calls this a fast forward attack (TUF section 1.5.2) and recovers by having root rotate the
key and the client forget the versions. This spec keeps the rule that no message lowers a floor, so the
recovery is the provisioning step (P3) after the key is rotated and revoked. A controller in the wrong
hands can withhold releases and revocations and can choose among unrevoked releases at or above a PEP's
floor. It can do nothing else, and the longest it can freeze a PEP is the time left on that PEP's
envelope (X2). An install statement (section 21) never expires and no authority key can take it back. So nothing
bounds how long a controller can withhold one, where X2 bounds a withheld release. A controller can keep
a PEP on a wide action floor by never passing the narrower one, and can offer a superseded install set
the engineer signed, as long as its `seq` is above the PEP's own. It cannot make one, cannot offer one
at or below the `seq` the PEP holds (IS6), and cannot hide which sets a PEP holds from anyone who reads
its state records (H10). Install keys in the wrong hands are a live authority where the install
threshold is 2 or more, and section 21.7 states what they can and cannot do.

A note on the word envelope. The repository already uses it twice. `spec-secure-hotswap.md` section 3.2
has the qualification envelope, the caps and fields a pack must stay inside, named by `envelope_id`.
`spec-intoto-receipts.md` has the DSSE envelope. The object defined here is always written **distribution
envelope**, and its format tag is `prismpath.dist/1`.

## 2. Terms

| Term | Meaning |
|---|---|
| Authority key | An Ed25519 key that says which policy may run. Its key id is the SHA-256 of its 32 raw public bytes, in lower case hex. |
| Instance key | An Ed25519 key one PEP makes for itself. It signs what that PEP reports and never authorizes anything. |
| Trust store | What a PEP holds about authority keys. The trusted keys, the retired keys, the revocation list, the trust sequence and the threshold. Install and operator keys are never in it (K3). |
| Stream | A named line of policy that one group of PEPs follows, for example `agent/default` or `mesh/demo`. A name is 1 to 64 characters of `a-z 0-9 . _ / -`. The reserved stream `@trust` carries revocations and rotations. |
| Policy hash | The SHA-256 of the policy document every artifact of a release derives from. It is the `prismpath.core/1` image bytes when the policy has one, and the `.ppt` image bytes otherwise. |
| Distribution envelope | The canon/2 document of section 4 that names one artifact body by hash. |
| Envelope id | The SHA-256 of the envelope's canon/2 bytes, in lower case hex. Signatures are not part of it. |
| Sealed envelope | The envelope bytes with their signature block (section 4.3). |
| Release | Every sealed envelope that shares one stream, one `seq` and one policy hash. A PEP commits a release whole. |
| Floor | The highest `seq` a PEP has committed on a stream, with the envelope ids committed at it. |
| Install key | An Ed25519 key of the engineer who installs PrismPath on a resource. It signs the bounds the resource runs within and nothing else. |
| Operator key | An Ed25519 key the engineer enrolls to answer the action floor's escalations, one at a time (OP1). It signs nothing else. |
| Install statement | A sealed envelope, signed by install keys, that carries one artifact of an action floor, of a fallback policy or of a ceiling, or an install trust statement (section 21). |
| Install set | Every install statement that shares one install kind, one stream, one `seq` and one release id. A PEP applies it whole. |
| Action floor | The install set whose allows hold in every state of a PEP. It is never called the floor. |
| Fallback policy | The install set a PEP decides under when no release is active. It is not the physical safe state of a machine, which may hold with a release active. |
| Ceiling | The install set that says what no release may allow. It carries the reading domain. |

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
| `agent` | One agent home. The hook, the decider, the sandbox profile, the egress proxy and the MCP proxy all read it (`prismpath/agent/commands.py`, `load_checked`) | `policy.core`, `egress.hosts`, and `agent.zones` when the owner declares zones | Yes |
| `gateway` | One gateway home (`prismpath/gateway/proxy.py`) | `policy.core`, `gateway.routes` | Yes for the policy. A changed route table is always a widening |
| `xdp` | The host preloader in front of the XDP loader (`prismpath-ebpf/net_swap.py`) | `policy.core`, `net.dests`, `net.edge` | Yes |
| `mesh` | One ESP32 node (`prismpath-hw/mesh/main/ppt_mesh.c`) | `policy.ppt` | No |
| `cfs` | The cFS app (`integrations/cfs/prismpath_app`) | `cfs.table` | No |

The hook, the sandbox, the egress proxy and the MCP proxy are one target because they read one home. One
home holds one release, so they cannot hold different versions of one policy.

| Artifact | Body | `meta` members | Check beyond the hash (V11) |
|---|---|---|---|
| `policy.core` | A `prismpath.core/1` image in canon/2 bytes with no trailing line feed | none | The image loads (`prismpath.agent.policy.Policy`), every value a rule names is inside its field's reading domain (9.4, `policy:out-of-domain`), and its SHA-256 is `policy_sha256` |
| `policy.ppt` | A `.ppt` image | `fields`, `counts`, `wcet_cycles`, `qualification`, and when present `packing`, `flow_sha256`, `overlay_of`. They mean what the same members of a `ppt-pack/1` manifest mean, and `qualification` is its `envelope_id` | `validate_image`, the counts, the recomputed WCET and the qualification envelope gate, with their existing causes. A `mesh` target runs its own table parser and ignores `meta` |
| `policy.spiral` | The spiral sidecar bytes (`<name>.ppt.spiral`) | none | Its SHA-256 is the `sidecar_sha256` in the staged `policy.ppt` envelope's `meta.packing`. A missing one is `spiral:sidecar-missing` at commit and a wrong one `spiral:sidecar-hash-mismatch` |
| `sandbox.profile` | A sandbox profile in canon/2 bytes (`Profile.canonical`) | `compiler` | The PEP compiles the profile from the staged `policy.core` and the bytes must be equal. Optional for `agent`, and checked when present |
| `egress.hosts` | A canon/2 array of lower case host names, sorted, without repeats. It may be empty | none | Each name is one the egress proxy can read |
| `agent.zones` | A canon/2 object with `encoding`, `format` `prismpath.dist-zones/1` and `protected`, the owner's protected names, sorted, without repeats, at most 10,000 names of at most 512 characters | none | Each name is one the zone point can read. The body names no path. Where the project and its index are is the home's own setting, and the index is one of the home's control paths. A release with no `agent.zones` declares no zone, and the release id (E10) signs that absence |
| `gateway.routes` | A route table document in canon/2 bytes | none | `Routes.from_doc` accepts it |
| `net.dests` | A `prismpath.net_dests/1` destination table in canonical form | none | The table is one the edge can use |
| `net.edge` | The edge `.ppt` image | `flow_sha256`, `names_sha256`, `qualification` | The table recompiled from the staged `policy.core` and `net.dests` is byte for byte the body |
| `cfs.table` | The `PP_PolicyTable_t` bytes before `ImageSig` | none | The kernel check, and the SHA-256 of the core image inside the table is `policy_sha256` |
| `grant` | A grant document (section 13) | none | Section 13 |
| `trust.widening` | A widening statement (section 9.4) | none | Section 9.4 |
| `trust.revocation` | A revocation list (section 10) | none | Section 10 |
| `trust.rotation` | A rotation statement (section 11) | none | Section 11 |
| `install.floor` | One artifact of an action floor (section 21), in the form this table gives the artifact that `as` names | `as`, the members this table gives the artifact that `as` names, `layout` and `command` on a table (AF9, AF10), and `rate` when the engineer sets one (AF8) | The check this table gives the artifact that `as` names, and section 21 |
| `install.fallback` | One artifact of a fallback policy (section 21), in the same form | `as`, and the members this table gives the artifact that `as` names | The same |
| `install.ceiling` | One artifact of a ceiling, or a policy list (CL1) | `as`, and the members this table gives the artifact that `as` names | CL1 |
| `install.trust` | An install trust statement (IS11) | none | IS11 |
| `operator.answer` | An operator's answer to one escalation (OP2) | none | OP2 |

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
| `expires` | integer, Unix seconds | The envelope stops counting at this second. 0 only on a trust kind or an install kind (X4) |
| `format` | `prismpath.dist/1` | |
| `meta` | object of the members section 3 lists for the artifact, strings and integers and one level of object | Facts about the body that are signed with it |
| `not_before` | integer, Unix seconds | The envelope does not count before this second |
| `policy_sha256` | 64 lower case hex digits | The policy hash. On a `@trust` envelope it is 64 zeros |
| `release` | 64 lower case hex digits | The release id (E10). On a `@trust` envelope it is 64 zeros |
| `replaces` | 64 lower case hex digits, or the empty string | The policy hash the signer compared against when setting `widens` |
| `seq` | integer, 1 to 2^53 - 1 | The sequence number on the stream |
| `stream` | a stream name | |
| `targets` | array of target kinds, sorted, at least one, no repeats | The PEP kinds this envelope is valid for. On a `@trust` envelope the writer names every kind and a reader does not check it (V5) |
| `widens` | `true` or `false` | The signer's statement that the release allows something `replaces` did not |

**E2.** The envelope bytes are the canon/2 bytes of that object (`prismpath.kernel.canon2.dumps`). A reader
that parses bytes which are canon/2 but not canonical refuses with `document:not-canonical` and never
writes them again in another spelling.

**E3.** The envelope id is the SHA-256 of the envelope bytes.

**E4.** An envelope names exactly one body. The body travels beside the envelope and is never changed to
carry it, so every certified image hash stays what it was.

**E5.** `expires` is greater than `not_before`, except on a trust kind or an install kind, where it is 0.

**E6.** An envelope is at most 2,048 bytes. A target kind has two bounds for a body, one for the body of an
artifact it uses and one for the body of a trust kind, and a PEP refuses a larger body with
`dist:too-large`. For `mesh` the artifact bound is 640 bytes (`TBL_MAX`), and for `cfs` it is the table
size. The trust bound of every kind is 16,384 bytes, which holds a revocation list of the full size R7
allows, so the smallest PEP of this version can take any list the authority may write. A PEP may set a
lower artifact bound of its own and never a lower trust bound. An `install.trust` and the list of a
ceiling (CL1) are held to the trust bound as well.

**E7.** Every envelope of one release carries the same `stream`, `seq`, `policy_sha256`, `release`,
`replaces` and `widens`.

**E8.** A reader ignores nothing. An unknown artifact kind or target kind is `dist:bad-format`.

**E9.** A target kind whose own check does not read `meta`, which is `mesh` and `cfs`, reads the envelope
with a strict scanner. The scanner accepts the members in canonical order and skips the value of `meta`
after checking three things only. It is an object, it nests at most three levels, and it ends inside the
envelope. The `meta` object counts as level one, and each object or array inside it one level more. Anything else is `dist:bad-format`. The member list of `meta` (E1) and the forms of E11 are not
checked on those kinds, because nothing there uses the members. Every other reader checks them, and so
does the controller for every envelope it stores, whatever its targets (F1). The reference
implementation reads an envelope for a `mesh` or `cfs` PEP the same way the scanner does, so the corpus
gives one answer per kind. The scanner runs only on bytes whose signature has already been checked (V3
comes before V4).

**E10.** The release id is the SHA-256 of the canon/2 bytes of the array of `[artifact, body_sha256]`
pairs of every artifact in the release other than a trust kind, sorted. A `trust.widening` envelope is
bound to its release by carrying the same `release` (E7) and is not part of the id, so the owner can sign
a widening statement for a release that is already sealed without signing the release again. The signer computes it over the whole release, so two
envelopes belong to one release only when the authority signed them as one set. A PEP verifies each envelope without the
other bodies. It requires the same `release` on every envelope it stages together (E7) and reports it
(H1), and that is what stops a mix of artifacts that were never released together (TUF's mix and match,
section 1.5.2). At commit it computes the id again over the artifacts it staged, so a release commits
whole or not at all (C2).

**E11.** Each `meta` member has a fixed form, and a reader that uses `meta` (every kind but those of E9)
checks the form when it reads the envelope (V4), before any check uses the member. Another form is `dist:bad-format`.

| Artifact | Member | Form |
|---|---|---|
| `policy.ppt` | `fields` | an object whose values are strings |
| `policy.ppt` | `counts` | an object with exactly `atoms`, `nodes`, `edges`, `prog_words`, `max_steps`, `max_stack`, each an integer from 0 to 65535 |
| `policy.ppt` | `wcet_cycles` | an integer, 0 or more |
| `policy.ppt`, `net.edge` | `qualification` | a string of 1 to 128 characters |
| `policy.ppt` | `packing` | an object with exactly `profile`, a string of 1 to 32 characters, and `sidecar_sha256`, 64 lower case hex digits. A profile other than `spiral` is then `packing:unknown-profile` at V11 |
| `policy.ppt`, `net.edge` | `flow_sha256` | 64 lower case hex digits |
| `policy.ppt` | `overlay_of` | a string of 1 to 128 characters |
| `net.edge` | `names_sha256` | 64 lower case hex digits |
| `sandbox.profile` | `compiler` | an integer, 1 or more |
| `install.floor`, `install.fallback`, `install.ceiling` | `as` | an artifact kind of section 3 other than a trust kind, a grant or an install kind, or `policy.list` on a ceiling (CL1) |
| `install.floor` | `rate` | an object with exactly `allows`, an integer from 1 to 65535, and `window`, an integer from 1 to 86400 |
| `install.floor` | `command` | an integer from 0 to 255, the register of the command field |
| `install.floor` | `layout` | 64 lower case hex digits, the SHA-256 of the layout document (AF10) |
| `install.floor`, `install.fallback`, `install.ceiling` | the members of the artifact that `as` names | the forms this table gives them for that artifact |

A check that reads a signed member never has to guess its type. The same holds for the older pack gate,
which refuses a manifest whose `fields` or `counts` is not an object with `manifest:bad-format`.

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

**S3.** An entry counts when its key id names a key the PEP holds in the role the artifact needs (K4),
in the trust store or in the install record, that key is neither revoked nor retired, and the signature
verifies. A key id is a hint for finding
the key and decides nothing by itself. An entry that does not count is skipped, as DSSE skips it.

**S4.** An envelope is signed when the number of counting entries is at least the trust store's
threshold. The threshold is 1 in this version for the role `authority`. The role `install` has its own
(IS2), and one operator signature is enough for an answer (OP1).

**S5.** An envelope that is not signed is refused with one cause, the first of these that applies.
`sig:revoked-key` when an entry verifies under a revoked or retired key. `sig:invalid` when an entry
names a key the store holds and does not verify. `dist:unknown-key` otherwise.

**S6.** The signature block is not signed. Adding, removing or reordering entries never changes the
envelope id and never makes an unsigned envelope signed.

## 5. Keys and the trust store

**K1.** A PEP holds a trust store with the trusted authority keys, the retired key ids, the current
revocation list, the trust sequence and the threshold. It is durable, and a PEP that cannot read it
refuses every envelope with `dist:unknown-key` and decides nothing beyond what section 21 installs (X3,
AF1, FB1). Its durable form is a canon/2
document with format `prismpath.dist-trust-store/1`.

**K2.** A PEP holds its own instance key. An instance key that is also a trusted authority key is refused
at start, as `root_statement.check_separation` refuses it today. A PEP under distribution holds no
authority private key.

**K3.** The trust store changes only by first key provisioning (section 14), by a `trust.rotation` and by
a `trust.revocation`. No other message changes it. The install keys and the operator keys are never in
it. They are held in the install record (IS10) and change only by provisioning and by an `install.trust`
(IS11, IS13).

**K4.** Every key a PEP holds has a role. This version has three roles. The install kinds need
`install` (IS2), `operator.answer` needs `operator` (OP1), and every other artifact kind needs
`authority`. The trust store holds the authority keys. The install keys and the operator keys are held
apart from it in the install record, with their own bounds (IS10, IS11, OP1). The roles are strictly
apart. No key is held in two roles, and none is the PEP's instance key. The PEP checks every two roles
against each other and each against the instance key at the anchor (P2, P4) and at every statement that
adds a key, which is a `trust.rotation` (O4) and an `install.trust` (IS11). A key retired in one role is
never added again in any role while the PEP remembers its id (K5, IS10). A PEP forgets the oldest ids
past those bounds and then cannot tell, so the sealing tool and the controller, which keep every retired
id, refuse to seal or store a statement that adds one. A key in a role this version does not know is kept and never counts.
The role an artifact needs is a column of the kind table. Because the artifact kind is inside the
envelope and V3 runs before the envelope is read, a version with more than one role works in two steps.
V3 finds every role under which the envelope is signed (S4) and fails only when there is none. V5 then
requires the role its artifact needs to be one of them, with `dist:unknown-key` otherwise. The scanner
still reads only bytes that a held key signed (E9).

**K5.** A trust store holds at most 8 keys and remembers at most 16 retired key ids. A rotation that would
make a ninth key is refused with `dist:too-large`. When a seventeenth key is retired the oldest retired id
is forgotten, and a signature by it then reads as one by an unknown key, which is refused all the same.
The bounds are the same in every implementation, so the smallest PEP and the reference agree. The
install and operator keys are not in the trust store and have their own bounds (IS10, IS11, OP1).

## 6. Sequence numbers and the floor

**Q1.** A PEP keeps one floor per stream. It is the highest `seq` it has committed and the envelope ids it
committed at that `seq`. The floor is durable before the release is active (C4).

**Q2.** An envelope whose `seq` is below the floor is refused with `dist:seq-replay`.

**Q3.** An envelope whose `seq` equals the floor is accepted only when its envelope id is one committed at
the floor, which implies the committed release id. It changes nothing and the PEP reports its state. Any other envelope at the floor is
`dist:seq-replay`.

**Q4.** Nothing lowers a floor. A `trust.revocation` may raise one (R4).

**Q5.** A PEP whose floor cannot be read is locked. It admits no release, decides nothing beyond what
section 21 installs (AF1, FB1) and reports
`dist:floor-lost`. Only a provisioning step clears it. On cFS the mission chooses the response with
`PRISMPATH_APP_PLATFORM_LOST_FLOOR`, and `PP_LOST_FLOOR_LOCK` stays the default.

## 7. Clocks

The trust assumption is stated once. A PEP trusts its own clock to be within 300 seconds of true time
(`SKEW`). The transport and the controller are not time sources.

**T1.** A PEP keeps a durable time floor. It is the highest `not_before` of any envelope whose signature it
has verified, other than an install kind (IS5) and an `operator.answer` (OP2). The PEP's time is the larger of its clock and the time floor, so a clock set back cannot
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
| `install` | controller | a sealed install statement and its body | Applied when its install set is whole and verified, with no commit (IS4) |

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
transfer with `dist:frame-invalid`. Chunks of one part may arrive in any order and may repeat. The sealed envelope comes first. A body
chunk that arrives before the sealed envelope is whole and has passed V8 is not read (B9), and the
sender sends it again.

**B7.** A PEP holds at most one transfer per part at a time and a transfer that is not complete after 5
seconds is dropped silently, so lost frames cost a retry and never a partial stage.

**B9.** A PEP never reads more than it was promised. It reads at most 2,440 bytes for a sealed envelope
(the largest S2 allows) and at most the signed `body_size` for a body, and it reads the body only after
the envelope verified through V8. An `offers` answer over 64 kilobytes is dropped. This is the bound
against endless data (TUF section 1.5.2).

**B10.** A relay passes frames between a medium and a PEP that has no radio of its own, such as an
ESP32-C6 in front of a board on a serial line. A relay holds no key, verifies nothing, and is not a PEP.
It is part of the untrusted transport, so what it drops or changes is caught by the PEP behind it. The
frame binding runs unchanged on the link behind a relay, with that link's own frame limit. A state
record travels in one frame, so a link's limit is at least 216 bytes, and 246 bytes for a PEP that holds
an install statement (H10).

**B11.** A link may be declared ordered. On an ordered link the sender sends the chunks of a part in
offset order without repeats, and the PEP drops a transfer whose chunk is out of order with
`dist:frame-invalid`. This lets a PEP that cannot hold a sealed envelope check it as it arrives.

**B8.** A `commit` with a delay makes the release active at the PEP's own monotonic time plus the delay, so
a group flips together without a shared clock, as the mesh does today with `FLIP_DELAY`.

## 9. The PEP state machine

A PEP runs one machine per stream it follows. The states are these.

| State | Meaning |
|---|---|
| `no-policy` | Nothing is active. Every decision is a refusal with `dist:policy-lapsed` or the PEP's own fail closed cause, but for a request an action floor allows (AF1) |
| `active` | One release is active |
| `staged` | A release is verified and held beside whatever is active. It is a sub state of the two above |
| `locked` | The floor is lost (Q5) |
| `fallback` | No release is active and the installed fallback policy decides (FB1). It is a sub state of `no-policy` and of `locked` |

### 9.1 Verify

**V1.** A PEP verifies every sealed envelope in the order V2 to V12. The first rule that fails is the only
cause reported and nothing is staged.

| Rule | Check | Cause when it fails |
|---|---|---|
| V2 | The sealed container reads (S2), and the body is no longer than the larger of the PEP's two bounds (E6) | `dist:bad-format`, `dist:too-large` |
| V3 | The signatures (S3 to S5) | `dist:unknown-key`, `sig:invalid`, `sig:revoked-key` |
| V4 | The envelope reads (E1, E2, E5, E8, E11) | `document:not-canonical`, `dist:bad-format` |
| V5 | `targets` holds this PEP's kind, `artifact` is one this kind uses or a trust kind, and `stream` is this PEP's stream or `@trust` for a trust kind. A `trust.revocation` or a `trust.rotation` is for every PEP whatever `targets` says, because one trust sequence must count the same for all of them (R1). An install kind on this PEP's stream is one it uses (IS5). An `operator.answer` on this PEP's stream is one it uses when its kind has escalation, which is `agent`, `gateway` and `cfs` (AF2, OP1), and on `host`, `mesh` and `xdp` it is `dist:target-mismatch`. Then the signed `body_size` is within the bound for that artifact (E6), which is checked before any body is read (B9) | `dist:target-mismatch`, then `dist:too-large` |
| V6 | Time (T3, T4, and X4 for a trust kind) | `dist:not-yet-valid`, `dist:expired` |
| V7 | The envelope id and the policy hash are not on the revocation list | `dist:revoked` |
| V8 | The sequence (Q2, Q3, or R1 and O1 for a trust kind) | `dist:seq-replay`, `dist:trust-replay` |
| V9 | The body has `body_size` bytes and hashes to `body_sha256` | `dist:body-mismatch` |
| V10 | The envelope agrees with what is already staged at this `seq` (E7) | `dist:incomplete` |
| V11 | The artifact's own check, from the table in section 3 | The check's existing cause, or `dist:derived-mismatch` when a recompiled artifact differs |
| V12 | The widening rule (W1 to W7) | `dist:widening-unsigned` |

**V13.** After V6 passes, the PEP raises its time floor to `not_before` (T1). An install kind and an
`operator.answer` never raise it (IS5, OP2), so neither an install key nor an operator key can expire a
release.

### 9.2 Stage, commit and abort

**G1.** An envelope that passes V2 to V12 is staged. The PEP writes it and its body durably and sends
`stage-ack` with event `staged`. A refusal sends `stage-ack` with event `refused` and the cause. Both are
written to the PEP's audit log.

**G2.** A staged release is replaced by a staged envelope with a higher `seq` on the same stream. A lower
`seq` than the staged one is `dist:seq-replay`.

**C1.** A `commit` that names no staged release is answered with a state record whose cause is
`dist:not-staged`, and nothing changes.

**C2.** A PEP commits only when every artifact its target kind needs (section 3) is staged with one
stream, one `seq` and one policy hash, and when the artifacts it staged are the whole release. The release
id computed again over the staged artifacts, trust kinds left out (E10), must be the signed `release`. So a
transport that withholds an artifact of a signed release, such as its `agent.zones`, its `sandbox.profile`
or its `policy.spiral`, cannot commit the rest. Otherwise the cause is `dist:incomplete` and nothing
changes.

**C3.** At commit the PEP checks time (T3, T4), revocation (V7) and the ceiling (CL2) again for every
staged envelope, since all three can change after staging. A failure drops the staged release and reports
the cause. It then holds the release to the widening rule (V12) again against the release active at that
moment, since a lapse, a rollback or another commit may have changed it since staging. A release staged as
a renewal of a policy that lapsed before the commit goes from no policy to one, which is larger, so without
a covering statement it is refused with `dist:widening-unsigned` and stays staged.

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

**RB2.** A rollback is refused unless every envelope of the kept release still passes T4 and V7, has a
counting signature (S3), is not below a floor a revocation raised (R4) and is inside the ceiling (CL2). It
is held to what a staged
release is held to at its commit, since it becomes active anew. The cause is the one the failed check
gives.

**RB3.** A rollback to a release that allows more than the active one is a widening and falls under W1 to
W7, as the kept release would if it were staged against the active one. A PEP that cannot decide treats it
as W2 says, so on a `host` or a `mesh` node a kept table that is not the active one is larger. It refuses
the rollback unless the kept release holds a widening statement that covers it, and refuses a kept release
that is larger and says it does not widen even with one (W6).

### 9.4 The widening rule

A release is **larger** than another when some request is treated more permissively. For a policy the
order is refuse, then escalate, then allow, and a release is larger when any reading of the finite reading
domain moves up that order, or when the two policies do not have the same fields. For `egress.hosts` and
for the address set of `net.dests`, larger means not a subset. For `gateway.routes` any change is larger,
because a path that loses its route reads as another class. For `agent.zones`, larger means a protected
name is gone, and a release that drops the artifact drops every name. A `policy.ppt` image has no order.
The table format gives its nodes no meaning (the substrate does), so nothing in the image says which
outcome is the more permissive one, and any change of the image is larger. A `cfs.table` is ordered by
the core image inside it, as a `policy.core` is, and any other change of the table is larger. Going from no policy to any policy is larger.

The reading domain is set by the engineer who installs PrismPath. For a category it is the values the
classifier produces, for a bool true and false, and for an int its declared min to max. A tool or any
other value outside that domain is a resource nobody accounted for, so it is never allowed. A policy
whose rule names a value outside its domain is refused when it is loaded and when it is checked (V11),
with `policy:out-of-domain`. A reading whose category value is outside the domain is refused with the
same cause before the policy decides it, and an int or a bool outside its range or kind is refused by the
core as before. Some combinations of values in the domain are ones the classifier never
gives, such as a `net_dest` for a tool that is not `connect`. The walk covers them as well, so a release
that allows more on one of them is larger, and one that refuses more there is a tightening.

**W1.** A PEP that can decide (section 3) computes whether the staged release is larger than the active
one. It does not trust `widens` for that. It walks the reading domain and holds each policy to it as the
paragraph above says.

**W2.** A PEP that cannot decide treats the release as not larger only when `widens` is `false` and
`replaces` is the policy hash it has active. In every other case it treats the release as larger. It
still makes every comparison it can, and what it computes as larger is larger whatever `widens` says
(W6). A `host` or a `mesh` PEP can make one. A table has no order, so a staged table that is not byte
for byte the active one is larger. On those kinds a release goes in on its signature alone only when it
is a renewal.

**W3.** A release that is larger is staged only when a `trust.widening` envelope of the same release is
staged with it. Otherwise the cause is `dist:widening-unsigned`.

**W4.** A widening statement is an envelope with artifact `trust.widening`, the same `stream`, `seq` and
`policy_sha256` as the release, and this canon/2 body.

```json
{"encoding":"canon/2","format":"prismpath.dist-widening/1","from":["<policy hash>", "..."]}
```

`from` is sorted and holds at most 64 hashes. A longer one is `dist:too-large`. It lists the policy hashes
the release may replace. An empty list means any, including
none. The statement covers a PEP when `from` is empty or holds the PEP's active policy hash.

**W5.** A widening statement is signed by the authority. In this version every envelope is, so the rule
asks for a second, separate signed statement. That is what makes a widening an act the owner takes on
purpose and what the audit log records.

**W6.** A PEP that finds `widens` is `false` on a release it computes as larger refuses it with
`dist:widening-unsigned` even when a statement is present, because the signer's claim is wrong. A PEP that
can decide computes this of every release. Every PEP computes that a first install is larger, since it
goes from no policy to one, and a `host` or a `mesh` PEP computes that another table is.

**W7.** A controller checks W1 itself before it offers a release to a target that cannot decide, and
refuses to offer one whose `widens` is `false` and which it computes as larger. It compares the release
with the one it holds whose policy hash is `replaces`, and a `replaces` it holds no release for is
treated as larger. The sealing tool applies the same test when it sets `widens`, so for a `mesh` or a
`host` table `widens` is `false` only on a renewal.

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
reports event `lapsed` with `dist:revoked`, or goes to its fallback policy where it has one (FB1). That is the case when an active envelope's id or policy hash
is listed, when its `seq` is below a raised floor, or when it no longer has a counting signature. A staged
release is dropped on the same test. The owner avoids an outage by order of work. Rotate, release under
the new key, commit, then revoke the old key.

**R6.** A revocation list never restores trust, and a PEP holds the latest list and no more, so its
memory is bounded by R7. A later list drops an envelope or a policy only after a floor has passed it.
The PEP cannot check that, since an id does not tell its `seq`, so the tool that seals a list and the
controller that stores one both check it against the earlier lists and the envelopes they hold, and
refuse a list that drops an entry no floor has passed or that they cannot place (R8). A key is never
dropped. A PEP refuses a list that lacks a key id its current list holds with `dist:trust-replay`, so a
key id once in `keys` stays refused for the life of the trust store. A PEP keeps the entry of `floors`
for its own stream and need not keep the others.

**R8.** The sealing tool refuses to write, and a controller refuses to store, a revocation list that drops
a key, or that drops an envelope id or a policy hash whose every envelope it cannot show to be below a
floor that list or an earlier one raised.

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

**O4.** `add` is never the PEP's own instance key, never a key id on the revocation list, never a key
the store has retired, since a retired key does not come back, and never a key the PEP holds or has
retired in the role `install` or `operator` (K4). Each is `dist:rotation-invalid`.

## 12. Expiry

**X1.** A PEP checks the `expires` of every envelope of its active release at least once a minute and
before it reports state. When one has passed, the PEP goes to `no-policy` and reports event `lapsed` with
`dist:expired`, unless X6 and X7 put it on hold or it has a fallback policy (FB1).

**X2.** This is fail toward expiry. A PEP that is cut off from the controller, and so from any
revocation, keeps deciding under its last release until that release expires and not after. The longest a
revoked release can keep deciding at a cut off PEP is the time left on its envelope, plus the limit of T2
on a PEP without a clock. A deployment that chose HOLD (X6) has given this bound up for that PEP and
keeps only what X8 and X9 state.

**X3.** A PEP in `no-policy` or `locked` allows nothing. The cause on its receipts is
`dist:policy-lapsed`, or `dist:floor-lost` when locked. The two exceptions are signed by the engineer
and never by the authority. An action floor allows what it allows in every state (AF1), and a PEP with a
fallback policy decides under it (FB1).

**X4.** A trust kind carries `expires` 0 and never expires, and so does an install kind (AF3). A revocation that could expire would restore
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

**X9.** A hold never widens what the authority signed. A held PEP refuses a local rollback with
`dist:held`. An install set is the engineer's and a held PEP takes one as any PEP does, a widening one
with its event and its finding (IS12, H13). The only way out
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
   (`prismpath.dist-trust/1`, or `/2` by P4) with the trusted public keys, the threshold, the PEP's
   target kind and its stream. Every entry of `keys` is an authority key. At this step the PEP checks
   the anchor's keys pairwise. No key is in two of `keys`, the install keys and the operator keys, none
   is the PEP's instance key, and none is a key the PEP holds in another role or has retired in any role
   (K4). Any of these refuses the anchor and leaves the PEP as it was.
4. The PEP prints the fingerprint of the anchor and the operator compares it with the one the owner's
   tool printed. A host PEP does not start following a stream until the operator confirms.
5. The owner enrolls the PEP's instance public key, target kind and stream at the controller.

**P3.** Provisioning sets the trust sequence, the floor and the time floor to their starting values and is
the only step that clears `locked`. It is written to the audit log as its own event. It never reopens the
older forms of section 17. A stream on which the PEP refused them stays refused after any provisioning,
whether or not the PEP ever held an install statement (L2, IS9).

**P4.** An anchor that holds install keys has format `prismpath.dist-trust/2`. It holds what a
`prismpath.dist-trust/1` anchor holds and the member `install`, which holds `keys`, `threshold` and
`operators` as the body of an `install.trust` does (IS11), `seq`, the install trust sequence they stand
at, and `domain`, the SHA-256 of the reading domain the PEP was built with (CL4). Those keys go to the
install record and never to the trust store (K3, K4). A PEP of this version reads both formats, and a
`/1` anchor holds no install part. A reader of `/1` alone refuses a `/2` anchor, so a PEP is never
given install keys it would not keep. In both formats `keys` holds authority keys only, and an entry
that names another role is `dist:bad-format` and refuses the anchor. An older PEP whose trust store holds
a key in a role it does not know keeps it and never counts it (K4), which is why the sealing tool never
writes one there. A `/1` anchor, or a `/2` anchor with no `install` member, that reaches a PEP holding an
install record replaces the trust store only. The install record, its keys, its sets and its sequences
stay as they are, and the anchor's keys are still checked pairwise against the held and the retired
install and operator keys (P2 step 3). A PEP refuses an anchor whose `domain` is not the hash of the
domain it was built with. The engineer may put install statements on the PEP in step 3 with the anchor,
and section 21 gives their rules. P3 resets nothing of an install statement. A provisioning never lowers
an install `seq` or the install trust sequence, starts them again only with a disjoint install key set
(IS6), and never reopens the older forms (IS9). A provisioning that brings install statements and no
anchor is the install provisioning of IS13.

## 15. The heartbeat and the fleet view

### 15.1 The state record

**H1.** A state record is this byte string. Integers are little endian.

```
offset  size  field
0       4     magic "PPSR"
4       1     version, 1
5       1     event     0 beat, 1 staged, 2 refused, 3 committed, 4 aborted,
                        5 trust-applied, 6 lapsed, 7 rolled-back, 8 provisioned, 9 held,
                        10 fallback, 11 install-applied, 12 install-widened, 13 answered
6       1     status    0 no-policy, 1 active, 2 locked. Bit 7 set when a release is staged.
                        Bit 6 set when this is a dev build (D3). Bit 5 set while the PEP is
                        on hold past expiry (X7). Bit 4 set while the installed fallback
                        policy decides (FB2)
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
policy's hash and layout hash. Only decisions of the active release are frames. A request the action
floor answered, a decision of the fallback policy and one of an operator's answer are left out, since no
active policy made them, and the counts of H10 and the receipts show them (RC1). A PEP under its
fallback policy has no active policy and sends a body of length 0. A PEP that does not encode Facet sends a body of length 0. The `mesh` and
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
| 4 | When the body is not empty, its preamble's policy hash and layout hash equal the ones the controller computes from the expected release. A body on a record with bit 4 set is a mismatch, since the fallback policy sends none (H5) | `fleet:policy-mismatch` |
| 5 | The body decodes under the expected policy | `wire:codebook-mismatch` |

A `provisioned` record whose PEP id is not yet enrolled is not filed at step 1. The controller keeps it,
at most four for each PEP id and 64 in all, the oldest dropped first, and checks them when the PEP is
enrolled (P2 step 5). Only a record that verifies under the enrolled instance key is used, so a forged
record cannot stand for the real one. A flood of forged ids can push the real record out. That loses the
event and nothing else, since the enrollment of the install id is the acknowledgement (H13) and the
PEP's next record carries its install id. So a first install set that arrives at provisioning is never
`fleet:state-invalid` before the enrollment that acknowledges it. The controller keeps the last counter
it accepted for a PEP id across a new enrollment of that id, so a record from before it is still a
replay at step 2.

**H9.** A controller names the present with an epoch id, a number that rises at least once per heartbeat
interval. It rides in the `offers` answer as `epoch` and in a frame of type 6 (bytes 4 to 11). A PEP puts
the highest epoch id it has seen in every record. This is the epoch id of RFC 9334 section 10.3. It tells
the controller that a record was made after that epoch began, which the PEP's own clock cannot prove. An
epoch id is not signed, changes nothing but that field, and a PEP never lowers the one it holds.

**H10.** The extensions are a run of entries, each a type byte, a two byte length and that many bytes.
The instance key's signature covers them. Type 1 is an Entity Attestation Token (RFC 9711) whose
`eat_nonce` is the SHA-256 of bytes 0 to 146+m of the record, so hardware evidence is bound to one state
record. Type 2 is reserved for the record of a member a PEP speaks for. Type 3 is the install record of a
PEP that holds an install statement or install keys, and it is 27 bytes.

```
0   16  install id, the first 16 bytes of the SHA-256 of 160 bytes. They are the set id (IS1) and
        the seq of the action floor, of the fallback policy and of the ceiling the PEP holds,
        then the install trust sequence and the install trust id (IS10). A set id and the
        install trust id are 32 raw bytes, a number is 8 bytes, and a set not held is zeros
16  2   the low 16 bits of the install trust sequence
18  1   subject. On a record with event staged, refused, answered, install-applied or install-widened it says what
                the event is about. 0 not an install kind, 1 action floor, 2 fallback policy, 3 ceiling,
        4 install trust statement, 5 operator answer
19  4   floor answers, every request the action floor allowed or escalated since provisioning
23  4   floor overrides, those of them the release or the fallback policy would not have allowed
```

Integers are little endian. The two counts are cumulative and stop at 2^32 - 1. The PEP saves them with
its counter (H3), so no count goes down and a lost record loses nothing. Such a PEP sends type 3 in every
record, which makes its record 242 bytes on `mesh` and `cfs` and its frame 246 of the 250 bytes ESP-NOW
carries. So a `mesh` PEP with an install record sends no Facet body, and this version gives it none (H5).
Its record has no room for a type 1 or a type 2 entry either, so it sends neither.
A PEP in this version sends no other type.
A controller skips a type it does not know and never treats an extension as a signature on the record.
A type 1 entry that does not read, or whose `eat_nonce` is not that hash, makes the record
`fleet:state-invalid` at step 1 of H6.

**H7.** A PEP with no accepted record for three intervals is filed as `fleet:silent`.

**H8.** A PEP whose record has bit 5 set is filed as `dist:held` for as long as its records carry the bit.
A record with bit 5 from a target that has no HOLD setting is filed as `fleet:state-invalid`.

**H11.** A PEP whose record has bit 4 set is filed as `dist:fallback` for as long as its records carry
the bit. Such a record has zeros for the active policy hash, release id and `seq`, and step 3 of H6
expects those zeros of it and files no `fleet:policy-mismatch` for them. A record with bit 4 from a PEP
enrolled with no fallback policy, or with bits 4 and 5 together, is filed as `fleet:state-invalid`.

**H12.** The controller keeps the install id it expects of each PEP, the enrolled one and then the one
its latest offered install statements give (IS8). A record whose type 3 extension carries another install
id, or that has no type 3 where one is expected, is filed as `fleet:policy-mismatch` at step 3 of H6. The
controller reads the install trust sequence from the record to offer the install trust statements the
PEP lacks, and the subject byte to file a refusal against the install statement or the release it was
about. The fleet view shows both counts, and a count is never a finding.

**H13.** A widening is acknowledged before a controller spreads it. A controller that is handed an
install set whose `widens` is `true`, or an `install.trust` that adds a key of either role or lowers
the threshold, files `dist:install-widened` against it, offers it to nobody, and does not expect its
install id of any PEP, until an acknowledger acknowledges it at the controller. An acknowledger is a
person the controller lets do this by its own login. It holds no key of this spec and signs nothing,
and it is not the signed operator of OP1. Its power is detection only, and it is bounded and unsigned.
An acknowledgement lets the controller offer a set and expect its install id, and that is all. No PEP
reads it, and a PEP takes only what its install signatures carry. The acknowledgement names the
envelope ids of the statements, never a release id, and goes to the controller's audit log (F5). A statement with no
envelope id on file cannot be acknowledged. A controller also treats as widening, for each PEP, a ceiling
that would lapse the release it expects of that PEP (IS12). A set that does not widen, and a set of another install kind, never waits behind an unacknowledged one.
On `host` and `mesh` every changed table is larger, so there only a renewal of the same table goes
without an acknowledgement. The controller and the sealing tool compare every install
set with the one it follows and refuse one whose `widens` is `false` and which they compute as larger
(W7). On `host` and `mesh` a table that is not byte for byte the one before is larger. A `cfs.table` is compared
by the core image inside it, as section 9.4 orders it, and any other change of the table is larger. The
cFS app itself cannot make that comparison, which is why section 3 says it cannot decide and why the duty
is here. A record with event `install-widened` is filed as `dist:install-widened` against
its PEP. The finding stays open until the set it reports is an acknowledged one, and for a set the
controller never held that means the acknowledger hands the controller the statements and acknowledges
them. For a first set that arrives at provisioning, the `provisioned` record carries cause
`dist:install-widened`, and the enrollment of the install id at P2 step 5 is the acknowledgement. This
rule detects and does not prevent. A PEP applies a well signed widening set from any sender, a hostile
controller, a relay or a broadcast included, and what H13 gives is that it cannot spread or stay unseen.

### 15.3 The controller

**F1.** A controller holds no authority private key. It stores sealed envelopes and bodies and cannot make
one. It runs the same verifier a PEP runs (V2 to V11, with the target taken from the envelope) before it
offers anything, and refuses to store what does not verify. It always reads `meta` in full (E1, E11),
also for an envelope whose targets all skip it (E9).

**F2.** A controller keeps, per PEP, the enrolled instance key, the target kind, the stream, the group,
the expected policy hash and `seq`, the last accepted record and the open findings.

**F3.** Per group and release the controller runs this machine.

| State | Leaves when | To |
|---|---|---|
| `offered` | the first `stage-ack` arrives | `staging` |
| `staging` | the group's rule is met | `committing` |
| `staging` | a member refuses, or the stage window (default 120 seconds, 500 milliseconds on the mesh) ends, under rule `all` | `aborted` |
| `committing` | every member that staged reports `committed` | `committed` |
| `committing` | the commit window (default 120 seconds, and on the mesh the commit's delay plus 2 seconds) ends first | `partial` |

A group's rule is `each` or `all`. Under `each` the controller sends `commit` to a member as soon as that
member staged, and a single PEP is a group of one. Under `all` it sends `commit` only when every member
staged and `abort` otherwise, which is the mesh's two phase commit.

**F4.** `partial` and every finding of H6 and H7 stay open until a later record clears them. The fleet
view shows, per PEP, the expected and the reported policy hash and `seq`, so a mixed fleet in mid swap is
bounded by the windows of F3 and visible while it lasts. A rollout of a release that says it widens is
marked in the view and in the state the controller keeps, so a widening the owner pushed stands out. It is
larger by comparison when a comparator with an order finds it larger, or when nothing came before it, and
larger by rule when it is larger only because a host or a mesh node counts any change of a table as larger.

**F5.** The controller writes every offer, ack, commit, abort, finding and trust statement to its own
audit log, signed with the controller's instance key.

**F6.** A controller offers a PEP the trust statements it lacks, in order, and offers it no release until
the PEP reports the trust sequence of the chain's end. Install statements are not held back by this
(IS7). A state record does not say which release it
refused, so this order is what tells a refused trust statement from a refused release. A refusal that
comes while the PEP is behind on the chain, and whose subject byte names no install kind (H10), is filed
against the trust statement and never against a
rollout. One controller serves one trust chain.

## 16. Dev builds and escape hatches

**D1.** An escape hatch is any switch that skips a check of this spec or of `spec-secure-hotswap.md`.
The hatches are `PPT_NET_ALLOW_UNVERIFIED=1` in the XDP loader, `--allow-unsigned` on a swap, an attach or
an edge verify, and a verify of evidence or of in-toto envelopes without the authority key and the instance key pinned, and the install key where the run holds
an install case (RC4). In a production
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
(destination tables), `prismpath.grant/1` (grants), `prismpath.zones.attestation/1` (the agent home's zone
file), `prismpath.cfs-table/1` (`TableSig`) and the mesh's `PPTM1` message. Each has its own revocation or none.

**L1.** From package version 0.3.0 every writer emits only distribution envelopes. The bodies are the same
bytes as before, so an image, a table or a core image keeps its hash.

**L2.** A PEP that has committed any distribution envelope on a stream refuses the older forms for that
stream from then on with `dist:legacy-refused`. This holds whatever the package version is, so the older
forms are never a way around a floor, an expiry or a revocation. The PEP keeps this as a mark in its
anchor part, apart from the trust store, so no provisioning clears it (P3), whether or not the PEP ever
held an install statement.

**L3.** A reader accepts the older forms on a PEP that L2 does not cover through the 0.3 series, and
writes a `legacy_form` audit event each time. From 0.4.0 the older forms are refused everywhere with
`dist:legacy-refused`.

**L4.** The flow manifest (`prismpath-flow-manifest/1`), the qualification envelope, the crypto registry
and root statements are not distributed artifacts in this version and keep their forms.

## 18. Refusal causes

The registry is of refusals and of deviations. Three rows below are deviations and refuse nothing.
`dist:held`, `dist:fallback` and `dist:floor-allowed` mark a decision or a record that was not made by a
release in force.

These rows are appended to `prismpath/kernel/causes.py` after 134, the highest code on main when this was
written. If another change lands first the numbers move up together and the names do not change. Section
21 appended 161 to 168 after 160, `policy:out-of-domain`, which section 9.4 registers and CL4 uses.

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
| 144 | `dist:trust-replay` | authority | A revocation or rotation whose `seq` is not the trust sequence plus one, or a revocation list that would restore trust by dropping a key, or by dropping an entry no floor has passed (R6, R8). Also an `install.trust` that is not the install trust sequence plus one, and a provisioning whose install trust sequence is below the PEP's (IS6, IS11) |
| 145 | `dist:rotation-invalid` | authority | A rotation without the new key's signature, or that names a key it may not. Also an `install.trust` that adds a key without its signature or adds a key of another role (IS11) |
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
| 156 | `fleet:state-replay` | wire | A state record whose counter is not above the last accepted, or whose epoch is neither the controller's current one nor the one before |
| 157 | `fleet:policy-mismatch` | wire | A PEP reports a policy hash, `seq` or Facet preamble other than the expected one |
| 158 | `fleet:silent` | wire | No accepted state record from a PEP for three intervals |
| 159 | `dist:held` | state | A PEP deciding under an expired release because its deployment chose HOLD, or an action refused because of that hold |
| 160 | `policy:out-of-domain` | envelope | A policy whose rule names a value outside its field's reading domain (9.4) |
| 161 | `dist:fallback` | state | A PEP deciding under its installed fallback policy because no release is active |
| 162 | `dist:floor-allowed` | state | A request the installed action floor allowed, whatever the policy says |
| 163 | `dist:install-lost` | state | An install set or an install record that no longer reads at start, so the PEP runs without it |
| 164 | `dist:install-widened` | state | An install set applied or handed over that allows more than the one before it, or is the first of its kind |
| 165 | `dist:above-ceiling` | envelope | A release or an install set that allows what the installed ceiling does not, or a ceiling the held sets are above |
| 166 | `dist:floor-rate` | routing | A request the action floor would have allowed, escalated because the signed rate of floor allows is spent, or an operator's answer past its signed rate (OP3) |
| 167 | `dist:floor-broad` | envelope | An action floor with a default or catch all, a rule that names no one action or lacks a required test, a test of a field that is not independent, or more rules or entries than its bound |
| 168 | `dist:answer-unbound` | authority | An operator's answer that names no open escalation of this PEP, or one already answered |

Reused as they are. `sig:invalid` (2), `sig:revoked-key` (3), `wire:codebook-mismatch` (51),
`document:not-canonical` (103), and the causes of the artifact checks of section 3.

## 19. Implementations and parity

Python holds every part. Rust (`prismpath-hotswap-rs`) holds the sealed envelope, the verifier, the trust
store with revocation and rotation, the PEP machine for the `host` target and the state record. C holds
the sealed envelope, the strict scanner, the verifier, the trust store and the PEP machine for the `mesh`
and `cfs` targets, compiled natively for tests and unchanged for the targets. The controller, the HTTP
binding and the `agent`, `gateway` and `xdp` targets are Python only.

Section 21 is built in no implementation yet, and its cases are pending in each. This is what exists
today and what the section needs of each part.

| Part | Today | Section 21 needs |
|---|---|---|
| Python | The envelope, the verifier, the trust store, the PEP machine for `host` and `mesh`, the controller and the HTTP binding. One role, a threshold of 1, no install kind | All of section 21. The install and operator roles, the install record, the three sets on every kind, the overlay of AF1 in the widening comparison, the acknowledgement of H13 and the replay of RC4 |
| Rust | The envelope, the verifier, the trust store, the `host` PEP and the state record | Section 21 for the `host` target |
| C core | The envelope, the scanner, the verifier, the trust store and the PEP machine, in eight durable parts, with `PP_RECORD_MAX` at 212 bytes and one role | `PP_RECORD_MAX` at 242 bytes (H10). A ninth part for the install record and a tenth for the rate counts (IS10, AF8). The role `install` with a threshold above one (IS2), and the role `operator` for `cfs` alone, since `host`, `mesh` and `xdp` have no escalation (OP1). The staging of install statements as G1 stages an envelope (IS4). The readers of an install `meta`, of a list and of an `install.trust`. The narrowness check on a table (AF9). No table comparator, which stays at the sealing tool and the controller (CL1) |
| cFS app | It admits a table by `TableSig` and decides with one image. Its layout has `INT`, `BOOL` and `MONITOR` and no command label. A monitor staleness bound of 0 is accepted | The work of PR 18, then a second and third image for the floor and the fallback policy, the layout kinds `COMMAND` and a mark for a proposer's reading, a staleness bound that 0 cannot switch off (AF10), the not enacted case and `rates.jsonl` (AF7, RC4), and an event at the fallback (FB4) |
| Mesh firmware | A local copy of the evaluator, one table, and an allow list of ids standing in for the signature check | The C core in place of the stand in, three tables, a layout with a command label and independent fields with staleness, and the durable rate counts |
| `agent` home | Readings with `zone_reach` and no zone name | The reading field `zone_name` (AF1), the floor asked first by the hook, the proxies and the sandbox compiler, and the zones of FB9 |

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
| 54 | A rollback to a kept release that has expired, to one that is revoked, to one whose only signing key is revoked, to one whose only signing key was retired, and to one below a raised floor | refused with `dist:expired`, `dist:revoked`, `sig:revoked-key`, `sig:revoked-key`, `dist:seq-replay` | RB2 | P |
| 55 | A rollback to a kept release that allows more, without and with a covering statement | `dist:widening-unsigned`, rolled back | RB3 | P |
| 56 | An `agent` PEP is offered a policy that allows one more reading with `widens` false and no statement | `dist:widening-unsigned` | W1, W3, W6, V12 | P |
| 57 | An `agent` PEP is offered a policy that allows less | committed on its ordinary signature | W1 | P |
| 58 | An `agent` PEP is offered a policy that moves a reading from refuse to escalate | `dist:widening-unsigned` | W1 | P |
| 59 | An `agent` PEP is offered a host list with one more host, and a `gateway` PEP a changed route table | `dist:widening-unsigned` each | W1 | P |
| 60 | A `mesh` PEP is offered the table it has active again at a higher `seq`, with `widens` false and `replaces` its active hash, and a `cfs` PEP a table with another core image, `widens` false and `replaces` its active hash | committed each, the first as a renewal and the second on the signer's word | W2 | P C |
| 61 | A `mesh` PEP is offered `widens` false with `replaces` another hash, `widens` true, and another table with `widens` false and `replaces` its active hash, each without a statement, and the last again with a covering statement | `dist:widening-unsigned` each time, the last because the signer's word is wrong | W2, W3, W6 | P C |
| 62 | A widening statement whose `from` holds the active hash, one whose `from` is empty, and one whose `from` holds only another hash | committed, committed, `dist:widening-unsigned` | W4, W5 | P R C |
| 63 | A first install with no statement, and with one | `dist:widening-unsigned`, committed | W2, W3 | P R C |
| 64 | A statement is present and a deciding PEP computes larger while `widens` is false | `dist:widening-unsigned` | W6 | P |
| 65 | A controller is given a release for `mesh` that it computes as larger with `widens` false | it refuses to offer it | W7 | P |
| 66 | A revocation with `seq` one above the trust sequence, the same one again, an older one, and one that skips a number | applied, unchanged, `dist:trust-replay`, `dist:trust-replay` | R1 | P R C |
| 67 | After a key is revoked, a pack signed by it | `sig:revoked-key` | R2 | P R C |
| 68 | A revocation raises a stream's floor to 9, then a release at 8 | `dist:seq-replay` | R4, Q4 | P R C |
| 69 | A revocation lists the active envelope, the active policy hash, the only signing key, and a floor above the active `seq` | `no-policy`, event `lapsed`, `dist:revoked`, each time | R5 | P R C |
| 70 | A later revocation drops a key id an earlier one listed | `dist:trust-replay`, the list is not applied and the key is still refused | R6 | P R C |
| 71 | A revocation list with 65 entries | `dist:too-large` | R7 | P R C |
| 72 | A rotation signed by the old and the new key, then a pack under the new key | applied, committed | O1, O2, O3 | P R C |
| 73 | After a rotation that retires the old key, a pack signed by the old key, while the release active under it keeps deciding | `sig:revoked-key`, still active | O3, S5 | P R C |
| 74 | A rotation signed only by an unknown key, and one without the new key's signature | `dist:unknown-key`, `dist:rotation-invalid` | O2 | P R C |
| 75 | A rotation whose `retire` is unknown, whose `add` is the PEP's instance key, whose `add` is revoked, and whose `add` is a key the store retired | `dist:rotation-invalid` each | O3, O4 | P R |
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
| 127 | A `policy.ppt` envelope whose `fields` is a string, whose `counts` is an integer, whose `counts` lacks a member, whose `packing` has no `sidecar_sha256`, and a `ppt-pack/1` manifest whose `fields` is a string | `dist:bad-format` four times, then `manifest:bad-format`, and no check raises | E11, V4 | P R |
| 128 | One signed `policy.ppt` envelope whose `counts` is an integer, read by a `mesh` PEP, by a `host` PEP and by the controller, then for the `mesh` PEP a `meta` that is a string, one nested four levels, and one that runs past the envelope | staged on `mesh`, `dist:bad-format` on `host`, refused by the controller, then `dist:bad-format` three times | E9, E11, F1 | P C |
| 129 | An `agent` PEP is offered a release whose `agent.zones` lacks a name the active one protects, one with no `agent.zones` at all, and one that adds a name, each with no statement | `dist:widening-unsigned`, `dist:widening-unsigned`, committed | W1, W3, V11 | P |
| 130 | A list raises a floor past a revoked envelope, the next list drops that envelope, and the envelope is sent again. Then a list that drops an envelope no floor has passed is given to the sealing tool and to a controller | applied, applied with the PEP holding only the latest list, `dist:seq-replay`, then refused by both | R6, R8 | P R C |
| 131 | A rotation that would make a ninth key, and seventeen keys retired one after another, then a pack signed by the first retired | `dist:too-large`, then `dist:unknown-key` | K5 | P R C |
| 132 | A `mesh` PEP is sent a revocation list of 64 entries in each list and 16 streams, a `policy.ppt` of 641 bytes, and over frames a trust body offered at 16,385 bytes | applied, `dist:too-large` from the signed `body_size` with no body read, and the transfer dropped with `dist:too-large` | E6, V5, R7, B9 | P C |
| 133 | A PEP one trust statement behind is offered that statement and a release, refuses the statement, then takes it and the release | only the statement is offered first, the refusal is filed against the statement and the rollout is unmoved, then the release is offered and commits | F6 | P |
| 134 | A revocation whose `targets` names only `mesh` is sent to a `host` PEP and a `mesh` PEP, then a rotation naming every kind | applied on both, and both then take the rotation at the next trust sequence | V5, R1 | P R C |
| 135 | A widening statement whose `from` holds 64 hashes, and one with 65 | staged, `dist:too-large` | W4 | P R C |
| 136 | The sealing tool and a controller are given a `mesh` release whose table differs from the one it replaces by one constant, with `widens` false, then the same table again with a later `expires`, then a `cfs` table whose core image allows less and one whose core image is the same and whose rules differ | the tool writes `widens` true and the controller refuses the false one, the renewal is offered with `widens` false, the narrower `cfs` table is not larger, and the last is larger | W7, W1 | P |
| 137 | A first install whose signed release id names an artifact that is not staged, on a `host` without its `policy.spiral`, on a `mesh` node whose table's release id also names a `policy.spiral`, and on an `agent` PEP without its `agent.zones` | `dist:incomplete` each, and no release is active | C2, E10 | P R C |
| 138 | An update whose signed release id names an artifact that is not staged, on a `host` without its `policy.spiral`, on a `mesh` node whose table's release id also names a `policy.spiral`, and on an `agent` PEP that keeps its protected zones and adds a host with the `agent.zones` envelope withheld | `dist:incomplete` each, and the old release stays active | C2, E10 | P R C |
| 139 | A `host` and a `mesh` PEP are offered a first install with `widens` false and a widening statement whose `from` is empty | `dist:widening-unsigned`, and no release is active | W2, W6 | P R C |
| 140 | A `host` and a `mesh` PEP roll back from another table to a kept renewal that says it does not widen and holds a widening statement whose `from` is empty | `dist:widening-unsigned`, the active release stays | RB3, W2, W6 | P R C |
| 141 | An `agent` PEP is sent a `policy.core` whose rule allows a tool the classifier does not produce, and the agent's policy loader is given the same image | `policy:out-of-domain` both times | 9.4, V11 | P |
| 142 | An `agent` PEP is offered a `policy.core` that allows a combination the classifier never gives, and one that refuses there what the active one asks about, each with `widens` false, and a policy whose rules name only values in the domain decides a reading whose tool is outside it | `dist:widening-unsigned`, committed, and the reading is refused with `policy:out-of-domain` | 9.4, W1, W6 | P |
| 143 | A renewal staged on a `host` and a `mesh` PEP with `widens` false and no statement, whose active release then expires before the commit | `dist:widening-unsigned` at commit, and nothing is active | C3, V12, W2 | P R C |
| 161 | A `mesh`, a `cfs` and a `host` PEP are each provisioned with an anchor that holds two install keys, an action floor and a fallback policy, and each is then restarted | at P2 step 4 each prints the envelope id of every install statement beside the anchor fingerprint, the `provisioned` audit event names them, and both sets are held after the restart | IS1, IS2, IS8, IS10, P4 | P R C |
| 162 | A PEP is sent an install statement signed only by authority keys, one with `expires` 30 days on, one whose `targets` names two kinds, one for another stream, one whose body is one byte short, one whose body fails the check of the artifact `as` names, one with no `as`, and a PEP with a clock one whose `not_before` is 301 seconds ahead | `dist:unknown-key`, `dist:bad-format`, `dist:bad-format`, `dist:target-mismatch`, `dist:body-mismatch`, the check's cause, `dist:bad-format`, `dist:not-yet-valid`, and what the PEP holds is unchanged each time | IS1, IS2, IS5 | P R C |
| 163 | An anchor that holds one key in both roles, an anchor whose install key is the PEP's instance key, then a release, a widening statement, a revocation and a rotation each signed only by install keys, and a `trust.rotation` whose `add` is an install key and one whose `add` is a retired install key | refused at provisioning twice, `dist:unknown-key` four times, then `dist:rotation-invalid` twice | IS2, K4, O4 | P R C |
| 164 | A PEP of each of the six kinds is sent an action floor, a fallback policy and a ceiling in the form of its kind. Then an `agent` PEP is sent a fallback set with no `egress.hosts` and a floor set that holds an `agent.zones`, an `xdp` PEP a set whose `net.edge` is not compiled from its `policy.core` and `net.dests`, and a `gateway` PEP two statements at one `seq` with different release ids | applied on all six, then the set that is not whole is not applied and the held set still decides, `dist:bad-format`, `dist:derived-mismatch`, `dist:incomplete` | IS1, IS3, IS5, CL1 | P |
| 165 | With three install keys and an install threshold of 2, a PEP is sent an install statement with one good signature, one with two, and one with one good signature and one by a retired install key | `dist:unknown-key`, applied, `sig:revoked-key` | IS2 | P R C |
| 166 | A PEP with an install threshold of 1 is sent a well signed action floor and a well signed `install.trust` in a message, and is then provisioned with the same floor | `dist:target-mismatch` twice and nothing changes, then the floor is held | IS4, IS2 | P R C |
| 167 | With an install threshold of 2, an action floor is sent to a `mesh` PEP over the frame binding and pulled by a `host` PEP over HTTP, with no `commit`. A forged `abort` and a forged `commit` that name it follow | applied when verified, durable before the event is reported, and the forged messages change nothing | IS4 | P C |
| 168 | The fallback policy of an `agent` PEP arrives one statement at a time. One run has a restart before the last statement, one has a set at a higher `seq` arrive while the first is staged, then one at a lower | the held fallback policy decides throughout, each statement is staged with event `staged` and survives the restart, the set is applied when its last statement arrives, the higher set replaces the staged one, then `dist:seq-replay`, and no part ever reads a mix of two sets | IS4, G1, G2 | P |
| 169 | A PEP that holds an action floor at `seq` 3 is sent one at 2, another at 3, the same one again, one at 5, one at 4, and a fallback policy at 1 | `dist:seq-replay`, `dist:seq-replay`, unchanged, applied, `dist:seq-replay`, applied | IS6 | P R C |
| 170 | A PEP that holds an action floor at `seq` 5 and a fallback policy is provisioned with its own install key set and a floor at 4, with an anchor alone, with an anchor whose install trust sequence is lower, with a higher one that shares a key with the held set, drops another and brings a floor at 1, and with a higher one that shares no key and brings a floor at 1 and no fallback policy. The floor at 5 is then sent again | `dist:seq-replay`, the held floor stays, `dist:trust-replay`, then the key set changes with the dropped key retired and the install trust id the anchor's fingerprint while the floor at 1 is `dist:seq-replay`, then the floor at 1 is held with every old install key retired and the fallback policy dropped, and the old floor is `sig:revoked-key` | IS6, IS10, P4 | P R C |
| 171 | A `locked` PEP with an install threshold of 2 is sent a fallback policy at a higher `seq` | applied, and the PEP stays `locked` | IS6, FB1 | P R C |
| 172 | A PEP with an action floor is sent a revocation that lists an install key id, the floor's envelope ids and its policy hash, then a `trust.rotation` whose `retire` names an install key, and the sealing tool and a controller are given that revocation list | applied with the floor deciding as before and the install key still counting, `dist:rotation-invalid`, and the tool and the controller refuse the list | IS7, AF3 | P R C |
| 173 | A PEP two statements behind on the authority's trust chain is offered an action floor, and a PEP two behind on the install trust sequence is offered a release | each is offered and applied or committed without waiting for the other chain | IS7, IS8 | P |
| 174 | An `install.trust` signed by two old keys and a new one adds the new key, a floor signed with the new key follows, a second `install.trust` drops an old key, a floor signed by the dropped key and one other follows, and the PEP restarts holding a fallback policy the dropped key signed | applied, applied, applied, `sig:revoked-key`, and the fallback policy is still held | IS11, AF3 | P R C |
| 175 | An `install.trust` two above the install trust sequence, one without the signature of the key it adds, one with fewer signatures than the install threshold, one with five keys, one with a threshold of 0, one that adds the PEP's instance key, one that adds a trusted authority key, one that adds a key id on the revocation list, one that adds a retired install key, and one signed only by authority keys | `dist:trust-replay`, `dist:rotation-invalid`, `dist:unknown-key`, `dist:too-large`, `dist:bad-format`, `dist:rotation-invalid` four times, `dist:unknown-key`, and the trust store of section 5 is what it was | IS11, IS7 | P R C |
| 176 | A set of four install keys at a threshold of 4 is asked to add a fifth signer's key in one statement, then does it in two, first dropping a key with the threshold at 3 and then adding the new one | the sealing tool refuses the first because it needs five signatures, then both statements are applied | IS11 | P R C |
| 177 | Nine install keys are retired one after another, then a floor signed by the first retired and one current key is sent | `dist:unknown-key`, since the ninth retirement forgot the first id, and the floor is refused all the same | IS11 | P R C |
| 178 | The empty set of the action floor is sent at a `seq` above the held floor's, the held floor is sent again, and the empty set of the ceiling is sent | the floor is withdrawn with event `install-applied` and the PEP holds none, `dist:seq-replay`, and the ceiling is withdrawn with event `install-widened` | IS1, IS6, IS12 | P R C |
| 179 | Two PEPs are sent different `install.trust` statements at the same install trust sequence, each well signed | both apply, their install ids differ, and the controller files `fleet:policy-mismatch` against the one it did not offer | IS11, IS10, H12 | P |
| 180 | A `mesh` PEP with no clock, whose release expires in a month, is sent an action floor whose `not_before` is a year ahead | applied, the time floor does not move and the release is still active | IS5, T1 | P C |
| 181 | A controller is handed an install statement with a bad signature and a good one, serves a PEP two install trust statements behind by its record, and receives a `refused` record with subject 1 while a release is also on offer | it refuses the first and offers the second, offers the two trust statements in order before any install set, and files the refusal against the floor and not the release | IS8, H12 | P |
| 182 | A PEP that holds an install statement and has committed nothing is given its older signed form, again after a second provisioning, and again after its install record is made unreadable | `dist:legacy-refused` each time | IS9, L2 | P R C |
| 183 | A PEP starts with one byte of its stored action floor changed and a second good copy, then with no good copy, and is then sent that same floor again and one at a new `seq`. A PEP starts with one copy of its install record unreadable, then with both | it uses the good copy, then event `refused` with `dist:install-lost`, its install id no longer counts the floor and it decides as a PEP that never had one, then unchanged with no floor held, then applied. The last PEP uses the second copy, then holds no set, reports `dist:install-lost`, keeps deciding under its release and takes no install statement by message and no release until it is provisioned | IS10, IS6 | P R C |
| 184 | A first action floor with `widens` true, a floor that allows more with `widens` true, the same table again at a higher `seq` with `widens` false and `replaces` the held policy hash, one with `widens` false and another `replaces`, and a table that allows less with `widens` false and `replaces` the held policy hash are sent to a `mesh` PEP. An `agent` PEP is sent a floor it computes as larger with `widens` false. A held `cfs` PEP is sent a floor with `widens` true, then a local rollback, then a wider table with `widens` false and `replaces` the held policy hash | event `install-widened` with `dist:install-widened` twice, `install-applied`, `dist:widening-unsigned` three times, then `dist:widening-unsigned` on the `agent` PEP, then `install-widened` with bit 5 still set and a finding that waits for its acknowledgement, `dist:held` for the rollback, and `install-applied` on the signers' word | IS12, X9, H13, W2 | P C |
| 185 | A controller is handed a narrowing `agent` floor, a widening one, a `mesh` floor table that differs by one byte with `widens` false, a `cfs` floor whose core image allows less, an `install.trust` that adds a key, the empty ceiling, and a narrowing fallback policy. An acknowledger then acknowledges the widening floor by a release id, by 64 zeros, and by its envelope ids. A PEP reports `install-widened` for a set the controller never held, and the acknowledger later hands that set over and acknowledges it | the narrowing floor, the `cfs` floor and the fallback policy are offered at once, the widening floor, the trust statement and the empty ceiling are held with `dist:install-widened` open, the `mesh` table is refused as larger, the first two acknowledgements are refused and the third lets the floor be offered and its install id expected, and the last finding stays open until the hand over and then clears | H13, IS12, AF4 | P |
| 186 | A request the action floor allows is asked of a PEP whose active release refuses it, of a held `cfs` PEP, and of a PEP in `no-policy`, in `locked` and under the fallback policy | allowed each time with basis `floor` | AF1 | P R C |
| 187 | With a release that refuses each, an `agent` PEP is asked for a call its floor's `policy.core` allows through the hook and through the MCP proxy, and for a host in its floor's `egress.hosts`. Its running sandbox profile is read. A `gateway` PEP whose floor allows `read` on the class of one exact route is asked to read that path, to write it, and to read a path beside it. An `xdp` PEP whose floor holds two addresses is sent a packet to one of them and one to a third | allowed each time with basis `floor` and the profile is the one compiled from the release's policy and the floor's together, then allowed, silent and silent on the gateway, and passed and left to the release on `xdp` | AF1, AF9, IS3 | P |
| 188 | A request the action floor escalates is asked of a `cfs` PEP whose release allows it, and requests the floor refuses and cannot read are asked of a PEP with an active release, then of a PEP in `no-policy` with no fallback policy. A `mesh` PEP is asked for a request its floor does not allow | escalated with basis `floor` and the floor's cause, then the release's own answer each time, then `dist:policy-lapsed` each time, and the `mesh` floor is silent | AF2 | P R C |
| 189 | A PEP with an action floor sees its release expire, is sent a revocation of everything the authority signed, loses its floor of section 6, is sent every unsigned message type, sees the key that signed its floor retired, and runs ten years past the floor's `not_before` | the action floor allows the same request after each | AF3 | P R C |
| 190 | A PEP whose active release refuses a request its action floor allows is offered a renewal of that release, and a controller is given the renewal | committed with no widening statement, the floor still allows the request, and the controller offers the renewal as it would with no floor | AF4 | P R C |
| 191 | A `mesh` PEP with an action floor, a fallback policy and a ceiling at their bounds and no release decides a request the floor is silent on, and is then sent an action floor of 641 bytes | two sets are asked and no more, the three sets and both copies of the install record fit the store, then `dist:too-large` from the signed `body_size` | AF5, IS5 | P C |
| 192 | A `cfs` PEP whose action floor allows a command only when the monitor agrees is asked for it with the monitor's verdict good, then bad, with no release and no fallback policy | allowed with basis `floor`, then `dist:policy-lapsed` | AF6, AF2 | P C |
| 193 | A PEP writes a receipt for a floor allow where its release would allow, where it would refuse, where it would escalate, and with no release and no fallback policy. A `cfs` PEP writes its lines for a floor allow its release would refuse. An `xdp` PEP passes a packet by its floor's edge table | `would` is allow, refuse with the release's cause, escalate with its cause, each with the release's policy hash, and none, the override count rises by two, the `cfs` PEP writes one line in the floor's case and one in a case of the release marked not enacted, and the `xdp` PEP counts the floor allow and records no `would` | AF7, RC1 | P R C |
| 194 | A `cfs` PEP whose floor has two rules and a rate of 3 in 60 seconds is asked for the first rule's action, which its release refuses, five times in one window with a restart after the second, for the second rule's action once, for an action the release allows ten times, and for the first again in the next window. A `mesh` PEP with the same rate is asked five times, an `xdp` PEP is sent a floor with a `rate`, and a release with a `not_before` two windows ahead arrives in mid window | allowed three times and escalated twice with `dist:floor-rate` and basis `floor` with the restart changing nothing, allowed, allowed ten times with no count, allowed again, on `mesh` the last two are decided by the release, `dist:bad-format`, and the window ends early | AF8, AF5 | P C |
| 195 | A `mesh` and a `host` PEP with a fallback policy each see their release expire, have their active release revoked, start with nothing committed, and lose their floor of section 6 | the fallback policy decides each time, event `fallback` with `dist:expired`, `dist:revoked`, `dist:fallback` and `dist:floor-lost`, bit 4 set, status 0 three times and 2 once, zeros for the active hash, and no decision is `dist:policy-lapsed` | FB1, FB2, FB3 | P R C |
| 196 | A `host` PEP with a fallback policy lapses, and an `agent` PEP with one lapses. The same two with none lapse | the host runtime decides under the fallback `policy.ppt` and the hook, the egress proxy and the MCP proxy of the agent home all read the fallback set, then the host withdraws its policy and every part of the agent home refuses | FB1, X3 | P |
| 197 | A PEP with an action floor and no fallback policy sees its release expire | `no-policy`, event `lapsed`, `dist:expired`, bit 4 clear, and every request the floor is silent on is `dist:policy-lapsed` | FB1, X3 | P R C |
| 198 | A PEP goes to its fallback policy on a medium where every frame it sends is recorded | it sends its state record and nothing else, and no command leaves it that was not proposed to it | FB4 | P C |
| 199 | A PEP under its fallback policy is sent a release with no widening statement, one with a statement whose `from` holds the fallback policy's hash, and one with a statement whose `from` is empty, and a `locked` PEP under its fallback policy is sent a good release and is then provisioned | `dist:widening-unsigned` twice, then `committed` with bit 4 clear, and the `locked` PEP admits no release and decides under the fallback policy until the provisioning | FB5, FB2 | P R C |
| 200 | A `cfs` PEP with HOLD and a fallback policy sees its release expire, and is then sent a revocation of that release | held with bit 5 set and bit 4 clear, then the fallback policy with bit 4 set and bit 5 clear and event `fallback` with `dist:revoked` | FB6, X7, X8 | P C |
| 201 | A cut off PEP with a fallback policy holds a release until it expires, then runs a year with no message | it decides under the release until `expires`, then under the fallback policy for the whole year | FB7, X2 | P R C |
| 202 | A PEP under its fallback policy is sent a narrower one and then a wider one, and a PEP with an active release is sent the wider one | the first decides under each at once with bit 4 still set, the wider one with event `install-widened`, and the second holds it with the same event while its release keeps deciding | FB8, IS12 | P R C |
| 203 | An `agent` PEP with a ceiling is offered a release whose policy allows a reading the ceiling refuses, one with a host the ceiling's `egress.hosts` lacks, one that drops a name the ceiling's `agent.zones` protects, and one inside the ceiling. A `gateway` PEP with a ceiling is offered a route table that gives one path another class than the ceiling's, and one that names fewer routes. A `mesh` and a `cfs` PEP with a list are each offered a table whose body hash is on it and one off it, the `cfs` one with the listed core image and other rules, then a floor table off the list, then a list that adds that floor's hash with `widens` false and with `widens` true, then the floor again. A controller that holds each ceiling is given the same releases | `dist:above-ceiling` three times, staged, `dist:above-ceiling`, staged, then staged and `dist:above-ceiling` on each, `dist:above-ceiling` for the floor, `dist:widening-unsigned` and `install-widened` for the lists, then the floor is applied, and the controller refuses to offer the releases above | CL1, CL2, IS12 | P C |
| 204 | A release inside the ceiling is staged, a narrower ceiling it is above is applied, and the release is committed. The same with a kept release and a rollback | the staged and the kept release are still held after the ceiling is applied, then `dist:above-ceiling` at the commit and at the rollback and each is dropped | CL2, C3, RB2 | P R C |
| 205 | A PEP with a ceiling is sent an action floor above it, a fallback policy above it, and a ceiling its held floor is above. Then it is sent a ceiling its active release is above with `widens` false, once with a fallback policy and once without. An `agent` PEP whose ceiling protects a name is asked for a call on that name that a floor rule testing `zone_reach` allows | `dist:above-ceiling` three times with nothing changed, then the ceiling is applied with event `install-widened` and the release lapses with `dist:above-ceiling`, to the fallback policy and to `no-policy`, and the floor is silent for the call | CL3, IS12, AF1 | P R C |
| 206 | An `agent` PEP with a ceiling is offered a release whose rule names a tool the ceiling's fields do not define, a ceiling whose fields define a tool the PEP was not built with, and an `agent` PEP with no ceiling the first release | `policy:out-of-domain` twice, then judged by the domain the PEP was built with | CL4 | P |
| 207 | One PEP writes a receipt for a request its release allows, one its release refuses, one the action floor allows, one the fallback policy allows and one it refuses, and a PEP with no fallback policy writes one for a request it refuses in `no-policy` | basis `release` twice, `floor`, `fallback` twice, each with the policy hash of the set that decided, then no basis and `dist:policy-lapsed` | RC1 | P R C |
| 208 | A held PEP writes a receipt for a request its release allows and for one the action floor allows, in a receipt format with a cause field | `release` with the hold mark, then `floor` with the hold mark and `dist:floor-allowed` | RC2, RC3 | P C |
| 209 | A cFS core run with a case for each basis, its not enacted lines and its `rates.jsonl`, whose floor changed across an `install.trust` that dropped a key, at an install threshold of 2, is verified with the authority key and the starting install key set pinned. Then with a floor receipt moved to the release's case, with a `would` line whose outcome is changed, with a rate count that skips a number, with the `install.trust` left out, with a floor case that has one signature, and with no install key pinned | verified, then refused six times | RC4, RC3, AF7 | P |
| 210 | A `mesh` PEP with install statements sends a record after three floor allows of which one was an override, one after none, one after a restart, and one after it applied a new action floor | a type 3 extension of 27 bytes with its install id, the low bits of its install trust sequence, counts of 3 and 1 that never go down, then event `install-applied` with subject 1 and another install id, each in one frame of 246 bytes with no type 1 or type 2 entry | H10, H1, B10 | P C |
| 211 | A controller receives records with bit 4 and zeros for the active hash from a PEP enrolled with a fallback policy whose release lapsed, then one without the bit, one with bit 4 from a PEP enrolled with none, one with bits 4 and 5, one whose install id is not the expected one, one with no type 3 where one is expected, and one with counts of floor allows and overrides | `dist:fallback` open with no `fleet:policy-mismatch` then cleared, `fleet:state-invalid` twice, `fleet:policy-mismatch` twice, and the counts file nothing | H11, H12, H6 | P |
| 212 | An `agent` PEP and the sealing tool are each given an action floor whose policy allows what no rule matched, one whose rule allows every tool of a category, one whose rule tests `tool` only in one branch of an or, one that allows `tool` `unknown`, one that allows `run_command` with no test of `command_class`, one that allows `write_file` with no test of `path_scope`, one that allows it with `path_scope` and no `path_control`, one with nine allowing rules, one whose `egress.hosts` has a wildcard, and one with nine hosts. Then one with eight rules, of which one allows `run_command` with `command_class` `read_only`, and the PEP is asked for a read only command and a mutating one | `dist:floor-broad` ten times at both, then applied and sealed, and the first command is allowed with basis `floor` while the second is left to the release | AF9, IS5 | P |
| 213 | A `mesh`, a `cfs` and a `host` PEP are each sent a floor table whose outcome with no matching edge is the allow, one with an edge to the allow that tests no command, one with two decision nodes, one with nine allowing edges, one whose `command` names a register the layout does not label, one that allows a command with no bound on a parameter, one whose bound on a parameter is the field's whole domain, one whose `layout` is another layout's hash, and one with eight edges that each test one command and bound each parameter. Each PEP is then asked for that command inside and outside the bound | `dist:floor-broad` seven times, `dist:target-mismatch`, then applied, allowed with basis `floor` and left to the release | AF9, AF10 | P R C |
| 214 | An `agent` PEP whose release protects the zones `keys` and `ledger` is asked for a `write_file` call that reaches `keys`, so its reading has `zone_reach` `protected` and `zone_name` `keys`. First with a floor rule that allows `write_file` and tests no zone, then with one that tests `zone_reach` alone, then with one that tests `zone_reach` and `zone_name` `ledger`, then with one that names `keys`, then with that rule and a call that reaches both zones. A floor that newly names `keys` and drops two tools is sent with `widens` false | silent with the call refused as the release says three times, then allowed with basis `floor` and the zone override mark naming `keys`, then silent because `zone_reach` is `unknown`, and the new floor is `dist:widening-unsigned` | AF1, IS12, RC1 | P |
| 215 | A PEP with a ceiling starts with every copy of the ceiling unreadable, is offered a release, told to roll back and sent an action floor, and is then sent a ceiling at a new `seq`. A PEP that held a ceiling starts with its install record unreadable and is offered a release | event `refused` with `dist:install-lost`, its release keeps deciding, the offer, the rollback and the floor are `dist:install-lost`, then the ceiling is applied and a release inside it stages. The second PEP refuses the release with `dist:install-lost` until it is provisioned | IS10 | P R C |
| 216 | A `cfs` PEP whose layout marks `monitor_ok` independent with a staleness bound of 5 seconds and `ground_contact` as the proposer's is sent a floor whose rule tests `ground_contact`, then one whose rule tests `monitor_ok`. The second is asked with a proposal that claims the monitor agrees while the monitor's own message says it does not, then with the monitor's last message 6 seconds old, then with none ever received. A layout with a staleness bound of 0 is given to the sealing tool | `dist:floor-broad`, applied, then the floor is silent three times, and the tool refuses the layout | AF10 | P C |
| 217 | An `agent` set arrives without its `agent.zones` while the signed release id covers one, and a set whose signed release id covers none arrives with a stray `agent.zones` statement of another release id | not applied until the zones statement arrives and the computed release id is the signed one, and the second is applied without the stray statement, which is `dist:incomplete` | IS4 | P |
| 218 | A PEP is sent an `install.trust` that adds a key with `widens` false, one that lowers the threshold with `widens` true, and a floor at a higher `seq` with the same policy and a looser `rate` and `widens` false | `dist:widening-unsigned`, applied with event `install-widened`, `dist:widening-unsigned` | IS11, IS12, AF8 | P R C |
| 219 | A PEP is provisioned with a first action floor and its `provisioned` record reaches the controller before the PEP is enrolled, then it is enrolled, and three `mesh` PEPs of one group are sent a new floor that one of them refuses | the record is kept and not filed, then at the enrollment it carries `dist:install-widened` and the enrollment clears it, then two PEPs apply and one does not, with no abort and three install ids that show the mix | H13, H6, IS4 | P C |
| 220 | A `cfs` PEP with an install threshold of 2 escalates a floor action with `dist:floor-rate`. It is then sent an answer `allow` signed by an enrolled operator key, the same answer again, and the same again after a restart. Other escalations are sent an answer signed by an install key, one signed by an authority key, one whose lifetime is 601 seconds, one that arrives after `expires`, one whose `receipt` names no escalation, one for an escalation older than 600 seconds, an unsigned message that claims to be an answer, and an answer `refuse` | the request passes once and leaves a receipt with basis `operator`, the answer's envelope id and the escalation's hash, then `dist:answer-unbound` twice, then `dist:unknown-key` twice, `dist:bad-format`, `dist:expired`, `dist:answer-unbound` twice, nothing for the unsigned one, and the last request stays refused with its own `operator` receipt | OP2, OP3, AF8 | P C |
| 221 | An anchor enrolls one operator key, an `install.trust` adds a second with `widens` false and then with `widens` true, one tries to add a key that is an install key, and an operator key signs an install statement and a release | enrolled, `dist:widening-unsigned`, applied with event `install-widened` and held at the controller for its acknowledgement, `dist:rotation-invalid`, and `dist:unknown-key` twice | OP1, IS11, H13 | P R C |
| 222 | An `agent` PEP whose release protects `keys` lapses, once with a ceiling whose `agent.zones` protects `ledger`, once with a ceiling that has no `agent.zones`, and once with a restart after the lapse. Each time it is asked to write `keys` and `ledger` | with the ceiling's zones `ledger` is protected, with none the release's `keys` stays protected, and the restart changes nothing | FB9 | P |
| 223 | A `host` PEP is sent a floor whose `meta` carries `counts` that differ from the table, one with no `qualification`, and one whose members are those of its `policy.ppt`. An `xdp` PEP is sent a floor whose `net.edge` statement lacks `names_sha256`, and a `mesh` PEP a floor whose `meta` holds `counts` as a string | `manifest:count-mismatch`, `dist:bad-format`, applied, `dist:bad-format`, and applied on `mesh`, which skips it | IS1, IS5 | P R C |
| 224 | An anchor whose operator key is an authority key, one whose operator key is an install key, a `trust.rotation` whose `add` is an operator key and one whose `add` is a retired operator key, an `install.trust` that puts one key in `keys` and in `operators`, one that adds to `operators` a key the PEP retired as an install key, and one that drops an operator key and then one that adds it again | refused at provisioning twice, then `dist:rotation-invalid` four times, applied with the operator key retired, and `dist:rotation-invalid` | K4, O4, IS11 | P R C |
| 225 | A `host`, a `mesh` and an `xdp` PEP are each sent a well signed `operator.answer`, and a `cfs` PEP with an install threshold of 2 and an open floor escalation is sent a good answer whose `not_before` is above its time floor | `dist:target-mismatch` three times, then the answer is applied and the time floor does not move | V5, V13, OP1, OP2 | P R C |
| 226 | A `cfs` PEP whose second copy of its install record is in a Critical Data Store area loses the file that holds the first, and a `host` PEP with one file system loses both copies on it | the `cfs` PEP uses the second copy and holds its sets, and the `host` PEP holds no set, reports `dist:install-lost`, keeps deciding under its release, and takes no install statement by message and no release until it is provisioned | IS10 | P R C |
| 227 | A PEP with an install threshold of 1, a floor of section 6 at 7, a time floor a day ahead of its clock and an action floor at `seq` 2 is given an install provisioning with an action floor at 3, then the same again, then one with a floor at 2. It is then offered a release at `seq` 6, and a `locked` PEP is given an install provisioning | the floor at 3 is applied with event `install-applied` and the floor of section 6, the trust sequence and the time floor are unchanged, then unchanged, then `dist:seq-replay`, the release is `dist:seq-replay`, and the `locked` PEP takes the floor and stays `locked` | IS13, IS6, P3 | P R C |
| 228 | A `host` PEP with a release and an action floor decides two requests by its release and one by its floor and sends a record, then lapses to its fallback policy, decides a request and sends a record. A controller is then given a record with bit 4 set and a body that is not empty | the first body has two frames under the release's preamble, the second has length 0, and the third is `fleet:policy-mismatch` at step 4 | H5, H6, H11 | P |
| 229 | An `agent` PEP is sent a floor whose rule tests `zone_name` as not equal to `keys`, and one whose rule names a zone name the zone point cannot read. A release whose rule allows `write_file` where `zone_name` is `keys` is then offered over one that allows it where `zone_name` is `ledger`, with `widens` false | `policy:out-of-domain` twice, then `dist:widening-unsigned`, since the walk finds `keys` allowed where it was not | AF1, W1, W6 | P |
| 230 | A PEP is given a `/1` anchor that holds an `install` member, a `/2` anchor whose `domain` is not the hash of the domain the PEP was built with, and a good `/2` anchor, and is then sent a release signed by one of its install keys | refused at provisioning twice, then provisioned with the install keys in the install record and none in the trust store, and the release is `dist:unknown-key` | P4, CL4, K3, K4 | P R C |
| 231 | A `cfs` PEP with an install threshold of 1 is sent a well signed answer, and one with a threshold of 2 is sent an answer whose `pep` is another PEP's id. Two `cfs` PEPs then write receipts of the same bytes for one escalation each, and an answer for the first is sent to both | `dist:target-mismatch`, `dist:answer-unbound`, then applied on the first and `dist:answer-unbound` on the second | OP1, OP2 | P C |
| 232 | A `cfs` PEP whose floor has an `answer_rate` of 2 in 600 seconds gets three good `allow` answers for three open escalations and a restart after the second, then a `refuse`. An `agent` PEP is sent a floor that can escalate and has no `answer_rate` | applied twice, each with a record with event `answered` and subject 5 that the fleet view shows, the restart changes nothing, the third is `dist:floor-rate` and its escalation stays open, the `refuse` is applied, and `dist:bad-format` | OP4, H1, AF8 | P C |
| 233 | A PEP with an install threshold of 1 and two operator keys is given an install provisioning that carries an `install.trust` which drops one of them, then that key signs an answer | applied with the key retired, its trust state and floor unchanged, and the answer is `dist:target-mismatch` as the threshold is 1 | IS13, IS11 | P R C |
| 234 | A PEP that never held an install statement refuses an older signed form on a stream, is provisioned again, and is then sent that form on the same stream | `dist:legacy-refused` both times | L2, P3 | P R C |
| 235 | A PEP is given an anchor whose `keys` holds an entry in the role `install`. A PEP that holds an install record is given a `/1` anchor, then a `/2` anchor with no `install` member, then a `/1` anchor whose authority key is a held install key, then one whose authority key is an operator key it retired | `dist:bad-format`, then provisioned twice with the install record, its sets and its sequences unchanged, then refused twice | P4, P2, K4 | P R C |
| 236 | A PEP is given an anchor whose operator key is its instance key, one whose install key is also an operator key, and one whose install key is the instance key | refused at provisioning three times and the PEP is unchanged | P2, K4 | P R C |
| 237 | An `agent` PEP stages a fallback set whose release id covers an `agent.zones` that has not arrived, is then given a ceiling the staged set is above, and the zones statement arrives | the ceiling is applied, then the set is dropped with `dist:above-ceiling` at apply and the held fallback policy still decides | IS4, CL3 | P |
| 238 | A controller holds a PEP's last counter at 40 and the PEP is enrolled again. It is then given that PEP's record at counter 39, and, before another PEP is enrolled, four forged `provisioned` records for its id and the real one, and later 64 forged ids that push the real record out | `fleet:state-replay`, then the real record is the one used at enrollment, and after the flood the enrollment still acknowledges the install id and the next record shows it | H6, H3, H13 | P |
| 239 | Seventeen authority keys and nine install keys are retired, then the sealing tool and a controller are given a rotation and an `install.trust` that add back the first of each | the PEP no longer holds those ids, and the tool and the controller refuse both | K4, K5, IS11 | P |

## 21. The action floor, the fallback policy and the ceiling

Refusing is not always the safe answer. On a spacecraft, an industrial controller or a medical device, a
PEP that refuses everything when its policy lapses also refuses the command that enters safe mode and the
commands that recover a vehicle out of contact. The engineer who installs PrismPath on a resource defines
the bounds that resource runs within, and the policies of the process owners decide inside those bounds.
This section defines three bounds. The action floor is what is always allowed, or always sent to a
person. The fallback policy is what a PEP decides under when it has no release. The ceiling is what no
release may allow. The engineer signs all three with install keys, all three are per target, and nothing
the authority signs changes any of them. Every target kind may have them, and a PEP that has none refuses
as before.

The owner decided these on 2026-11-23, and the rules below carry them out. Every kind takes install
statements. An install statement can change over the transport on a stream whose install threshold is 2
or more, and only by provisioning otherwise. A widening of an install set stands out and is acknowledged.
A floor allow records what the release would have decided, and the engineer may sign a rate for it. The
fallback policy decides while a PEP is `locked`. A cFS core run has one case per basis.

This section leans on the reading domain and the table order of section 9.4 and on cause 160,
`policy:out-of-domain`, which the widening change brought.

Two notes on words. Everywhere else in this spec the floor is the sequence floor of section 6, and the
bound defined here is always written **action floor**. The fallback policy is not a safe state. A
machine's safe state is physical, such as a mower that has stopped, and a machine can be in it with a
release active. The fallback policy is only what decides when no release does.

### 21.1 The install statement

**IS1.** An install statement is a sealed envelope (section 4) whose `artifact` is an install kind. They
are `install.floor`, `install.fallback`, `install.ceiling` and `install.trust`. For the first three the
body is one artifact a release of the target kind holds, and `meta` names that artifact in `as`.
`targets` names exactly one kind and `stream` is the stream of the PEP it is for. `policy_sha256` is the
policy hash of the set and `release` is the release id of E10 taken over the `[as, body_sha256]` pairs of
the set. For the list of a ceiling (CL1) `policy_sha256` is the SHA-256 of the list. `replaces` and
`widens` are the signer's honest statement about the set this one follows (IS12).
`expires` is 0 (E5, X4). `seq` is the install sequence of that install kind on that stream. It is the
engineer's own count and has nothing to do with the floor of section 6. Any other value is
`dist:bad-format`. An install set is every statement that shares the install kind, the stream, the `seq`
and the release id, and it holds exactly the artifacts IS3 gives its kind. The one exception is the
empty set, a single statement whose `as` is `none`, whose body is empty and whose `policy_sha256` is 64
zeros. It withdraws the set of its install kind (IS6). The set id is the SHA-256 of the envelope ids of
the set, sorted, as raw bytes. It covers `meta`, which the release id does not, so it is the name a
record and an acknowledgement use for a set (H10, H13). The `meta` of an install kind also carries the members section 3 gives the artifact that `as` names,
such as `fields`, `counts`, `wcet_cycles`, `qualification` and `packing` for a `policy.ppt` and
`flow_sha256`, `names_sha256` and `qualification` for a `net.edge`, because the check of that artifact
reads them. Every reader reads `as`, `layout`, `command`, `rate` and `answer_rate` of an install kind, the `mesh` and
`cfs` readers too, and those two skip the rest as E9 says.

**IS2.** An install statement is signed by install keys, which are the keys a PEP holds in the role
`install` (K4). The anchor brings the first ones with the install threshold (P4). There are 1 to 4
install keys, and the install threshold is from 1 to their number. S4 counts an install statement against
the install threshold and never against the authority's. A stream whose install threshold is 1 takes
install statements by provisioning only (IS4). The two roles are strictly apart. An install key signs
install kinds and nothing else, and an authority key never signs an install kind. So a release, a
widening statement, a revocation or a rotation signed only by install keys is `dist:unknown-key`, and so
is an install statement signed only by authority keys. No key is ever held in both roles (O4, IS11). An
anchor that holds one key in both roles, or whose install key is the PEP's instance key, is refused at
provisioning, as K2 refuses its like.

**IS3.** Every target kind takes install statements. A PEP may hold an action floor, a fallback policy
and a ceiling, any of them or none, and one that holds none keeps plain refusal (X3). The form follows
the kind. A set for `host` is a `policy.ppt`, with a `policy.spiral` when it declares packing. A set for
`agent` is a `policy.core` and an `egress.hosts`, with an `agent.zones` when zones are declared. A set
for `gateway` is a `policy.core` and a `gateway.routes`. A set for `xdp` is a `policy.core`, a
`net.dests` and a `net.edge`. A set for `mesh` is a `policy.ppt` and one for `cfs` a `cfs.table`. Two
things differ from a release. An action floor never holds an `agent.zones`, since a zone protects and a
floor only allows, and one that does is `dist:bad-format`. A ceiling for a kind that cannot decide is a
policy list (CL1). HOLD is still for `mesh` and `cfs` alone (X6).

**IS4.** An install statement always arrives by provisioning (P4). It also arrives in an `install`
message, a `stage` of an install kind, on a PEP whose install threshold is 2 or more. On a PEP whose
install threshold is 1 an install kind in a message is `dist:target-mismatch` whatever its signatures. A
message travels as any sealed envelope does, in the transfers of the frame binding and in the `offers` of
the HTTP binding, so there is no new frame. A PEP applies an install set when every statement of it has
passed IS5 and the set is whole, and it needs no `commit`. Until then the PEP stages each statement as
G1 stages an envelope, durably, with `stage-ack` and event `staged`, whose subject byte names the install
kind (H10). Bit 7 of `status` stays for a release. A set at a higher `seq` of the same install kind
replaces the staged one as G2 says, and one at a lower `seq` is `dist:seq-replay`. A staged statement
survives a restart, as a staged envelope does. A set is whole when the release id the PEP
computes by E10 over the statements it holds is the signed `release`. At apply the PEP holds the set to
the ceiling it holds at that moment (CL3), as C3 holds a release at commit, since a ceiling may arrive
while the set is staged. A set that is not inside it is dropped with `dist:above-ceiling`. That is what settles an artifact
the kind needs only sometimes, such as an `agent.zones`. A PEP applies a set on its own. There is no
group commit for install sets (F3), so a fleet can be mixed while a set spreads, and the install ids show
it. The set is durable before the PEP reports its event (IS12), and a
refusal reports `refused` with its cause. A PEP stages at most one set per install kind, inside the
artifact bounds of its kind. Until a set is applied the PEP decides under what it held, and no part of a
PEP reads a mix of two sets. A `commit` or an `abort` that names an
install set changes nothing.

**IS5.** A PEP checks an install statement with the verifier it has, in the order of V1, with these
differences. V3 counts install keys against the install threshold (IS2). V5 takes an install kind on the
PEP's own stream as one the PEP uses, subject to IS4, and holds the body to the artifact bound of the
kind, or to the trust bound for a policy list and an `install.trust` (E6). V6 applies T3 where the PEP
has a clock, and an install statement never raises the time floor (T1, V13), so install keys cannot
expire a release. V7 does not apply, because the authority's revocation list is never read against an
install kind (IS7). V8 is IS6, or IS11 for an `install.trust`. V10 holds the statements of one set to one
stream, `seq`, policy hash, release id, `replaces`, `widens` and `rate` (`dist:incomplete`). V11 is the
check section 3 gives the artifact that `as` names, with a derived artifact compiled from the other
bodies of its own set, then the narrowness of an action floor (AF9), and then the ceiling (CL3). The
empty set has no check beyond IS1. V12 is IS12. On `mesh` and `cfs` the C core checks an
install statement in the one pass it checks any sealed envelope in, and the one new format it reads is
the bounded canon/2 list of a policy list or an `install.trust`, which is the shape of a revocation list.

**IS6.** A PEP keeps one install sequence for each of its action floor, its fallback policy and its
ceiling, and nothing lowers one. It takes a set only at a `seq` above the one it holds for that install
kind. A lower `seq`, or the same `seq` with another set id, is `dist:seq-replay`, and the same statement again
changes nothing. The empty set (IS1) at a higher `seq` withdraws the held set of its kind, and the PEP
then holds none of that kind at that `seq`. That is how the engineer withdraws an action floor, a
fallback policy or a ceiling, and how a superseded set is kept from coming back to a PEP that took it. The numbers need
not be consecutive, since each set replaces the one before whole. A provisioning follows the same rule,
and one that brings no set of an install kind leaves the held one in place. The anchor carries the
install trust sequence its install keys stand at (P4). A provisioning whose install trust sequence is
below the PEP's is `dist:trust-replay`, and one at the same number must bring the same key set. A provisioning with a higher install trust sequence may bring another key set. Every key it leaves out
is retired, and the install trust id becomes the fingerprint of that anchor (IS10). It starts the install
sequences again only when its key set shares no key with the held one, so that no statement signed under
the old set verifies again. Such a provisioning also drops every held set it does not bring, since
nothing the PEP then trusts signed them. A set that was lost (IS10) comes back only at a new `seq`. That is the recovery from install keys in the wrong hands. A
`locked` PEP still takes install statements, because its install record is kept apart from the store it
lost (IS10).

**IS7.** The two chains never touch. A `trust.rotation` adds a key in the role `authority` only, and one
whose `retire` names an install key is `dist:rotation-invalid`. A `trust.revocation` whose `keys` holds
an install key id does not revoke that key, and its `envelopes` and `policies` are never read against an
install kind. The sealing tool refuses to write, and a controller refuses to store, a revocation list
that names an install key id. An `install.trust` never adds, retires or revokes an authority key. Neither
chain waits for the other. A PEP behind on the authority's trust chain is still offered install
statements, and a PEP behind on the install trust sequence is still offered releases (F6).

**IS8.** A controller holds no install private key. It holds the install keys of each stream it serves,
runs the verifier of IS5 on every install statement it is handed, refuses to store one that fails, and
offers the rest subject to H13. It offers a PEP the install trust statements it lacks, in order, before
any install set, and reads what the PEP lacks from its state record (H12). At P2 step 4 the PEP prints
the envelope id of each install statement beside the fingerprint of the anchor, and at step 5 its install
id (H10) is enrolled. The `provisioned` audit event of P3 and every `install-applied` and
`install-widened` event name the envelope ids of the install statements the PEP then holds.

**IS9.** A PEP that has ever held an install statement refuses the older signed forms of section 17 on
every stream with `dist:legacy-refused`, whether or not it has committed a release (L2). An older form
knows none of the three bounds. The PEP keeps this as a mark in its anchor part, outside the install
record, and sets it before it applies its first install statement. So a lost install record does not
reopen the older forms, and no later provisioning does.

**IS10.** The install record is the install keys with their threshold, the operator keys (OP1), up to 8
retired install and operator key ids, the install trust sequence, the install trust id, the three install
sequences, the set id and envelope ids of each held set, and the rate counts of AF8. The install trust id is the
envelope id of the latest `install.trust` the PEP applied since it was last provisioned, or the
fingerprint of that anchor when it has applied none. A PEP keeps
the install record and the held statements apart from the store Q5 can lose, and keeps two copies of the
record, which is under 1,024 bytes, on two media where it has them. On a `mesh` node the second copy is
in a second NVS partition, on `cfs` in a Critical Data Store area apart from the file, and on a host on
a second file system where the deployment gives one. A PEP with one medium only keeps both copies there,
and one loss of that medium takes both. It is then a PEP with no copy of its install record that reads,
as the end of this rule says. At every start the PEP checks that each held statement is the one its
install record names and that each body has the signed hash. It does not check the signatures again,
since a key retired later does not remove what it signed (AF3). A PEP may keep more than one copy of a
statement and uses the first copy that passes. When none passes, the set is lost. The PEP reports event
`refused` with `dist:install-lost` and leaves the set out of its install id (H10). A lost action floor or
fallback policy leaves the PEP deciding as one that never had it. A lost ceiling does not fail open. The
PEP keeps the release it has, which was inside the ceiling when it was committed, and stages, commits
and rolls back nothing, with `dist:install-lost`, until it holds a ceiling again. While the ceiling is lost the action floor and the fallback policy are frozen too. The PEP takes no
install set but a ceiling, since it has nothing to hold one inside. It knows it had a ceiling by a mark
in its anchor part, beside the mark of IS9. A PEP with no copy of its install record that reads
holds no install set, reports `dist:install-lost`, takes no install statement by message and no release
until it is provisioned, and keeps deciding under the release it has. A PEP never decides under a body it
cannot verify.

**IS11.** An install trust statement is a sealed envelope with artifact `install.trust`. Its `stream` is
the PEP's stream, `targets` is written and not checked, as on `@trust` (V5), `policy_sha256` and
`release` are 64 zeros, `replaces` is empty, `meta` is empty and `expires` is 0. `widens` is `true` when
the statement adds a key of either role or lowers the threshold, and `false` otherwise. A PEP computes this itself and refuses a wrong `false` with `dist:widening-unsigned`. `seq` is the install trust
sequence, taken only at exactly one above the one the PEP holds, as R1 takes a trust statement, and any
other is `dist:trust-replay`. The body is this canon/2 document.

```json
{"encoding":"canon/2","format":"prismpath.dist-install-trust/1","keys":["<64 hex digits>"],
 "operators":["<64 hex digits>"],"threshold":2}
```

`keys` is sorted and holds 1 to 4 public keys, and a longer list is `dist:too-large`. `threshold` is from
1 to the number of keys. `operators` is sorted and holds 0 to 4 operator keys (OP1). The statement is accepted only when it is signed under the
install key set as it is now, at the threshold as it is now, and by every key it adds, which is the rule
of O2. An added operator key signs too, so it is shown to be held. Fewer signatures by current keys is
`dist:unknown-key`, and a missing signature of an added key is `dist:rotation-invalid`. A sealed envelope holds four signatures (S2), so a statement that would need
more, such as one that adds a key to four keys at a threshold of 4, cannot be sealed. The engineer makes
such a change in two statements, the first of which drops a key or lowers the threshold. An install key
or an operator key the new statement leaves out is retired. A signature by a retired key never counts
again (S5) and a retired key is never added again in any role (K4). When a ninth key is retired the
oldest id is forgotten, as in K5. A key the statement adds is never the PEP's instance key, a key the
trust store holds or has retired, or a key id on the revocation list. A key it adds to `keys` is never an
operator key, a key it adds to `operators` is never an install key, and no key is in both lists. Each is
`dist:rotation-invalid`. The statement is applied as soon as it verifies,
durably before its event. It is the rotation, the revocation and the withdrawal of the install role in
one statement, and a statement that lowers the threshold to 1 closes the stream to install messages.

**IS12.** A widening of an install set stands out. The signer sets `replaces` to the policy hash of the
set this one follows, or leaves it empty for the first, and sets `widens` to `true` when the set allows
or escalates more than that one, by the order of section 9.4. A first action floor and a first fallback
policy widen. A looser `rate` or a removed one widens, and every PEP can compute that. The comparison is of the
answers a PEP would give after the overlay of AF1, so a floor that overrides a zone the one before did
not is larger whatever else it drops. A list that holds a hash the one before did not is larger, and a
small PEP compares two lists itself. A first ceiling
does not widen, a ceiling that allows more does, and so does the empty ceiling (IS6). The empty floor
and the empty fallback policy do not widen. A PEP that can decide computes all of it, and refuses a set
it computes as larger whose `widens` is `false` with `dist:widening-unsigned`. A PEP that cannot decide,
which is `host`, `mesh` and `cfs`, takes `widens` `false` only when `replaces` is the policy hash of the
set it holds, and refuses any other with `dist:widening-unsigned`. A `host` and a `mesh` PEP also
compare bytes, as W2 does. A table that is not byte for byte the one of the set it holds is larger, and
they refuse it with `dist:widening-unsigned` when its `widens` is `false`. Only a `cfs` PEP takes the
signers' word beyond the `replaces` test, and for `cfs` the comparison is the duty of the sealing tool
and the controller (H13). A set that widens is applied on its install signatures with event
`install-widened` and cause `dist:install-widened`. A ceiling that lapses the PEP's active release
(CL3) is reported the same way whatever its `widens` says, because it hands the PEP to its fallback
policy. Every other set is applied with event `install-applied`. A held PEP takes a set that widens as
any PEP does (X9), and the widening waits for its acknowledgement all the same (H13).

**IS13.** An install provisioning brings install statements and no anchor. It is how the engineer
replaces an action floor, a fallback policy or a ceiling on a PEP whose install threshold is 1, by the
channel of P2 step 3. Each statement is held to IS5 and IS6 as any install statement is, and the set is
reported with the event IS12 gives it. P3 does not apply. The trust store, the trust sequence, the floor
of section 6, the time floor, the epoch id and the PEP's state stay as they were, and a `locked` PEP stays
`locked`. It may carry an `install.trust`, held to IS11, that removes an operator key, which is how the
engineer takes one back on a PEP whose install threshold is 1. It is written to the audit log as a
provisioning.

### 21.2 The action floor

**AF1.** A PEP that holds an action floor asks it first on every request, in every state. Each part of
the PEP that decides asks the floor's own artifact before the release's. The hook and the MCP proxy ask
the floor's `policy.core`, the egress proxy the floor's `egress.hosts`, the gateway the floor's routes
and policy, and the XDP program the floor's edge table. An `agent` home compiles its running sandbox
profile from the policy in force and the floor's together, so the sandbox never blocks what the action
floor allows. A zone yields to the action floor only where a floor rule names it. The reading of an `agent` call
carries `zone_reach`, which is `none`, `protected` or `unknown`, and from this version `zone_name`, the
one `agent.zones` name the call reaches. `zone_name` is empty when the call reaches none, and when it
reaches more than one `zone_reach` is `unknown`. For section 9.4 and cause 160 the domain of
`zone_name` is the empty name and every name an `agent.zones` can hold. A rule tests it only for equality
with one name, and a rule that tests it in any other way, or names a value that is not a name the zone
point can read, is refused with `policy:out-of-domain`. The walk of 9.4 needs no list of every name,
because a rule only tests equality. It takes the empty name, each name that either compared set tests,
and one name that neither tests, which stands for every other name. A floor rule answers a call whose `zone_reach` is
`protected` only when it tests `zone_reach` for equality with `protected` and `zone_name` for equality
with one name, both as conjuncts of the whole rule. The answer is marked as a zone override on its
receipt, with the name (RC1). A floor has at most 8 rules, so it overrides at most 8 zones. Every other
floor rule is silent for such a call, and every floor rule is silent when `zone_reach` is `unknown`,
which includes a call whose reach of the ceiling's names cannot be told. A name the ceiling's
`agent.zones` protects is never overridden. The hook asks the ceiling's names first and the floor is
silent for a call that reaches one (CL3). When the action floor answers,
nothing else decides. That holds while a release is active, while the PEP is held (X7), in `no-policy`,
in `locked` and under the fallback policy.

**AF2.** The action floor answers in two ways. An allow is allowed. An escalation is escalated with the
floor's own cause, so the engineer can sign that a request is always put to a person or a remote
operator. Any other outcome, a refusal or a request the floor cannot read, means the floor is silent. The
decision is then made exactly as it would be with no action floor, and the floor's refusal cause is never
reported. A kind whose policy form has no escalation, which is `host`, `mesh` and `xdp` and the host list
of an `agent`, has only the allow.

**AF3.** The action floor never lapses. It has no expiry. Nothing the authority signs reaches it (IS7), a
lost floor of section 6 does not take it (IS10), an install key retired later does not remove it (IS11),
and no unsigned message changes it (IS4). Only the engineer changes it, with an install set or the
empty set at a higher `seq`, or with a provisioning (IS6, IS13).

**AF4.** A release cannot narrow the action floor and is never checked against it. A release that refuses
what the action floor allows is staged and committed under the rules it would meet with no action floor,
and the action floor still allows the request. The widening rule of section 9.4 compares a release with a
release and never counts the action floor, at a PEP or at a controller (W7). An install set is compared
only with the install set before it (IS12, H13).

**AF5.** The action floor costs a bounded amount. A decision asks at most two sets, the action floor and
then the active release or the fallback policy. Each is inside the artifact bound, so the worst case time
of a decision is at most the sum of the two. A PEP holds at most three install sets and one staged set
per install kind beside its releases, and two copies of the install record. On a `mesh` node that is
1,280 bytes for the floor and the fallback policy, 2,048 bytes for a policy list of 64 hashes, the
staged sets inside the same bounds,
three sealed envelopes of at most 2,440 bytes each, under 2,048 bytes for the two copies, and one write
of a few bytes for each counted override (AF8).

**AF6.** The action floor reads the request the PEP's policy reads and nothing more. On `cfs` that
includes the verdict of the runtime monitor, so the engineer chooses whether a floor action is allowed
whatever the monitor says or only when the monitor agrees. The action floor is permission. It does not
make an action physically safe.

**AF7.** A floor answer records what it overrode. When the action floor allows or escalates a request,
the PEP also asks the active release, or the fallback policy when that decides, and writes the outcome,
the cause and the policy hash of the set it asked on the receipt as `would`. It is `none` when no set
would have decided. A verifier replays `would` as it replays the decision (RC4). On `cfs` the receipt
line has no place for it, so the app writes a second line for the same reading in a case of the release
that is marked not enacted, and both lines are ordinary core receipts. This second lookup is
inside the two of AF5. An answer whose `would` is not an allow is a floor override, and the PEP counts
floor answers and floor overrides in its state record (H10). The `xdp` kind is the exception. Its
program decides each packet in the kernel and writes no receipt per packet, and a second table lookup on
every floor pass would double the cost of the path the floor is there to keep open. It counts floor
allows and leaves the override count at zero.

**AF8.** The engineer may sign a rate for the action floor, as `rate` in the `meta` of every statement of
the set. The envelope bytes are what is signed, so the rate is signed, and the set id covers it (IS1). It
limits floor overrides and nothing else. It is `allows` overrides in each `window` of seconds, counted
for each floor rule apart, so one action cannot spend the allowance of another. An entry of an
`egress.hosts` or of a `net.dests` is a rule for this count. A floor answer whose `would` is an allow is
not counted and never limited, so a request the release allows always stands. The PEP counts in fixed
windows of its own time (T1, T2) and saves the start of the window and the count of a rule before it
acts on an override of that rule, so a restart does not begin a new window. An authority envelope that
raises the time floor can end a window early, and that is the stated limit of this count. Past the rate
the action floor escalates an override it would have allowed, with `dist:floor-rate` and basis `floor`,
and an operator's signed answer lets one such request through (OP2). On a kind with no escalation (AF2)
the floor is silent past the rate, so the release decides. The `xdp` kind takes no rate, since it
records no `would` and has no durable write on the packet path, and a set for `xdp` with `rate` is
`dist:bad-format`.

**AF9.** An action floor is narrow, and that is checked. A PEP refuses an action floor at IS5, and the
sealing tool and a controller refuse it before that, with `dist:floor-broad` when any of these holds.

| Check | What is refused |
|---|---|
| No default | A policy that allows or escalates a request no rule matched |
| One action | A rule that allows or escalates without an equality test of the action field against one value as a conjunct of the whole rule. A test inside one branch of an or, a range, a negation or a set does not count |
| No dispatcher alone | A rule whose one action is a dispatcher and that lacks the further conjunct the table below asks for |
| Few rules | More than 8 rules that allow or escalate, or a table with more than one decision node |
| Short lists | An `egress.hosts` or a `net.dests` with more than 8 entries, or an entry that is not one full name or one address. A `gateway.routes` with more than 8 routes or with a route that ends in `*` |

| Kind | Action field | Dispatchers and what they need |
|---|---|---|
| `agent` | `tool` | `unknown` is never allowed. `run_command` needs an equality test of `command_class` against a value other than `unknown`. `write_file`, `delete_path`, `git` and any other tool that changes files need an equality test of `path_scope` against a value other than `unknown` and a test of `path_control`. `connect` is allowed only to a host of the floor's `egress.hosts` |
| `gateway` | `path_class` | Every rule also tests `method_class` for equality. Neither test names `other` or `unknown`, and every route is one exact path |
| `xdp` | the destination class of `net.dests` | The compiled test is `dst_ip in [...]` over the floor's own addresses, at most 8. Narrowness is checked on the `policy.core` and the `net.dests`, and the `net.edge` is then held byte for byte to what they compile to, as V11 holds any edge table |
| `cfs` | the layout field of kind `COMMAND` | Every rule also bounds each `INT` field the layout holds, from both sides, so a command class is never allowed with any parameter |
| `host`, `mesh` | the field whose register is `command` in `meta` | The register is the one the layout (AF10) labels as its command field, and a PEP built with none takes no action floor. Every rule also bounds each parameter field from both sides, as on `cfs` |

A bound that is the whole domain of its field is no bound. On a table a rule is an edge of the one
decision node whose target is the allow outcome. The bound is 8
because that is half the 16 rules a cFS table holds, it fits a `mesh` image of 640 bytes with room to
spare, and it is few enough for the engineer and an operator to read every rule.

**AF10.** A floor rule tests only what the proposer cannot write about the world. A field of a layout
is the command, a parameter of the command, or a reading of the world. A floor rule may test the command
and its parameters, which say what is asked. It may test a reading of the world only when the layout
marks that field independent, which means the PEP takes it from a source other than the component that
proposes, as the cFS app takes `MONITOR`. A floor that tests any other field is `dist:floor-broad`.
Otherwise the component the floor overrides would authorize itself, as a perception stack that misread
an obstacle would report the way clear and so allow its own resume. The layout gives each independent
field a staleness bound in seconds, which is never 0, and a rule that tests a field whose value is
absent or older than its bound is silent. The labels live with the layout. On `cfs` they are the kinds
of the layout header, on `mesh` the layout compiled into the firmware, and on `host` the qualification
envelope the tables are admitted under. The engineer writes the same labels as a layout document, a
canon/2 list of each field's register, role, bounds and staleness bound, and gives it to the sealing
tool and the controller, which is how they make the checks of AF9 and AF10. Its SHA-256 is `layout` in
the `meta` of a table floor, and a PEP refuses a floor whose `layout` is not the hash of the layout it
was built with, with `dist:target-mismatch`. On `agent`, `gateway` and `xdp` the PEP reads every field
from the request itself, so all of them are independent. The cFS app today takes a monitor staleness
bound of 0 as never stale, and PR 18 closes that before a cFS floor may test the monitor.

### 21.3 The fallback policy

**FB1.** A PEP that holds a fallback policy decides under it whenever no release is active. That is at
start with nothing committed, after a lapse at expiry (X1) where the deployment did not choose HOLD,
after a revocation or a ceiling that removes the active release (R5, CL3), and while the PEP is `locked`
(Q5). The fallback policy is a set like a release. Its policy allows, refuses and escalates with its own
causes, and the action floor still comes first (AF1). On a host kind the PEP hands the fallback set to
its runtime where it would otherwise withdraw the policy, so a `host` runtime decides under the fallback
`policy.ppt`, every part of an `agent` home reads the fallback set, a `gateway` routes by it and the XDP
program loads its edge table. A PEP with no fallback policy refuses as X3 says, and that stays the
default on every kind.

**FB2.** The fallback policy is a sub state of `no-policy` and of `locked`. The PEP's status stays 0 or
2, the active policy hash, release id and `seq` of its state record stay zero, and bit 4 of `status` is
set in every record while the fallback policy decides. A PEP under its fallback policy stages and refuses
envelopes as it would in `no-policy`, and a `locked` one still admits no release.

**FB3.** A PEP that goes to its fallback policy reports event `fallback` in place of `lapsed`. The cause
is the one that ended its release, `dist:expired`, `dist:revoked`, `dist:above-ceiling` or
`dist:floor-lost`, and it is `dist:fallback` when the PEP starts with nothing committed. No decision made
under the fallback policy is `dist:policy-lapsed`.

**FB4.** A PEP never originates an action. Going to the fallback policy changes what the PEP allows and
is reported, and that is all. What commands the resource into its physical safe state is the deployment's
own fault response, and the commands it sends are ones the action floor or the fallback policy allows. On
`cfs` the app sends an event that the mission's fault response can act on.

**FB5.** The only way out of the fallback policy is the commit of a release that passes every rule, which
clears bit 4 and reports `committed`. Going from the fallback policy to a release is going from no policy
to a policy, so the release is larger (section 9.4) and needs a widening statement whose `from` is empty.
The policy hash of the fallback policy is never the PEP's active policy hash, in W1, in W2, in W4 or in a
state record. A `locked` PEP stays under its fallback policy until a provisioning step clears the lock
(P3).

**FB6.** HOLD and a fallback policy may both be set on a `mesh` or `cfs` target, and X6 alone decides
what happens at expiry. Under HOLD the PEP is held (X7) and is not under its fallback policy. When a
revocation ends the hold (X8) the PEP goes to its fallback policy. Under REFUSE, and on every other kind,
it goes there at expiry. Bits 4 and 5 of `status` are never set together.

**FB7.** The fallback policy does not change the bound of X2. A cut off PEP decides under its last
release until that release expires and then under the fallback policy, for as long as it is cut off. The
fallback policy has no time bound of its own.

**FB8.** A fallback policy at a higher `seq` replaces the held one when it is applied (IS4), with the
event IS12 gives it. A PEP that is under its fallback policy then decides under the new one at once. A
PEP with an active release holds the new one, and its release keeps deciding.

**FB9.** On `agent`, zone protection never drops with the release. When no release is active the
protected names are those of the fallback policy's `agent.zones` and of the ceiling's. Where the ceiling
has no `agent.zones`, the names of the last committed release stay in force as well. The PEP keeps them
with its install record and reads them at start.

### 21.4 The ceiling

**CL1.** The ceiling says what no release may allow. For a kind that can decide (section 3), which is
`agent`, `gateway` and `xdp`, it is an install set in the form of a release (IS3), and a release is
inside it when the release is not larger than the ceiling by section 9.4. That means no reading of the
reading domain is treated more permissively, the hosts and the addresses are subsets, and every name the
ceiling protects is protected. A route table is inside the ceiling when the ceiling's table gives every
path of every route the same class, which lets a release or an action floor name fewer or narrower
routes. An action floor holds no `agent.zones`, so it is compared on its policy and its hosts alone, and it
never reaches a name the ceiling protects (AF1). On `cfs` the app cannot walk the order section 9.4 gives
a `cfs.table`, so `cfs` is with the kinds that take a list. For a kind that cannot decide, which is `host`,
`mesh` and `cfs`, the ceiling is one statement whose `as` is `policy.list` and whose body is this canon/2
document. A release, an action floor or a fallback policy is inside it when the `body_sha256` of its `policy.ppt`
or `cfs.table` is on the list, and one that is off the list is `dist:above-ceiling`. So the engineer
lists a new floor table in the ceiling first, which is a widening of the ceiling, and sends the floor
after. It is the body hash and not the policy hash, because a cFS app decides with the image and the
rules of its table, which the hash of the core image does not cover. A table has no order a small PEP
can walk, so the engineer lists the tables that were qualified. The table comparator that is planned
runs at the sealing tool and the controller and never in the C core. It tells the engineer whether a new
table allows more than a listed one, so a table that allows nothing more can be listed without a new
qualification. A PEP always checks the list.

```json
{"bodies":["<body hash>"],"encoding":"canon/2","format":"prismpath.dist-ceiling/1"}
```

`bodies` is sorted and holds at most 64 hashes, and a longer list is `dist:too-large`. An empty list is
inside no release, and it is a ceiling that lapses every release (IS12).

**CL2.** A PEP that holds a ceiling refuses a release that is not inside it with `dist:above-ceiling`.
The check is part of V11 for every artifact of the release, and it runs again at commit (C3) and at a
rollback (RB2), since the ceiling can change in between. Those two are the only places a staged or a
kept release meets a newer ceiling. The sealing tool and a controller that hold the ceiling make the
same check before a release is sealed or offered, on every kind.

**CL3.** Everything a PEP decides under is inside its ceiling. An action floor or a fallback policy that
is not inside the held ceiling is refused with `dist:above-ceiling` (IS5), and so is a ceiling that the
held action floor or fallback policy would be above. The engineer narrows those first. A ceiling that the
active release is above is applied, and the release then lapses with `dist:above-ceiling` as it would
under R5. A staged or a kept release is left for CL2, and a staged install set is held to the ceiling
again when it is applied (IS4). The fallback policy is bounded by the ceiling
and not by the release, because it has to stand when there is no release, and because a process owner's
release is not what bounds the engineer.

**CL4.** The ceiling carries the reading domain. Section 9.4 gives every PEP the domain it was built
with, and the anchor holds the hash of that domain, which the PEP checks at provisioning (P4). So the
domain a PEP decides in is the one the engineer installed it with. On a kind that can decide, the field definitions of the ceiling's `policy.core` narrow that domain
for the PEP, for its releases and for its install sets, and they never widen it. A policy whose rule
names a value outside them is refused at V11 with `policy:out-of-domain`, the cause of section 9.4, and
so is a ceiling whose own fields go outside the built domain. On a kind that cannot decide, the domain
is the layout the PEP was built for, and the list names the tables qualified for it. A PEP with no
ceiling keeps the domain it was built with.

### 21.5 The operator's answer

**OP1.** An escalation by the action floor is answered by a signed operator. An operator key is a key in
the role `operator`, a third role apart from `authority` and `install`. The engineer enrolls up to 4 of
them in the install record, at provisioning or in `operators` of an `install.trust` (IS11), and adding
one is a widening (H13). No key is held in two roles (K4). An operator key signs answers and nothing
else, one signature is enough, and no other key signs an answer. Only a kind with escalation uses
operator keys, which is `agent`, `gateway` and `cfs` (AF2). A `host`, `mesh` or `xdp` PEP keeps the
`operators` it is given and never uses them, and the C core reads an answer only on `cfs`. Answers work
only on a PEP whose install threshold is 2 or more, so an operator key stands beside an install chain
that no single stolen key controls. On a PEP whose install threshold is 1 an `operator.answer` is
`dist:target-mismatch`.

**OP2.** An answer is a sealed envelope with artifact `operator.answer` and this canon/2 body.

```json
{"answer":"allow","encoding":"canon/2","format":"prismpath.dist-answer/1","pep":"<32 hex digits>",
 "receipt":"<sha256>"}
```

`answer` is `allow` or `refuse`, `pep` is the PEP id of H1 in lower case hex, and `receipt` is the
SHA-256 of the receipt of the escalation it answers. So an answer binds to one PEP and one escalation,
even when two PEPs wrote receipts with the same bytes. `stream` is the PEP's stream, `targets` names its kind, `policy_sha256` is the policy hash of
the action floor that escalated, `seq` is 1, `release` is 64 zeros, `replaces` is empty and `widens` is
`false`. Its lifetime, `expires` less `not_before`, is at most 600 seconds. It travels as a `stage` of
its kind over either binding and is applied when it verifies, on an install threshold of 2 or more
(OP1). It never raises the time floor (V13). B1 still holds,
since nothing unsigned answers an escalation. The PEP checks V2 to V6 and V9, then that `pep` is its own PEP id and that `receipt` names
an escalation it made on basis `floor`, under the action floor it still holds, that is still open. An
answer that fails that last check is `dist:answer-unbound`. An escalation by a release or by the
fallback policy keeps the path its kind already has.

**OP3.** An answer is used once. A PEP holds at most 8 open escalations, the oldest dropped first, and
each closes at its answer or after 600 seconds. Before it acts on an answer the PEP writes the
escalation as answered, durably, so the same answer after a restart is `dist:answer-unbound`. An `allow`
lets the one request of that escalation through once, uncounted by AF8. The answer leaves a receipt of
its own, with basis `operator`, the envelope id of the answer and the receipt hash it answered. A
refused answer reports `refused` with subject 5 (H10).

**OP4.** An operator's answers are visible and bounded. Every answer the PEP applies sends a record with
event `answered` and subject 5, and the controller shows each one in the fleet view beside the PEP. An
action floor that can escalate, on `agent`, `gateway` or `cfs`, carries `answer_rate` in the `meta` of
every statement of its set, signed with it as `rate` is (AF8). It is `allows` answers `allow` in each
`window` of seconds for the whole PEP, counted and saved before the PEP acts as AF8 counts. A floor that
can escalate and has no `answer_rate` is `dist:bad-format`. An `allow` past the rate is refused with
`dist:floor-rate` and the escalation stays open until it closes. A `refuse` is never limited.

### 21.6 Receipts

**RC1.** Every receipt of a PEP that holds an install statement carries the policy hash of the set that
decided and its basis, which is `release`, `floor`, `fallback` or `operator` (OP3). A request the action floor answered is
`floor`, with `would` (AF7) and with the zone override mark and the zone's name where the rule named one (AF1), also when a release is active and would have allowed it. A decision of the
fallback policy is `fallback`. A decision of the active release is `release`. A refusal made with no set,
in `no-policy` or `locked` without a fallback policy, has no basis and carries `dist:policy-lapsed` or
`dist:floor-lost` as before (X3). So a reader tells refused, decided by the fallback policy and allowed
by the action floor apart on every line.

**RC2.** The hold mark of X7 is apart from the basis, and one receipt may carry both. A held PEP's own
decision is `release` with the hold mark, and a request the action floor allowed in that time is `floor`
with the hold mark.

**RC3.** A receipt format with a cause field also puts `dist:floor-allowed` on a request the action floor
allowed, so a reader that knows only the cause registry still sees that the allow was not the policy's. A
floor escalation carries the floor's cause or `dist:floor-rate`, and a refusal or an escalation by the
fallback policy carries the cause its policy gives. A cFS core receipt keeps its format and carries none
of this. Its case says the basis (RC4). A counted override carries its floor rule, the start of the
window and the count after it, and on `cfs` those three and the receipt's hash are one line of
`rates.jsonl` in the run, which `run.json` names by hash.

**RC4.** The evidence of a run holds every install statement its PEP decided under and every
`install.trust` it applied in that time, as sealed envelopes in the order applied. A verifier starts from
the install key set and threshold it has pinned, applies each `install.trust` by IS11, and requires each
install set to be signed at the threshold under the key set in force when it was applied. It then replays
each decision under the set its receipt names, and each `would` under the set that names (AF7), with the overlay of AF1 as the PEP applied it. It
checks that the counts of AF8 rise by one within a window and never pass `allows` without an escalation,
and that each `operator` receipt names an answer an enrolled operator key signed for an escalation in
the run. A `release` decision is checked against a body the
authority signed. In a cFS core run each basis has its own case, and so do the `would` lines of AF7, the image attestation of a `floor` or
`fallback` case is the signature block of its install statement, and the receipt lines keep their format.
`core_evidence.verify` pins the install key set beside the authority key and refuses a run that holds a
`floor` or `fallback` case without it.

### 21.7 What install keys in the wrong hands can do

On a stream whose install threshold is 1 no install statement travels, so a stolen install key is of use
only to someone who also has the provisioning channel. On a stream whose threshold is 2 or more the
install keys are a live authority, and the transport is assumed hostile. This is what as many stolen
install keys as the threshold can do there, what a controller can do with none, and what stops both.

| Who | Can | Cannot |
|---|---|---|
| Fewer install keys than the threshold | Nothing | Sign anything a PEP takes |
| Install keys at the threshold | Replace the action floor and the fallback policy of every PEP on the stream, inside the held ceiling, and the floor only as narrow as AF9 holds it | Sign a release, a widening statement, a revocation or a rotation (IS2) |
| | Widen or withdraw the ceiling, and then widen the rest | Add, retire or revoke an authority key, or change the trust sequence or the floor of section 6 (IS7) |
| | Sign an install `seq` so high that the engineer's own sets cannot follow | Move the time floor, and so expire a release (IS5) |
| | Replace the install key set and lock the engineer out, or enroll an operator key and answer the floor's escalations | Make a PEP originate an action. A wider floor answers only what is proposed to the PEP (FB4) |
| | Sign a ceiling that lapses every release, an empty list for one, and a fallback policy inside it that then decides everything | Change what a PEP holds unseen. Every change gives a new install id in every record (H10) |
| | On `cfs`, sign a wider table with `widens` `false`. The PEP takes their word, and only a controller or a sealing tool that compares catches it (H13) | Sign a wrong `widens` past any PEP but a `cfs` one (IS12), or a broad floor past any PEP (AF9) |
| An operator key in the wrong hands | Answer `allow` to escalations the action floor made, on PEPs of a stream whose install threshold is 2 or more, up to the signed answer rate, each shown by an `answered` record (OP4) | Answer what the floor did not escalate, answer for another PEP or twice (OP2, OP3), sign any other kind (OP1), or act where the install threshold is 1 |
| A controller, with no key | Withhold an install set for as long as it likes. No expiry bounds this | Make or change an install statement (IS8) |
| | Offer a superseded set the engineer signed, at a `seq` above the PEP's | Offer one at or below the `seq` the PEP holds (IS6), or one the PEP's ceiling does not hold (CL3) |
| | Fork a stream by giving two PEPs different `install.trust` statements that were both signed | Hide it. The install trust id is in every install id (IS10, H12) |

H13 is detection and not prevention. A PEP applies a well signed widening set from any sender, a hostile
controller, a relay or a broadcast included. What stands against that is the install threshold, the
ceiling, the narrowness of AF9 and the record that shows it.

The authority cannot undo any of it, by design. The recovery from stolen keys is a provisioning by the
engineer with a new and disjoint install key set (IS6). The guard against a superseded set is a newer
set or the empty set at a higher `seq`, which keeps it from every PEP that took one, and the guard
against a withheld one is the state record, which shows the engineer what each PEP holds.
