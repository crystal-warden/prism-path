# Policy distribution

This guide is for the person who sends a signed policy to the machines that enforce it and has to know,
afterwards, which machine runs which policy. It covers the reference controller, the pull binding a host
uses, and the `prismpath dist` commands. The rules themselves are in `docs/design/spec-policy-distribution.md`,
and each rule named here by its letter and number is defined there.

## 1. The parts

There are three roles and they never share a key.

The owner holds the authority key. Only the owner signs, and the owner signs on the machine where the key
is. A signed release is a sealed envelope and its body.

The controller holds no authority key (F1). It stores what the owner sealed, checks it with the same
verifier an enforcement point runs before it offers anything, tells each enforcement point what it is
offered, and keeps the fleet view. Its own instance key signs its audit log and nothing else.

An enforcement point, the PEP, holds a trust anchor and its own instance key. It verifies every envelope
itself, keeps a floor so that nothing older comes back, and signs a state record after every change. A
host PEP pulls from the controller every 30 seconds. The controller never connects to it (B3).

Nothing on the wire is trusted for who sent it (B1). A forged commit can only make active a release the
owner signed for that PEP, so staging a release is consent to run it. A release the owner no longer wants is
revoked, not aborted.

## 2. Keys

```bash
prismpath swap keygen --out owner/        # the authority key, which stays with the owner
prismpath ledger keygen --out controller/ # the controller's instance key
prismpath ledger keygen --out pep/        # one instance key per PEP
```

The trust anchor names the authority public keys, the target kind and the stream. The owner writes it once
and gives the same file to the controller and to each PEP of that stream. It prints the fingerprint the
operator of each PEP confirms.

```bash
prismpath dist anchor --pub owner/authority.pub --target host --stream web/prod --out anchor.json
```

## 3. A first release

On the controller, enrol each PEP by its instance public key. Enrolling also serves the anchor's stream, and
a host stream needs the qualification envelope its PEPs hold.

```bash
prismpath dist enroll --dir ctl --key controller/instance.key --pub pep/instance.pub \
    --anchor anchor.json --qualification qualification.json --group web
prismpath dist serve --dir ctl --key controller/instance.key --listen 127.0.0.1:8471
```

On each PEP, provision the anchor and confirm its fingerprint with the owner by a channel the network does
not control (P2). The PEP follows no stream until the fingerprint is confirmed.

```bash
prismpath dist pep provision --state pep-state --key pep/instance.key --anchor anchor.json \
    --qualification qualification.json
prismpath dist pep provision --state pep-state --key pep/instance.key --confirm <fingerprint>
prismpath dist pep poll --state pep-state --key pep/instance.key --url http://127.0.0.1:8471
```

The owner seals the release and drops it with its body in the controller's inbox. The controller checks it
there and refuses to store what does not verify (F1).

```bash
prismpath dist seal --artifact policy.ppt --body policy.ppt --stream web/prod --seq 1 --target host \
    --key owner/authority.key --expires 1893456000 --qualification qualification.json \
    --out ctl/inbox/r1.sealed
cp policy.ppt ctl/inbox/r1.body
prismpath dist offer --dir ctl --key controller/instance.key --group web --stream web/prod --seq 1
```

A first release allows more than no policy at all, so it goes with the owner's widening statement (W3). `widen`
signs one for a sealed release. With no `--from` it covers any PEP, and with `--from` only a PEP whose active
policy is one of those hashes (W4).

```bash
prismpath dist widen --sealed ctl/inbox/r1.sealed --key owner/authority.key --out ctl/inbox/w1.sealed
```

Each PEP fetches the sealed envelope by its envelope id, checks it through V8, and only then fetches the
body, at most the signed `body_size` (B9). It stages the release, and the controller sends commit. The
controller offers a release's widening statement before the release itself.

## 4. Releases that allow more

`seal --held ctl` fills in `replaces`, the policy hash of the release stored on the stream just below the new
`seq`, and sets `widens` unless it holds that release and finds the new body allows no more. A `policy.ppt`
image has no order, so for a host or a mesh table `widens` is false only on a renewal of the same table. The
controller holds a release to the same test before it offers it to a target that cannot decide (W7). A PEP that can decide whether a policy allows more walks every reading of
the policy's finite domain and compares the verdicts, so it does not trust `widens` (W1), and it refuses a
release it finds larger whose `widens` is false even with a statement (W6). A host, a mesh node and the cFS app
cannot decide. They take a release on its signature alone only when `widens` is false and `replaces` is the
policy they have active (W2). Every other release needs a widening statement that covers them. A first install
goes from no policy to one, so every PEP counts it as larger and refuses one whose `widens` is false, even with
a statement (W6).

The reading domain an agent policy is compared over is the one the engineer who installs PrismPath defines: the
values the classifier produces for each category, true and false, and each int's min to max. A policy whose
rule names a value outside it, such as a tool the classifier does not produce, is refused when it is loaded and
when a PEP checks it, with `policy:out-of-domain`, and a reading whose category value is outside it is refused with
the same cause before the policy decides it. The comparison walks the combinations the classifier never gives as well, so
a release that allows more on one of them is larger, and one that refuses more there is a tightening.

A commit holds the release to the widening rule again against what is active then (C3). A renewal staged against
a release that lapses before the commit goes from no policy to one, so it needs a statement that covers that.

A PEP commits a release only whole. It computes the release id again over the artifacts it staged, and when
that is not the signed `release`, because a transport left out an `agent.zones`, a `sandbox.profile` or a
`policy.spiral`, the commit is refused with `dist:incomplete` (C2).

A rollback is held to the same rule (RB3). A rollback to a release identical to the active one is never a
widening. On a host or a mesh node a local rollback to an older table works only when the kept release says it
widens and holds a widening statement that covers the newer policy. When the owner signed the older release,
the newer policy's hash was not known, so in practice that is a statement with an empty `from`. A kept renewal
says it does not widen, so it is never a rollback target from another table. Without one the owner releases
the older policy again at a higher `seq`.

## 5. Groups and the two rules

A group runs under one of two rules (F3). Under `each` a member is sent commit as soon as it staged, so one
refusal stops only that member. Under `all` nobody commits until every member staged, and a refusal or the
end of the stage window aborts the whole group. The stage window is 120 seconds, and 500 milliseconds on
the mesh. The commit window is 120 seconds, and on the mesh the commit's delay plus 2 seconds. A rollout
whose commit window ends with a member still not committed is `partial` and stays open until that member
reports.

`offer --delay` gives the commit a delay in milliseconds. Each PEP makes the release active at its own
monotonic time plus the delay (B8), which is how a mesh flips together without a shared clock. A PEP holds
a delayed commit in memory only, so a restart before it falls due loses it. The controller keeps sending
commit to every member that has not reported `committed`, after the commit window as well, so the PEP takes
it again on its next poll or the next send.

A PEP that is behind on the trust chain is offered the trust statements it lacks, in order, and nothing else
until it holds them all (F6). A refusal in that time is filed against the statement, never against a
rollout. A revocation or a rotation reaches every PEP whatever its `targets` says, since one trust sequence
counts the same for all of them.

## 6. The fleet view

```bash
prismpath dist fleet --dir ctl --key controller/instance.key
```

For each PEP it shows the policy and `seq` the controller expects, the ones the PEP last reported, and the
open findings. The controller checks every state record in the order of H6. A record that does not verify
under the enrolled key is `fleet:state-invalid`. A counter that did not rise, or an epoch older than the one
before the current, is `fleet:state-replay`. A policy other than the expected one is
`fleet:policy-mismatch`, found from the hashes the record's header carries. A PEP whose active release has a
`policy.core` also sends the decisions it made since its last record, at most 64, as a Facet stream of that
policy (H5). The stream's preamble names the policy and its layout, so a body built from another policy is
`fleet:policy-mismatch` too, and a body that does not decode under the policy it names is
`wire:codebook-mismatch`. Three intervals with no record is `fleet:silent`. A refusal is filed under the
cause the PEP gave. Each finding stays open until a later record clears it (F4). The same view is served at
`GET /dist/v1/fleet`, and its field names follow the OPA status API where they fit.

The controller writes every offer, ack, commit, abort, finding and trust statement to its own audit log,
signed with its instance key (F5).

## 7. Revoking and rotating keys

A revocation list replaces the one before it and is applied as soon as a PEP verifies it. `revoke` starts
from the latest list the controller holds, adds and drops what it is told, and refuses a list that drops a
key, or an envelope or a policy that no floor has passed (R8). Raise a floor past an old entry first, and
drop it in the next list.

```bash
prismpath dist revoke --held ctl --key owner/authority.key --entry envelope=<id> --out ctl/inbox/t1.sealed
prismpath dist rotate --held ctl --key owner/authority.key --new owner/next.key --out ctl/inbox/t2.sealed
```

A revocation that removes the key under the active release makes every PEP lapse at once (R5). `rekey`
avoids that by doing the work in order. It rotates to the new key, releases under it, waits for the group
to commit, and only then revokes the old key. The new key comes from `prismpath swap keygen --out owner/
--name next`.

```bash
prismpath dist rekey --dir ctl --key controller/instance.key --old owner/authority.key --new owner/next.key \
    --body policy.ppt --qualification qualification.json --group web --stream web/prod --seq 2 \
    --target host --expires 1893456000
```

The controller offers the trust statements a PEP lacks before any release, and in order (R1).

## 8. An agent home

An agent home follows a stream the same way. The home holds its instance key and no authority key.

```bash
prismpath agent init --follow web/agents --anchor anchor.json
prismpath agent init --follow web/agents --confirm <fingerprint> --yes
prismpath dist pep poll --kind agent --state ~/.config/prismpath/agent --key ~/.config/prismpath/agent/instance.key \
    --url http://127.0.0.1:8471
```

A release for it holds `policy.core` and `egress.hosts`, and may hold `agent.zones` and `sandbox.profile`. The
hook, the egress proxy and the MCP proxy read the committed release on every load and check it again. The
egress proxy reaches the committed hosts and no others, so `--allow-host` is refused. The project and the index
of the zones are the home's own setting in `zones.local.json`.

## 9. What this version does not do

A host, a mesh node and the cFS app send a state record with no Facet body, since their releases carry no
flow text to build one from (H5). A rollback with `prismpath dist pep rollback` follows RB1 to RB3, so on a
host, which cannot decide whether a policy allows more, it needs a widening statement that covers it. The
mesh and the cFS app use the frame binding of section 8.3, which the controller drives as a broadcast to
the whole group.
