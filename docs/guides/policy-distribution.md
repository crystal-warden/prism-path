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

Each PEP fetches the sealed envelope by its envelope id, checks it through V8, and only then fetches the
body, at most the signed `body_size` (B9). It stages the release, and the controller sends commit.

## 4. Groups and the two rules

A group runs under one of two rules (F3). Under `each` a member is sent commit as soon as it staged, so one
refusal stops only that member. Under `all` nobody commits until every member staged, and a refusal or the
end of the stage window aborts the whole group. The stage window is 120 seconds, and 500 milliseconds on
the mesh. A rollout whose commit window ends with a member still not committed is `partial` and stays open
until that member reports.

`offer --delay` gives the commit a delay in milliseconds. Each PEP makes the release active at its own
monotonic time plus the delay (B8), which is how a mesh flips together without a shared clock.

## 5. The fleet view

```bash
prismpath dist fleet --dir ctl --key controller/instance.key
```

For each PEP it shows the policy and `seq` the controller expects, the ones the PEP last reported, and the
open findings. The controller checks every state record in the order of H6. A record that does not verify
under the enrolled key is `fleet:state-invalid`. A counter that did not rise, or an epoch older than the one
before the current, is `fleet:state-replay`. A policy other than the expected one is
`fleet:policy-mismatch`. Three intervals with no record is `fleet:silent`. A refusal is filed under the
cause the PEP gave. Each finding stays open until a later record clears it (F4). The same view is served at
`GET /dist/v1/fleet`, and its field names follow the OPA status API where they fit.

The controller writes every offer, ack, commit, abort, finding and trust statement to its own audit log,
signed with its instance key (F5).

## 6. Revoking and rotating keys

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

## 7. What this version does not do

The controller reads the hashes of a state record and not yet its Facet body, since every PEP of this
version sends an empty one (H5). A rollback with `prismpath dist pep rollback` follows RB1 to RB3, so on a
host, which cannot decide whether a policy allows more, it needs a widening statement that covers it. The
mesh and the cFS app use the frame binding of section 8.3, which the controller drives as a broadcast to
the whole group.
