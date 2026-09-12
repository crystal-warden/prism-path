---
name: receiver_admission
start: reading
---

## reading
One reading as it arrives at the receiver, with what the receiver knows about it. `in_window` is 1 when
the record belongs to this take (records the relay buffered before the take drain first); `fresh` is 1
when its sequence has not been seen; `policy_held` is 1 when the receiver holds the policy version the
reading names, so it can decode the wire; `chain_ok` is 1 unless the reading's previous hash contradicts
the record before it on a consecutive sequence (a splice); `route_agrees` is 1 when the route the
receiver re-derives from the bands on the wire is the route the node claimed; `normal_held` is 1 when
the receiver holds the normal the reading was computed against. Three outcomes and nothing in between:
authorized, when the receiver has everything the policy needs and acts; refused, when the reading is
not admissible as evidence and the cause says why; abstain, when the reading is admissible but the
receiver lacks the state the policy needs to act on it, so it produces no authorized decision rather
than a guess.
@emits(in_window, fresh, policy_held, chain_ok, route_agrees, normal_held)
-> refuse_window: when in_window == 0
-> refuse_replay: when fresh == 0
-> refuse_policy: when policy_held == 0
-> refuse_chain: when chain_ok == 0
-> refuse_route: when route_agrees == 0
-> abstain: when normal_held == 0
-> authorized: else

## refuse_window
Before the take's window: cause 53 replay-stale.

## refuse_replay
A sequence already seen: cause 52 replay-duplicate.

## refuse_policy
The receiver does not hold the policy version the reading names, so the wire is not decodable here:
cause 51 wire:codebook-mismatch.

## refuse_chain
A consecutive sequence whose previous hash does not match: a splice, cause 56 wire:chain-broken.

## refuse_route
The node claimed a route the policy on the wire does not support: cause 37 route:contract-violation.

## abstain
The reading is the node's and it is sound, but it names a normal the receiver does not hold. Nothing
is painted and nothing is escalated; the receiver asks the node for its normal. Cause 68
state:normal-unheld. This is not a refusal: the node's decision stands, the receiver's does not exist.

## authorized
The receiver holds the normal, the policy and the chain, and its own re-derivation agrees: it paints the
reading over the normal and shows evidence the route asked for. Cause 0.
