# The evaluator's guide

You come after the fact. Was the decision right, was it the policy that was approved, and can either be
shown to someone who does not trust the system that made it. Everything you need is designed to be
verified without trusting the emitter.

## 1. What a decision leaves behind

A receipt: the decision, the rule that fired, and a one byte cause code from the registry
(`docs/design/spec-cause-codes.md`): 0 clean, 34 the worker asked for a person, 36 nothing matched and
no catch all, 64 state went stale, 66 a swap reset the resident state, and the rest by band. Receipts are
leaves of a Merkle tree per session; the root can be anchored to a timestamp with OpenTimestamps or an
RFC 3161 authority, including from an air gapped site.

## 2. What you run

```bash
prismpath trail run.audit.jsonl                 # decisions by outcome, rule, and cause; swaps; attestations; root check
prismpath ledger verify --dir proofs            # verify anchored roots
prismpath ledger upgrade ...                    # upgrade a pending anchor to a Bitcoin attestation
prismpath swap verify --ppt flow.ppt --pub authority.pub --revoked revoked.json
prismpath facet decode flow.md <hex>            # what a wire frame decided
```

`trail` reads the append only log, checks that the Merkle root still verifies, and summarises the window
in cause code terms; a root that no longer matches an anchored one is the signal that the log was
edited. `swap verify` checks a pack against the authority keys and the revocation list and prints the
reasons if it fails; the reason strings are a frozen vocabulary that maps onto the cause registry.

## 3. What the evidence base is

Every public claim maps to a row in `docs/research/supporting-evidence.md`: claim, method, result, honest
scope, provenance, with the ledger itself anchored per version. The pre registered comparison in
`prismpath/comparisons/VERDICT.md` is the one to read first, because it reports the claim that did not
survive. The formal development in `formal/` states plainly what is proven and what is not. The
conformance topology in `docs/SYSTEM_MAP.md` section 4 says which implementation is the reference and
what keeps the others in agreement.

## 4. Who you work with

The [operator](operator.md) produces the trail you read and the attestations you check; the
[engineer](engineer.md) holds the keys and the envelope; the [process owner](process-owner.md) holds the
document a decision must be traced back to.
