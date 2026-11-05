# The assessor's guide

You come after the fact. Was the decision right, was it the policy that was approved, and can either be
shown to someone who does not trust the system that made it. Everything you need is designed to be
verified without trusting the emitter.

## 1. What a decision leaves behind

A receipt: the decision, the rule that fired, and a one byte cause code from the registry
(`docs/design/spec-cause-codes.md`): 0 clean, 34 the worker asked for a person, 36 nothing matched and
no catch all, 64 state went stale, 66 a swap reset the resident state, and the rest by band. Receipts are
leaves of a Merkle tree per session; the root can be anchored to a timestamp with OpenTimestamps or an
RFC 3161 authority, including from an air gapped site.

A deployment that has an instance key also leaves root statements beside the log
(`run.audit.jsonl` beside `run.audit.roots.jsonl`). Each one is the deployment's signature over the
root and the number of receipts it covers, chained to the statement before it, with the policy in
force: the flow's hash and, when the flow was authorized, the hash of its flow manifest, the
authority key that signed it and its version. That gives one receipt a path back to two keys you can
pin separately, receipt to inclusion path to signed root to the instance key, and signed root to flow
manifest to the authority key. The instance key and the authority key are different keys by design.
A log written before signing existed has no statements and reads as unsigned, not as failed.

## 2. What you run

```bash
prismpath trail run.audit.jsonl                 # decisions by outcome, rule, and cause; swaps; attestations; root check
prismpath trail run.audit.jsonl --pub instance.pub              # and every signed root, under the pinned instance key
prismpath trail run.audit.jsonl --pub instance.pub --receipt 3  # one receipt: leaf, inclusion path, signed root, signature
prismpath trail --verify-bundle bundle.json --pub instance.pub  # a receipt you were handed as a file: no log needed
prismpath ledger anchor --log run.audit.jsonl --out proofs      # timestamp the log (its latest signed statement)
prismpath ledger verify --log run.audit.jsonl --out proofs --pub instance.pub   # the log still holds it, and the proof verifies
prismpath authorize verify flow.md --pub authority.pub          # the flow manifest a signed root names
prismpath ledger verify --out proofs --leaf <hash>   # one leaf: its Merkle path to the anchored root, then the OTS proof
prismpath ledger upgrade --out proofs --label v1     # upgrade a pending anchor to a Bitcoin attestation
prismpath swap verify --ppt flow.ppt --pub authority.pub --revoked revoked.json
prismpath facet decode flow.md <hex>            # what a wire frame decided
```

The `ledger` commands call the OpenTimestamps client, `ots`, which is installed separately
(`pip install opentimestamps-client`) and must be on your PATH.

Two things are not in the base install. `ledger anchor`, `upgrade` and `verify` call the external
OpenTimestamps client, `ots`, so install it separately (`pip install opentimestamps-client`) and keep it
on your PATH. Every `swap` and `authorize` action, `ledger keygen`, and `trail` on a log that has root
statements need the `signing` extra (`pip install 'prismpath[signing]'`); `trail` on an unsigned log
does not.

`trail` reads the append only log, checks that the Merkle root still verifies, and summarises the window
in cause code terms; a root that no longer matches an anchored one is the signal that the log was
edited. `swap verify` checks a pack against the authority keys and the revocation list and prints the
reasons if it fails; the reason strings are a frozen vocabulary that maps onto the cause registry.

With `--pub`, `trail` pins the deployment's instance public key and reports the log as signed or
invalid, naming what it found: a log shorter than a signed count (`log_truncated`), a receipt changed
under a signed root (`root_mismatch`, with the range of receipt indexes the change lies in), a
statement signed by a key you did not pin (`unpinned_key`), a statement removed, reordered or edited
(`chain_broken`, `bad_signature`), and a pinned key with no statements at all (`no_statements`), so
deleting the statements file cannot pass a signed log off as an old unsigned one. Without `--pub` it
checks each statement under the key the statement carries and says the key was not pinned, which
shows the log is consistent but not whose it is. Get the instance public key from the deployment
through a channel you trust, not from the log. `--receipt IDX --bundle-out FILE` writes a self contained
bundle (the receipt, its inclusion path, the covering statement; `--json` prints the same inside its
report), and `prismpath trail --verify-bundle FILE --pub instance.pub` checks it with nothing else, no
log and no network: receipt to leaf to inclusion path to signed root to signature to key. The answer is
`signed` (the pinned key made it, exit 0), `signed-unpinned` (no key was pinned, so the statement's own
key was trusted, exit 0, and it says so) or `invalid` (exit 1, with the step that failed); a file that is
not a bundle, or has a damaged path or hash, is `invalid` too and never an error trace. A bundle holds one
statement and not the chain around it, so it shows that the deployment's key signed a root that holds
this receipt and says nothing about the log's other receipts; `trail LOG --pub KEY` checks those.

What signing does not prove. A statement's time is the signer's clock, and whoever holds the instance
key can sign anything; a log and its statements cut back together leave a shorter chain that still
verifies. Anchoring answers both. `prismpath ledger anchor --log run.audit.jsonl --out proofs` stamps the
hash of the log's latest root statement, which covers its signature and, through the chain, every
statement before it; it says so, and says how many of the log's events that statement covers, because a
timestamp on it says nothing about the events after it (checkpoint, then anchor again). A log with no
statements is anchored by its Merkle root, and the output says that this timestamps the events and not
who recorded them. A log that does not verify, or is empty, is not anchored. `ledger anchor --log`
keeps a record beside the proof, and `prismpath ledger verify --log run.audit.jsonl --out proofs --pub
instance.pub` reads it back: the log verifies, the anchored statement (or the root over the first N
events) is still in it however much it has grown, and the proof verifies. `ledger anchor --statements
run.audit.jsonl` stamps every statement instead, so that `trail --verify-bundle bundle.json --pub
instance.pub --anchor-dir proofs` can check that the bundle's own statement was timestamped; with
only the latest anchored it reports the statement is not in the batch. The signature, chain and
inclusion checks run offline. An OpenTimestamps proof does not: `ots verify` needs Bitcoin block
headers, from a node or a block explorer, to turn the proof into a time, and a proof the calendar has
not yet had confirmed fails with that reason. An RFC 3161 token needs only the authority's certificate.

`authorize verify` checks a flow manifest against the authority keys and the revocation list: the
signature, the key it names, and that the flow document is byte for byte the one signed (line endings
aside). Compare the `manifest_sha256` it prints with the one the signed root names. A run that was
refused for want of authorization is itself a receipt, with the cause (`sig:missing`,
`flow:sha256-mismatch` 87, `flow:version-replay` 88 and the rest).

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
