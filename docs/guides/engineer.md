# The engineer's guide

You establish the interface once, calibrate for deployment, and deliver. The process owner writes the
policy; you make it executable where it needs to run and keep it that way in CI. Most of your work
happens rarely; that is the point.

## 1. The interface, once

```bash
prismpath contract flow.md      # each node's worker output schema, derived from its `when` edges
prismpath capability flow.md    # which targets the flow compiles to, and the edges that block the rest
```

`contract` is the schema the owner's edges imply: the fields a worker must emit for each step, with
their kinds. Build the worker against it and the owner's later changes are visible as contract diffs.
`capability` reports the tiers: P0 (deterministic only), P1 (semantic edges locked to a lockfile), P2
(needs a model at run time), and whether the deterministic fragment is Level M, the part every hardware
target executes. A flow that must reach a device stays in Level M by construction.

## 2. Delivery

```bash
prismpath lock flow.md          # pin semantic routing into a lockfile for reproducible routing (needs the embeddings extra)
prismpath compile --tier p0 flow.md   # a single file portable JS bundle (--tier p1 embeds the lock's vectors)
prismpath portable flow.md      # is this flow in the model free portable subset
prismpath plugins --check flow.md
prismpath ci-report             # the pull request report: validate, fixtures, before and after graph
```

For the compiled image, `.ppt`, the compiler is `prismpath-hw/ppt_compile.py` and the format is
`prismpath-hw/TABLE_FORMAT.md`; the C target, the kernel programs, the microcontroller firmware, and the
fabric all execute that image. The signed pack around it is your setup, and every `swap` and `authorize`
action and `ledger keygen` need the `signing` extra (`pip install 'prismpath[signing]'`):

```bash
prismpath swap keygen   --out keys --name authority
prismpath swap envelope --envelope-id env1 --fields temp:int,armed:bool --caps atoms=1024,nodes=256 --priv keys/authority.key --pub keys/authority.pub --out env
prismpath swap pack     --ppt flow.ppt --fields temp:int,armed:bool --version 3 --envelope-id env1 --priv keys/authority.key --pub keys/authority.pub
```

The envelope declares what a host will accept (fields, capabilities, size caps); the pack binds the
image, its fields, its version, and its computed worst case bound to your key. The operator swaps and
attests; the assessor verifies. `docs/design/spec-secure-hotswap.md` is the specification. Signed hot
swap packs (`.ppt`) are for Level M flows compiled for table substrates, and the compiler lives in the
repository's `prismpath-hw/`, not in the pip package.

A flow that is not compiled to an image, which is any flow with semantic edges and every flow
`prismpath run` executes, is authorized with a flow manifest instead, signed by the same authority key:

```bash
prismpath authorize sign   flow.md --priv keys/authority.key --pub keys/authority.pub --version 1
prismpath authorize verify flow.md --pub keys/authority.pub
```

`sign` writes `flow.md.manifest.json` and `flow.md.manifest.sig` beside the flow: the sha256 of the
flow's text, its name, the version, its field definitions when it defines them, your key id and the
time. Raise the version for every new authorization; a deployment that requires authorization refuses
a version below one it has already accepted. Any edit to the flow after signing, one character
included, unauthorizes it until it is signed again. Line ending conversions do not.

The deployment's instance key is a second key, and also your setup:

```bash
prismpath ledger keygen --out keys          # keys/instance.key (0600) and keys/instance.pub
```

It signs the root statements that bind the receipts to the deployment that wrote them. Keep it apart
from the authority key: the authority key says which policy may run and the instance key says what
ran, and one key doing both would let its holder write the policy and the evidence that it held. Hosts
and `run` refuse an instance key that is also a trusted authority key, and `authorize sign` refuses the
key `PRISMPATH_INSTANCE_KEY` names. `ledger keygen` never replaces a key that exists, because the
statements an old key signed verify only against it. Give the operator the instance key's path
(`--instance-key` or `PRISMPATH_INSTANCE_KEY`) and the assessor its public half.

## 3. Calibration

Thresholds are a deployment setting, so they are yours:

```bash
prismpath label       log.jsonl            # hand label routing decisions
prismpath annotate    bench.jsonl --out a.jsonl   # blind relabel for agreement measurement (each row names its flow, node and outcome; --flows-dir says where the flows are)
prismpath kappa       a.jsonl b.jsonl      # Cohen's kappa between two label sets
prismpath calibrate   labels.jsonl         # the risk controlled escalation threshold
prismpath centroids   bench.jsonl          # prototype routing against zero shot embedding (needs the embeddings extra)
```

`docs/decoder-ring.md` explains the statistics behind each of these in plain language.

## 4. The kernels and the gates

The Python engine is the reference for the flow language; the C target is the reference for the compiled
image's execution; the frozen corpus in `prismpath/portable/conformance/` judges every kernel. If your
change alters predicate or engine semantics, the conformance test fails by design; regenerate the
vectors, commit the diff, and say so in the pull request. `docs/SYSTEM_MAP.md` section 4 lists every
implementation of the interpreter, the wire, and the signed pack, which one is the reference, and what
CI gates it. `CONTRIBUTING.md` has the setup for each toolchain.

## 5. Who you hand off to

The [process owner](process-owner.md) authors and tests the policy; the [operator](operator.md) runs
the system and swaps packs you built; the [assessor](assessor.md) verifies what the receipts say.
