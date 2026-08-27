# Verify the demo yourself

The video claims a chip decided things under a signed rulebook and wrote receipts. You should not
take that on faith. Six commands walk from the video file down to the Bitcoin blockchain; every
expected output below is the real output of these exact commands, not a paraphrase. Steps 1 and 2
need only `sha256sum`. Steps 3 and 4 need Python 3.10+ with `pip install cryptography` and this
repo. Step 5 needs a C compiler and about three minutes. Step 6 needs the `opentimestamps-client`.

Files referenced live in `prismpath-hw/hyst-cert/evidence/` and the release assets. Some large
files (the unposted takes) ride the manifest **by hash** without being shipped; they verify
identically if requested. That is disclosure by hash, not omission: the manifest commits to their
exact bytes either way.

## Step 1: the video you watched is the video that was hashed

```
sha256sum take4_IMG_1751.MOV
```

Expect:

```
aee428a514ad4142f8b1f1bafff7f8808148869f1add9ef4530dc687d7edf8b6  take4_IMG_1751.MOV
```

The same hash appears in `evidence/SHA256SUMS` and in the repo README. If it matches, the camera
original in your hands is the file every receipt below binds to.

## Step 2: the evidence manifest holds

From the evidence directory:

```
sha256sum -c SHA256SUMS --ignore-missing
```

Expect a line per present file ending `: OK` and no `FAILED`. The manifest covers the take
receipts (the board's own decision stream during filming), the bridge radio logs, the signed
policies, the certification logs, the bitstream, and the videos. One manifest, one commitment.

## Step 3: the policy is signed, and by whom

From the repo root:

```
python3 -c "
import sys; sys.path.insert(0, '.')
from prismpath import policy_pack
ok, reasons, man = policy_pack.verify_pack(
    'prismpath-hw/demo/flows/hyst_band.ppt',
    ['prismpath-hw/demo/keys/demo_authority.pub'])
print('verified:', ok, reasons)
print(man['envelope_id'], 'v', man['version'], 'key', man['key_id'][:16])
print('image_sha256', man['image_sha256'])
print('signed wcet_cycles', man['wcet_cycles'])"
```

Expect:

```
verified: True []
hyst_band v 1 key d519348f46c4d153
image_sha256 b9c740b9bc1ab3e586144562174fa08c4123eb1c761d9da9f9255587c2484260
signed wcet_cycles 11
```

An Ed25519 signature over the manifest, which binds the exact compiled image and the timing bound
the silicon was held to. Repeat with `demo_input.ppt` (the flickering exact policy from the video's
first beat) and `switch_nav.ppt` if you want all three.

## Step 4: the rulebook you can read compiles to the exact bytes that were signed

Open `prismpath-hw/demo/flows/hyst_band.md`. It is a page of prose with thresholds in it. That
page IS the policy. Prove it:

```
python3 prismpath-hw/ppt_compile.py prismpath-hw/demo/flows/hyst_band.md -o /tmp/recompiled.ppt
sha256sum /tmp/recompiled.ppt
```

Expect:

```
/tmp/recompiled.ppt: 134B  fields=1 interns=1 atoms=4 nodes=3 edges=7  wcet=11cyc
b9c740b9bc1ab3e586144562174fa08c4123eb1c761d9da9f9255587c2484260  /tmp/recompiled.ppt
```

Byte identical to the signed image from step 3, and the compiler derives the same WCET the
signature carries. The human readable document and the machine artifact are the same object.

## Step 5: the oracle the silicon was certified against reproduces on your machine

The fabric was certified 4568/4568 against a frozen sequence corpus. Rebuild the independent C
reference and regenerate the corpus from scratch; two implementations must agree at every step and
land on the frozen bytes:

```
cd prismpath-hw && make && python3 gen_hyst_corpus.py
sha256sum demo/flows/hyst_corpus.json
```

Expect (about three minutes; the generator cross checks the C target at every one of the 4568
events and refuses to freeze on any disagreement):

```
FROZEN: hyst_corpus.json  41 streams, 4568 events, both references agree at every step
corpus sha256: bea5ab6e2b82f507501a508e723eb83411576456f79415152ed09cc26f1b69e4
bea5ab6e2b82f507501a508e723eb83411576456f79415152ed09cc26f1b69e4  demo/flows/hyst_corpus.json
```

What you cannot reproduce without the bench is the silicon itself; that leg lives in
`evidence/cert_leg1.log` (the fabric reproducing this corpus 4568/4568 over MMIO replay) and
`evidence/wcet_rewitness_hyst_band.log` (16,009 evaluations on the pins, max 9 cycles against the
signed 11). Both are inside the manifest you checked in step 2.

## Step 6: the ledger predates its claims, per Bitcoin

The research ledger rows behind this demo are anchored with OpenTimestamps:

```
ots verify prismpath/evidence/ledger_v2.4_2026-08-23.SHA256SUMS.ots
ots info   prismpath/evidence/ledger_v2.5_2026-08-27.SHA256SUMS.ots
```

Expect: the v2.4 anchor verifies against Bitcoin blocks 963725/963726 (a full `ots verify` needs a
Bitcoin node; `ots info` shows the block attestation without one). The v2.5 anchor (which covers
the demo rows #121 to #123) upgrades to its block attestation as the calendar commits; run
`ots upgrade` then `ots verify` on it.

## The one step that is yours

Watch the take against `evidence/take_receipt_session2.log` with `evidence/TAKE_NOTES.md` open.
The button presses in the video line up with the stateful flag flips in the receipt; the walker
shake lines up with the quantized field values; the parked knife edge holds one band while the
field jitters. The receipt was written by the fabric while the camera rolled. If the video and the
receipt tell the same story, everything above says neither could have been quietly rewritten.
