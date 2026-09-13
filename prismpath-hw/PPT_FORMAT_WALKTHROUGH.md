# One policy, from the compiler to the fabric

*A companion to [TABLE_FORMAT.md](TABLE_FORMAT.md) and to
[../prismpath/hotswap/policy_pack.py](../prismpath/hotswap/policy_pack.py), for a reader who knows what
a match action table is but has never followed one of these images end to end. The vocabulary is
[../docs/DICTIONARY.md](../docs/DICTIONARY.md); the evaluator that executes the image is
[EVALUATOR_WALKTHROUGH.md](EVALUATOR_WALKTHROUGH.md).*

## Why this document exists

`TABLE_FORMAT.md` says what the bytes are. It does not say who produces them, who checks them, who
signs them, who carries them, or what happens to a reader that gets one of the fields wrong. The answer
to all of those is spread across a Python module, a C reference, a header for microcontrollers, a
hardware description, two loaders and eight firmware ports, and every one of them holds its own copy of
the layout. That is the situation this document exists to make navigable: **the layout is written down
in more than a dozen places, and none of them can move without the others.**

The way to see it is to follow one real policy all the way through. This document follows
[demo/flows/hyst_band.md](demo/flows/hyst_band.md), the three band hysteresis policy that the finale
datapath gate certifies against. It is 134 bytes long, which is small enough to print in full, and it
exercises the parts of the format that are easy to get wrong: an optional section, a declared fail safe,
and a declared execution profile.

## The policy as a person wrote it

Three nodes, one field. `pot` is a potentiometer's raw twelve bit count. Each band is entered sixteen
counts above its boundary and left sixteen counts below it, so that the measured seven count analog
jitter cannot sit on a line and flip the decision. `high` is declared the fail safe, so a torn or
uninitialized resident state lands on the alarm rather than quietly on the baseline.

```
## low       -> mid: when pot >= 681        -> low: else
## mid       -> high: when pot >= 1647      -> mid: when pot >= 649      -> low: else
## high      -> high: when pot >= 1615      -> mid: else
```

The hold edges are written out. Staying in a band is a decision the substrate makes on every evaluate,
not the absence of one, and that is what makes the trail auditable: every evaluate produces an edge.

## The image the compiler emits

The table compiler, [ppt_compile.py](ppt_compile.py), turns that flow into two files: `hyst_band.ppt`,
the image, and `hyst_band.json`, a debug view holding the field name table, the intern table and the
node names. **Only the image is signed and only the image is executed.** The JSON exists so that a
person, a dashboard or a loader can print names instead of indices; nothing on any substrate depends
on it.

The image is 134 bytes, little endian, in six sections laid end to end. Every section is found by
walking the one before it, so the header's counts are load bearing rather than advisory:

```
offset   0   header          28 bytes
offset  28   atoms            4 x 8 =  32 bytes
offset  60   nodes            3 x 4 =  12 bytes
offset  72   edges            7 x 6 =  42 bytes
offset 114   program words    7 x 2 =  14 bytes
offset 128   node attribute   3 x 2 =   6 bytes   (present only because flags bit 0 is set)
offset 134   end
```

Section by section, this policy in full:

```
atoms    every atom is (field 0 = pot, operator 5 = >=, type 2 = int, constant)
   0:  pot >= 681        1:  pot >= 1647        2:  pot >= 649        3:  pot >= 1615

nodes    (edge_off, edge_cnt); edge_cnt 0 would mean terminal
   0 low:  (0, 2)        1 mid:  (2, 3)         2 high: (5, 2)

edges    (target, prog_off, prog_cnt), in the order they were authored
   0: -> 1 mid   1 word at 0       4: -> 0 low   1 word at 4
   1: -> 0 low   1 word at 1       5: -> 2 high  1 word at 5
   2: -> 2 high  1 word at 2       6: -> 1 mid   1 word at 6
   3: -> 1 mid   1 word at 3

program  one word each; 0x8003 is push true, the compiled form of `else`
   [ atom0, 0x8003, atom1, atom2, 0x8003, atom3, 0x8003 ]

node attribute   one uint16 per node: [2, 4, 1]
   the fabric materializes these as LED color: low green, mid blue, high red
```

Three things to notice. The atoms are deduplicated flow wide and referenced by index, so a threshold
that appears in two nodes costs one atom. The edges of a node are contiguous and ordered, which is what
makes "first satisfied edge wins" an ordering over an array rather than a search. And an `else` is not a
special case anywhere below the compiler: it is a one word program that pushes true, so the evaluator
has exactly one code path.

## The header, word by word

| offset | word | type | this image | who writes it | what a reader does with it |
|---|---|---|---|---|---|
| 0 | magic | u32 | `PPTM` (0x4D545050) | compiler | refuse anything else |
| 4 | version | u16 | 1 | compiler | refuse anything else |
| 6 | n_fields | u16 | 1 | compiler | size the register file; bound every atom's field index |
| 8 | n_interns | u16 | 1 | compiler | size the intern table; id 0 is always the empty string |
| 10 | n_atoms | u16 | 4 | compiler | find the nodes section; bound every program word |
| 12 | n_nodes | u16 | 3 | compiler | find the edges section; bound every edge target |
| 14 | n_edges | u16 | 7 | compiler | find the program section; bound every node's edge range |
| 16 | prog_len | u16 | 7 | compiler | find the end; bound every edge's program range |
| 18 | start_node | u16 | 0 | compiler, from the flow's `start` | where a run begins |
| 20 | visits_idx | u16 | 0xFFFF | compiler | the field register the substrate overwrites with the current node's visit count; 0xFFFF means the flow never reads `visits` |
| 22 | max_steps | u16 | 25 | compiler, engine parity default | the run loop's iteration bound |
| 24 | max_stack | u16 | 1 | compiler, computed | the deepest the program stack goes, so hardware can be sized |
| 26 | flags and safe_node | u16 | 0x0209 | compiler | **split**, see below |

`visits_idx` is the quiet one. When it is not 0xFFFF the substrate writes the current node's visit
counter into that register **before** evaluating, overriding whatever a worker emitted, which is exactly
the reference engine's `ctx = {**fields, "visits": n}`. A substrate that forgets this is correct on
every policy that does not mention `visits` and wrong on every policy that does.

## The twelfth word is two fields

Offset 26 is documented in `TABLE_FORMAT.md`'s layout block as a plain `flags` word, and that block is
older than the format. `read_ppt_header` splits it: **the low byte is the flag bits, the high byte is
`safe_node`.** For this image, 0x0209 is flags 0x09 and safe_node 2.

| bit | name | meaning | materialized by |
|---|---|---|---|
| 0 | `FLAG_NODE_ATTR` | a per node uint16 section is appended after the program and signed with the image. The format gives the value no meaning at all | the fabric as an LED color, the kernel as a packet mark or traffic class, software as a label. The back compatible alias `FLAG_COLORS` is the fabric's reading of the same bit |
| 1 | `FLAG_MIGRATE_BY_NAME` | how a resident selector migrates across a hot swap: set means re resolve the current node by name, clear means reset to the fail safe. Meaningful only when `safe_node` is declared | the resident selector in each substrate |
| 2 | `FLAG_NODE_NAMES` | a per node uint32 name hash section is appended after the node attribute section. These are the signed identities a by name migration matches on | the loader |
| 3 | `FLAG_STATEFUL` | the policy **declares** the resident state machine profile rather than the stateless recompute. Declared, never negotiated: every endpoint derives the mode from the same signed image | every substrate that has both profiles |

`safe_node` is the one that deserves a paragraph. It is a single byte in the high half of one word, and
two consequences follow from that and are load bearing:

- **Node index 0 can never be the declared fail safe.** Zero is the sentinel for "undeclared", and a
  reader that sees zero falls back to the convention that the last node is the fail safe. A flow whose
  fail safe is its start node cannot express that in this header.
- **A policy with more than 255 nodes cannot name a fail safe at all**, even though the envelope allows
  256 nodes and the node count itself is sixteen bits.

Neither is a defect a reader can discover from the bytes; both are things a reader has to be told. For
`hyst_band`, `safe` is `high`, which is node 2, and `migration` is `reset-to`, so bit 1 is clear.

## Signing: `build_pack`

`build_pack(ppt_path, fields, version, envelope_id, priv_path, pub_path)` does five things in order:

1. reads the image off disk and **refuses to sign anything `validate_image` rejects**, which is the one
   place in the system where an invalid image cannot get a signature;
2. loads the public key and derives `key_id`, the SHA-256 of the raw public bytes, which is the identity
   that appears in manifests and revocation lists;
3. builds the manifest: the image's SHA-256, the header counts, the declared fields and their types, the
   version, the envelope id, the key id, a creation timestamp, and `wcet_cycles`;
4. signs the canonical compact JSON encoding of that manifest, not the image directly;
5. writes `<image>.manifest.json` and `<image>.manifest.sig` **beside the image, which is never
   modified.**

That last point is why every certification row in the ledger keeps citing the same image hash: the
signing step is additive and the compiler's output is the artifact of record. For our policy the
manifest reads:

```
image_sha256  b9c740b9...4260      counts  atoms 4, nodes 3, edges 7,
version       1                            prog_words 7, max_steps 25, max_stack 1
envelope_id   hyst_band             fields  {"pot": "int"}
wcet_cycles   11                    format  ppt-pack/1
```

The signature covers the manifest rather than the image because the manifest carries the things a loader
has to agree with the author about but cannot read off the image: which key, which version, which
envelope, and what the field named `pot` is supposed to be. The image hash inside the manifest is what
binds the two together, so tampering with either is a signature failure.

Two optional declarations ride the same signature when present. `packing` names a wire packing profile
and the hash of its sidecar artifact, re hashed at load. `overlay_of` names the policy of record that
this pack temporarily overrides, so an operator's short lived change is visible to the owner of the
baseline; it changes nothing about verification or the version floor.

## Checking: `validate_image`

`validate_image` is the structural and fragment check, and it runs twice in the life of a pack: once at
build time, before signing, and once at load time on the artifact that actually arrived. It returns
`(ok, reasons)`, with stable reason strings rather than prose, so tests and audit rows can pin an exact
failure class.

Walked on our image, in the order the code walks it:

1. **Header.** Parse it, and refuse on a bad magic, a bad version or a truncated header.
2. **The fail safe names a real node.** `safe_node` 2 is less than `n_nodes` 3.
3. **Exact length.** Not "at least", exact. The expected length is
   `28 + 8*atoms + 4*nodes + 6*edges + 2*prog_words`, plus `2*nodes` when the node attribute flag is set
   and `4*nodes` when the name hash flag is set. Here `28 + 32 + 12 + 42 + 14 + 6` is 134 and the file is
   134 bytes. A length mismatch returns immediately, because every later walk would be reading
   whatever happened to follow.
4. **The envelope, when caps are supplied.** The default caps are the eBPF loader's compile time maxima:
   1024 atoms, 256 nodes, 1024 edges, 4096 program words, 25 steps, 16 stack. An image over any of them
   is refused at admission rather than clamped.
5. **Every atom.** The operator is one of the seven, the constant type is one of the four, and the field
   index is inside `n_fields`. This is where "Level M fragment membership" is re verified on the shipped
   artifact; the compiler already guaranteed it, and this does not take the compiler's word for it.
6. **Every edge.** The target is a real node index, and the edge's program range fits inside the program
   section.
7. **Every program word.** A word below 0x8000 is an atom index and must be inside `n_atoms`; a word at
   or above 0x8000 must be one of the five opcodes. Our program's four atom words are 0 to 3 and its
   three opcode words are all 0x8003.
8. **Every node attribute, when the section is present.** Each must fit in six bits, which is the
   fabric's materialization envelope, two three bit LEDs. Our `[2, 4, 1]` all do.

What `validate_image` deliberately does not check is balance: nothing verifies that a program leaves
exactly one value on the stack. That is the compiler's guarantee, and the hardware does not check it
either, so a hand crafted image with an unbalanced program is outside what any of this defends against.

## The bound: `wcet_cycles`

```
wcet_cycles = max over nodes of ( sum over that node's edges of (2 + max(prog_cnt, 1)) ) + 2
```

For `hyst_band` the worst node is `mid`, with three edges of one program word each:
`3 * (2 + 1) + 2 = 11`.

The shape of that expression comes straight from the interpreter's state machine: two cycles of overhead
per edge, one cycle per program word, and two cycles of overhead per evaluate. For images the compiler
emits, where every edge has at least one word, it reduces to `2E + P + 2`. The `max(prog_cnt, 1)` term
exists for hand crafted images with zero word edges, which still cost one cycle each; that is the
adversarial `3E + P` case the formal work surfaced, and keeping the term makes the expression exact for
both. Because the interpreter is a fixed state machine with no pipeline, no cache and no speculation,
this is an exact count rather than an over approximation, and at clock frequency `f` the time bound is
`wcet_cycles / f`.

Eleven cycles is not only computed, it is witnessed. A logic analyzer watched the fabric's pins over
16,009 evaluations of this policy and recorded a worst case of 9 cycles, inside the 11 the signed
manifest declares. The bound is a bound, not a prediction: the instrument's job is to catch a violation
of it, and the record of that run is in
[hyst-cert/VERIFY.md](hyst-cert/VERIFY.md).

## Loading: from the signed pack to the load port

Verification comes first. `verify_pack` checks the signature over the canonical manifest by a known and
unrevoked key, that the manifest's `key_id` matches the key that verified it, and that the image's hash
and header counts match the manifest. Only then does anything load.

The fabric's interpreter has no parser. It has a **load port**: a three bit selector, an address and a
32 bit data word, and the loader writes the image into it one record at a time. The seven selectors are
the whole interface between the format and the hardware:

| `load_sel` | address | data | the section it fills |
|---|---|---|---|
| 0 | ignored | `visits_idx` | the visits register index |
| 1 | atom index | type in bits 25 and 24, operator in bits 23 to 16, field index in bits 15 to 0 | the atom's shape |
| 2 | atom index | the constant, full 32 bits signed | the atom's constant |
| 3 | node index | edge count in the high half, edge offset in the low half | the node record |
| 4 | edge index | program offset in the high half, target in the low half | the edge record |
| 5 | edge index | program word count | the rest of the edge record |
| 6 | program word index | the word | the program |
| 7 | node index | the node attribute | **ignored by `ppt_interp` itself**; the surrounding datapath consumes it as LED color |

Selector 7 is the one that catches readers out: the interpreter's load case statement has no branch for
it and falls through the default, so writing it is harmless and reading `ppt_interp.sv` alone makes the
node attribute look unimplemented.

Two loaders drive that port with the **identical** write sequence:

- **The processor**, in [pynq/ppt_pynq.py](pynq/ppt_pynq.py). `PptImage` parses the image and the debug
  JSON; `load_image` issues a soft reset, then selector 0, then atoms, nodes, edges and program words in
  order, each as a pair of register writes: the selector and address into one register, the data into
  the next.
- **The fabric itself**, with no processor at all, in `ppt_pack_loader.sv`, whose read only memory is
  generated by [tools/gen_pack_svh.py](tools/gen_pack_svh.py). `policy_writes` emits exactly the
  sequence above, including the node attribute pass on selector 7, and the generator **refuses to emit**
  a policy whose pack fails `verify_pack`. A pytest gate cross checks its parse against `PptImage` so
  the two cannot drift.

The sequence ends, optionally, with one more write: the arm word. It packs `safe_node` into its top
byte, the governed field index and the start node into the middle bytes, and the stateful bit and an
enable bit at the bottom. **The stateful bit and the safe byte come from the signed image header**, so
the execution profile rides the signed replay and a manifest cannot contradict the pack. A policy that
is not armed writes a zero arm word rather than leaving the previous policy's, because a mode inherited
across a swap is a mode negotiated, which is the hole the declared profile exists to close.

## On the fabric

From there the image is the circuit's data and the circuit does not change. On each evaluate the
interpreter takes a node index, walks that node's edges in order, runs each edge's program on a one bit
stack, and reports the first edge whose program leaves true, together with its target. The atoms are
total: a comparison that cannot be performed is unsatisfied rather than an error, so the edge is simply
not taken. With the resident profile armed, the fabric holds the current node itself and free runs,
which is what makes the hysteresis in `hyst_band` a property of the silicon rather than of a host
polling it.

The evidence that this is the same function the reference computes is
[rtl-tb/README.md](rtl-tb/README.md): the conformance gate replays the frozen corpus through this exact
circuit, and the finale gate replays 4,568 corpus events of this exact policy through the whole
datapath.

## Every hand kept mirror of the layout

This is the cost of the design and the reason this document exists. Each of these holds its own copy of
the offsets, the widths or the flag numbers. None of them can move alone.

| where | what it holds | what moving it costs |
|---|---|---|
| [ppt_compile.py](ppt_compile.py) | the writer, the only producer of images | every artifact and every hash in the ledger |
| [TABLE_FORMAT.md](TABLE_FORMAT.md) | the prose specification and the declared subset | the specification of record; note its layout block predates the flags and safe_node split |
| [../prismpath/hotswap/policy_pack.py](../prismpath/hotswap/policy_pack.py) | the Python reader: the header, atom, node, edge and word struct formats, the operator and type sets, the opcode set, the flag constants, the envelope caps | the pack tooling and the signing path |
| [interp.c](interp.c) | the C reference, decoding each section into heap structs | a recertification against the conformance corpus |
| [ppt_eval.h](ppt_eval.h) | the embedded evaluator, keeping section offsets into a static buffer | a recertification on every firmware that includes it |
| [rtl/ppt_interp.sv](rtl/ppt_interp.sv) | the load port's seven selectors and the field packing of each | a synthesis and a silicon recertification |
| [pynq/ppt_pynq.py](pynq/ppt_pynq.py) | `PptImage`, a second full parse, plus the processor's load sequence | the board's loader and the hot reload path |
| [tools/gen_pack_svh.py](tools/gen_pack_svh.py) | `parse_ppt`, a third full parse, plus the baked write sequence and the arm word packing | the in fabric loader's read only memory, and a resynthesis |
| [../prismpath-hotswap-rs/src/lib.rs](../prismpath-hotswap-rs/src/lib.rs) | the Rust mirror: the magic, the 28 byte header size, the header struct and the capped structural walk | the Rust consumers |
| [../prismpath-ebpf/ppt_common.h](../prismpath-ebpf/ppt_common.h) | the kernel structs and the compile time maxima that `DEFAULT_CAPS` is a copy of | a kernel loader recertification on both architectures |
| the firmware ports on the pending list in [eval_copies_check.py](eval_copies_check.py) | eight microcontroller firmwares still carrying a local copy of the evaluator, two of which switch on raw opcode literals rather than named constants | a hardware recertification each, on a board, which is why the conversion is tracked rather than done |
| the corpus and certification scripts (`../prismpath-ebpf/cert_corpus.py`, `hyst-cert/cert_hyst_board.py`, `../prismpath/comparisons/groupa/cross_substrate_corpus.py`, `mesh/gen_mesh_tables.py`) | partial parses, each reading the fields it needs | the evidence each produces |

The direction of travel is fewer of these, not more. `eval_copies_check.py` is the instrument for the
firmware half of the list: it reports which firmwares include the one shared evaluator and which still
carry a local copy, with a named recertification procedure for each one that has not converted yet. The
same move for the loaders and the wire structs has not been made, and until it is, this table is the
list of places to change together.

## What checks the format

- `make cert` runs the frozen conformance corpus through `interp.c` and through `ppt_eval.h`, and then
  checks the firmware copies.
- `make -C tb` runs the same corpus through the interpreter circuit under simulation, with every policy
  loaded at run time through the load port, because the claim is one fixed circuit and any conformant
  flow as data.
- `make -f Makefile.finale_hyst` in [rtl-tb](rtl-tb/README.md) replays this policy's own signed load
  sequence into the whole datapath and checks 4,568 corpus events against the resident band.
- [tools/test_gen_pack_svh.py](tools/test_gen_pack_svh.py) cross checks the generator's parse against the processor's, so the two
  loaders cannot disagree about what an image says.
