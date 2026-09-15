# Walking the C evaluator

*A companion to [interp.c](interp.c) and [ppt_eval.h](ppt_eval.h), for a reader who knows what a match
action table is but has never opened these two files. Read it beside the code. The vocabulary is
[docs/DICTIONARY.md](../docs/DICTIONARY.md); the binary format is [TABLE_FORMAT.md](TABLE_FORMAT.md).*

## Why this document exists

These two files are the same function written twice. `interp.c` is the reference: it allocates, it reads
files, and it exits when an image is malformed. `ppt_eval.h` is that same evaluator written for a
microcontroller: no allocation, fixed buffers, and a return code for every failure. Their claim is that
they decide identically, and `make cert` runs both against the frozen conformance corpus to hold them to
it.

Because that claim is certified byte for byte, the identifiers in both files cannot be renamed without a
recertification, and some of them are short and unhelpful (`a`, `e`, `im`, `sp`, `tbl`, `w`). The
dictionary's rule twelve says that where a rename would move certified bytes, the walkthrough is written
instead of the rename. This is that walkthrough. Nothing here asks you to change the code; it tells you
what the code already does, in words the rest of the repository uses.

## What the evaluator is for

One evaluator call takes a node index and a register file and returns the position of the first edge of
that node whose predicate is satisfied. That is the smallest unit of decision in the system. Everything
else in these two files exists to get an image into memory and a register file filled so that this one
call can happen.

An **image** is the compiled flow: a header, a deduplicated pool of atoms, a node table, an edge table,
and a flat array of program words. A **register file** is one typed slot per field, a type tag and a
32 bit value. An **atom** is one `field OPERATOR constant` test and is total, meaning it is satisfied or
unsatisfied and never an error. A **program** is the word list that folds a node edge's atom results into
one boolean. A node's edges are tried in document order and the first satisfied one wins, which is why
the evaluator is described everywhere as a priority encoder.

## The image as it sits in memory

The image is one contiguous little endian byte string, laid out in [TABLE_FORMAT.md](TABLE_FORMAT.md).
Reading order matters because every section is found by walking the one before it:

```
offset 0    header, 28 bytes
              magic "PPTM", version 1,
              n_fields, n_interns, n_atoms, n_nodes, n_edges, prog_len,
              start_node, visits_idx, max_steps, max_stack, flags

offset 28   atoms   n_atoms entries of 8 bytes   field, operator, constant type, constant value
then        nodes   n_nodes entries of 4 bytes   edge_off, edge_cnt   (edge_cnt 0 means terminal)
then        edges   n_edges entries of 6 bytes   target, prog_off, prog_cnt
then        prog    prog_len words of 2 bytes
then        colors  n_nodes words of 2 bytes, present ONLY when flags bit 0 is set
```

The two files hold that same string in two different ways, and this is the first thing to keep straight.
`interp.c` copies it out: it walks the bytes once at load time and fills four heap arrays of decoded C
structs, then never touches the original bytes again. `ppt_eval.h` leaves it alone: it keeps the bytes in
a static buffer named `tbl` and records four offsets (`atoms_off`, `nodes_off`, `edges_off`,
`prog_off_base`), so every later read is an offset computation and a two or four byte load out of the
buffer. The reference trades memory for decoded structs; the embedded copy trades that for a buffer whose
size a firmware can state at compile time.

## Preconditions, which the code relies on and does not state

Both files evaluate a signed image that a pack loader has already verified. Signature and envelope
checking happen upstream, in `prismpath/hotswap/`, not here, and neither file repeats them. Inside the
evaluator, that upstream verification is what stands behind the following, each of which is assumed
rather than tested:

- Every atom's `field` is less than `n_fields`. Neither `eval_atom` bounds checks it. In `interp.c` a
  larger field index reads past the end of the heap register array; in `ppt_eval.h` it reads past the end
  of `regs`, which is `4 + 8 * PPT_MAX_FIELDS` bytes. The compiler guarantees this and nothing at runtime
  does.
- Every edge's `prog_cnt` is at least 1. Both `eval_prog` functions return `stack[0]` unconditionally, so
  an edge with an empty program returns whatever was in that stack slot, which in `interp.c` is
  uninitialized stack memory. The compiler never emits an empty program; keyword rows such as `always`
  emit a one word constant true program precisely so that this stays true.
- Every edge's program is well formed reverse Polish: it ends with exactly one value on the stack, and
  every `NOT` has one operand and every `AND` or `OR` has two beneath it. Neither file checks the stack
  depth before an operator pops; an underflowing program indexes `stack[-1]`.
- Every `target`, `edge_off` and `prog_off` is in range for its section. Only `ppt_eval.h` checks the
  start node, and it checks nothing else.
- In `ppt_eval.h`, the image and the register file are file scope statics. One translation unit holds one
  image at a time, and two translation units that both include the header get two independent images with
  no diagnostic. A firmware that includes it from more than one source file is not doing what the header
  assumes.

## The functions, in reading order

### `rd16` and `rd32` in the reference, `rd16b`, `rd32` and `wr32` in the header

These are the little endian loads. `rd16` assembles two bytes by hand so that the result does not depend
on the host's byte order or on alignment; `rd32` does the same for four bytes and casts to a signed 32 bit
value, which is the type every constant and every register value has. The header's `rd32` and `wr32` use
`memcpy` instead of shifts, which a compiler turns into a single unaligned load or store and which is the
standard way to say "read these four bytes as an integer" without invoking an aliasing rule. The header
names its 16 bit reader `rd16b` only because a firmware including it may already have an `rd16`.

### `read_file` in the reference

Opens a file, seeks to the end to learn its length, allocates that many bytes, reads them in one call and
returns the buffer with the length written through an out parameter. Every failure is a message on
standard error and `exit(2)`. This is the reference's whole input layer and it is host only; the header
has no counterpart, because a firmware has already received its image over a wire or has it linked in as
a byte array.

### `load_image` in the reference

Reads the file, checks that it is at least 28 bytes long and that the magic and version match, then copies
the ten header counters into an `Image` struct. It computes the minimum length the image must have from
those counters, `28 + 8 * n_atoms + 4 * n_nodes + 6 * n_edges + 2 * prog_len`, and refuses anything
shorter. Then it allocates four arrays and decodes each section into them, advancing one cursor through
the byte string, and frees the raw buffer. Note what it does not do: it never reads the flags word at
offset 26, so it never knows whether a color section follows, and its minimum length therefore does not
include one. It also never checks the start node. See "Differences that are deliberate" below.

### `parse_table` in the header

The same work against the bytes already sitting in `tbl`, where the caller has placed `len` of them. It
returns a `ppt_parse_rc` rather than exiting: `PPT_PARSE_SHORT` (3) for too short, truncated, or a start
node out of range, `PPT_PARSE_BAD_MAGIC` (1), and `PPT_PARSE_CAPS` (4) when the image is bigger than this
build was compiled to hold. It reads the flags word, adds `2 * n_nodes` to the required length when bit 0
says a color section is appended, and compares the result against three compile time caps before it
compares it against the length the caller passed. When it succeeds it stores the four section offsets and
nothing else; there is no decode pass, so parsing is a few dozen instructions and a firmware can afford to
do it on every policy swap.

### `eval_atom`

One atom against one register, and the place where the totality rule lives. Both copies read the atom's
four parts and the register's type and value, classify each side as numeric (`BOOL` or `INT`) or not, and
then branch on the operator. Equality compares numerically when both sides are numeric, by interned
identifier when both are strings, is true when both sides are `NONE`, and is false for every other pairing
of types; inequality is exactly its negation. The four ordering operators are satisfied only when both
sides are numeric and are **unsatisfied** otherwise, never an error, which is the rule that lets a missing
field appear in a comparison without raising. Truthiness is false for `NONE` and otherwise "value is not
zero", which is correct for all three remaining types because the empty string interns to identifier 0.
The two copies differ only in how they reach the operands: the reference indexes decoded arrays, the
header computes offsets into `tbl` and `regs`.

In the language of [TABLE_FORMAT.md](TABLE_FORMAT.md) section "Semantics the interpreter must reproduce",
the whole function is this:

```
atom  = (field, operator, constant)
value = register_file[field]        # a (type, number) pair; a missing field is NONE

if operator is EQUAL or NOT_EQUAL:
    if value and constant are both numeric:      equal = (value.number == constant.number)
    elif value and constant are both STR:        equal = (value.number == constant.number)   # intern ids
    elif value and constant are both NONE:       equal = true
    else:                                        equal = false
    return equal if operator is EQUAL else not equal

if operator is LESS, LESS_OR_EQUAL, GREATER or GREATER_OR_EQUAL:
    if either side is not numeric:  return unsatisfied      # totality, never an error
    return the ordinary signed comparison of the two numbers

if operator is TRUTHY:
    if value is NONE:  return unsatisfied
    return value.number != 0                               # "" interns to 0, so it is falsy

return unsatisfied     # unreachable for a compiled image; an unknown operator is unsatisfied
```

### `eval_prog`

One edge's predicate. The program is reverse Polish over atom results, run on a stack of bytes. A word
below `0x8000` is an atom index: evaluate that atom and push its result. The five words at and above
`0x8000` are the operators: `NOT` inverts the top, `AND` and `OR` pop one operand and combine it with the
new top, and `TRUE` and `FALSE` push a constant. The result is the single value left on the stack. Both
copies check the stack bound before a push and neither checks it before a pop, which is the precondition
above. The reference calls `overflow()`, which prints and exits; the header writes
`PPT_EVAL_STACK_OVERFLOW` (7) or `PPT_EVAL_BAD_OPCODE` (8) into the caller's error byte and returns 0.

```
function eval_prog(program_words):
    stack = empty
    for word in program_words:
        if word < 0x8000:
            if stack is full: overflow            # reference exits; header returns error 7
            push eval_atom(atom[word])
        elif word is NOT:    top = not top
        elif word is AND:    right = pop; top = (top and right)
        elif word is OR:     right = pop; top = (top or right)
        elif word is TRUE:   if stack is full: overflow ; push true
        elif word is FALSE:  if stack is full: overflow ; push false
        else:                bad opcode           # reference exits; header returns error 8
    return stack[0]                               # a well formed program leaves exactly one value
```

No short circuit is observable. Every atom of an edge's program is evaluated whether or not an earlier one
already settled the answer, which is sound because atoms are total and free of side effects, and which is
what makes the worst case execution bound depend on the counts alone.

### `evaluate`

The priority encoder, and the call an outside caller actually wants. It reads the node's `edge_off` and
`edge_cnt`, walks the node's edges in order, runs each edge's program, and returns the position of the
first satisfied one; it returns minus one when the node has no edges or when none of them is satisfied.
The returned value is a **position within the node's edge list**, not an index into the global edge table,
which is why every caller has to add `edge_off` back to recover the edge. The header's copy additionally
writes the matched edge's target through an out parameter and, after each edge, checks the error byte and
gives up on an evaluation error rather than continuing to the next edge.

```
function evaluate(node, register_file):
    for position in 0 .. node.edge_cnt - 1:
        edge = edges[node.edge_off + position]
        if eval_prog(edge.program):
            return position, edge.target          # first true wins, document order
    return no_match
```

### `mode_eval` in the reference

The `interp eval image.ppt regs.bin` command line. It reads a register file in the `regs.bin` encoding, a
four byte node index followed by `n_fields` pairs of 32 bit type and value, insists that the file is
exactly that size, refuses a node index that is not a real node, decodes the pairs into the register
array and calls `evaluate` once. It prints `match <position> <target>` or `none`. This is the harness the
conformance corpus drives, so those two strings are compared byte for byte and must never change.

### `mode_run` in the reference

The `interp run image.ppt script.bin` command line, and the only place in either file where a whole run
happens rather than a single decision. A script holds, per node, the sequence of outcomes a scripted
worker will emit on successive visits to that node. `mode_run` indexes the script, then loops at most
`max_steps` times: a node with no edges ends the run as `terminal`; otherwise the node's visit counter is
incremented **before** the register file is filled, which is what the general engine does and is the
reason a predicate reading `visits` sees 1 on the first visit; the register file is loaded from that
node's outcome row, using the last row again once the visits run past the end of the list; if the image
declares a `visits` register, the counter is written into it, overriding anything the script put there; and
then `evaluate` decides the next node. A node with no satisfied edge ends the run as `stuck`, and running
out of iterations ends it as `max_steps`. It prints `N <node>` for the start node and for every node it
moves to, then one `S <stop state>` line. `interp_hdr.c` reproduces this loop on top of the header so that
the same corpus certifies both.

```
node = start_node
print "N", node
repeat at most max_steps times:
    if node has no edges:                 print "S terminal" ; stop
    visits[node] = visits[node] + 1                       # before the worker, as the engine does
    row = outcomes[node][ min(visits[node] - 1, count(outcomes[node]) - 1) ]
    register_file = row
    if visits_idx is declared:            register_file[visits_idx] = INT visits[node]
    position, target = evaluate(node, register_file)
    if no match:                          print "S stuck" ; stop
    node = target
    print "N", node
print "S max_steps"
```

### The embeddable API in the reference

`interp.h` wraps the same certified core for an application that wants to link the evaluator rather than
run the command. `ppt_image_open` allocates a handle and loads an image into it, `ppt_image_close` frees
the four arrays and the handle, and three accessors expose the start node, the field count and the node
count so a caller can size its own register array. `ppt_evaluate_node` is the whole interface to a
decision: it refuses a node index that is out of range with `PPT_EVAL_BAD_NODE`, calls the same
`evaluate`, and writes the matched edge's target through an optional out parameter. A `_Static_assert`
holds the public `ppt_reg` and the internal register cell to the same layout, so the cast between them is
not a hope. The contract is stated in the header and worth repeating: this is the evaluator, not the
verifier, and a malformed image still exits, because the CLI and the embedding application are meant to
run the identical code path.

### The register accessors in the header

`node_edge_count` reads one node's edge count without a full `evaluate`, which is how a firmware detects a
terminal node in its own run loop. `set_reg` writes an `INT` typed value into a field's slot,
`set_reg_typed` writes any type, and `get_reg` reads a value back. A firmware's front end calls these to
turn measurements into a register file and then calls `evaluate`; that is the entire integration surface,
and it is why `ppt_eval.h` has no `mode_run` of its own.

## The same function on three substrates

The three implementations that must agree, and what each calls the same thing. Use this table to read one
against another; none of these names can move without recertifying the substrate it belongs to.

| what it is | `interp.c` | `ppt_eval.h` | `rtl/ppt_interp.sv` |
|---|---|---|---|
| little endian 16 bit read | `rd16` | `rd16b` | none; the load port receives whole words |
| little endian 32 bit read | `rd32` | `rd32` | none; same |
| get the image in | `read_file` plus `load_image` | caller fills `tbl`, then `parse_table` | the load port: `load_en`, `load_sel` 0 to 6, `load_addr`, `load_data` |
| the parsed image | the `Image` struct and four heap arrays | file scope statics plus four section offsets | `atom_field`, `atom_op`, `node_eoff`, `node_ecnt`, `edge_tgt`, `edge_poff`, `edge_pcnt`, `prog` |
| one atom | `eval_atom` | `eval_atom` | `atom_true`, a combinational function |
| one edge program | `eval_prog` | `eval_prog` | state `S_RUN`, one word per clock |
| the priority encoder | `evaluate` | `evaluate` | the `S_IDLE` to `S_EDGE` to `S_RUN` to `S_DONE` machine |
| the operand stack | `stack[STACK_MAX]` with `sp` | `stack[STACK_MAX]` with `sp` | `stk`, one bit per slot, with `sp` |
| the register file | `Reg regs[]` | the `regs` byte array, through `set_reg` and `get_reg` | `f_ty` and `f_v`, written through the field port `fld_we`, `fld_idx`, `fld_type`, `fld_val` |
| the visits counter | `visits[]` inside `mode_run` | the caller's own, written with `set_reg` | the visits counter bank: `bump_en`, `bump_node`, `use_visits` |
| ask for one decision | `ppt_evaluate_node` | `evaluate` | pulse `start` with `node_idx` |
| get the answer back | the return value plus `out_target` | the return value plus `out_target` | `done` pulses with `match`, `match_edge`, `target` |

The fabric's arrangement is worth one sentence, because it is the reason the format looks the way it does.
In silicon the atoms are comparators standing in parallel over the field registers, and the edge loop and
the program loop are states of one machine; the worst case per decision is therefore derivable from the
counts alone, `2 * edges + program words + 2` cycles for a real policy, which is what lets a signed image
carry a worst case execution bound.

## Differences that are deliberate

Four places where the reference and the embedded header do not read alike. All four are intended, and all
four leave the decision identical for any image inside the declared subset, which is what the corpus
checks.

**1. Return codes instead of exits.** Every failure in `interp.c` prints to standard error and calls
`exit(2)`: a file that will not open, a bad magic, a truncated image, a bad register file size, a node out
of range, a stack overflow, an unknown opcode. A firmware cannot exit, so `ppt_eval.h` returns instead.
`parse_table` returns a `ppt_parse_rc` and `eval_prog` writes a `ppt_eval_rc` into the caller's error byte,
and `evaluate` checks that byte after every edge so an error stops the walk rather than being read as a
non match. These two enumerations are the header's own small namespace, deliberately kept stable since the
first firmware. **They are not registry causes.** A caller that puts a refusal on the wire maps them to a
cause from `prismpath/kernel/causes.py`; the numbers 1, 3, 4, 7 and 8 mean nothing outside this header.

**2. The caps checks.** The reference sizes itself to the image: it allocates whatever `n_atoms`,
`n_nodes`, `n_edges` and `prog_len` ask for, and its operand stack is a fixed 64 bytes with no relation to
the image's declared `max_stack`. The header cannot allocate, so it refuses instead. `parse_table` returns
`PPT_PARSE_CAPS` when the image needs more bytes than `TBL_MAX`, when it names more fields than
`PPT_MAX_FIELDS`, or when its declared `max_stack` exceeds this build's `STACK_MAX`. Those three macros
are the whole configuration surface of the header, and the check means a firmware refuses an oversized
policy at parse time rather than overrunning a buffer at decision time. It is also the only place in
either file where `max_stack` is read at all.

**3. The length rule.** Both compute the same minimum length from the counters. The header then does two
things the reference does not. It reads the flags word at offset 26 and, when bit 0 says a per node color
section is appended, adds `2 * n_nodes` to the requirement, so a firmware that drives an LED from the
image will not accept an image whose color section was truncated away. And it requires `n_nodes` to be non
zero and `start_node` to be a real node, which the reference checks nowhere. The reference does not read
offset 26 at all, so for the same colored image the two files compute different minimum lengths, the
reference's being the smaller. Neither decision changes: the color section sits after everything the
evaluator reads.

**4. The stack check placement.** This one used to be a real divergence and is now closed, and it is listed
here because the closure is the interesting part. The header has always tested `sp >= STACK_MAX` *before*
writing `stack[sp++]`. The reference tested it after the write, so a push past the end corrupted the frame
before the diagnostic fired, and the comparison was off by one besides. The reference was moved onto the
header's discipline rather than the other way round, and `interp.c` now carries a comment saying the check
is before the write and never after it. What remains is a difference of depth and of reporting, not of
placement: the reference's stack is 64 deep and overflow exits, the header's is a macro defaulting to 256
and overflow returns error 7. Any predicate in the declared subset folds left associatively and stays two
or three deep, so neither bound is reachable from a compiled flow.

## What certifies this

`make cert` in this directory is the gate, and it has three legs:

1. `run_vectors.py` drives `build/interp`, the reference, against the frozen conformance corpus in
   `prismpath/portable/conformance/`, reporting every vector outside the declared subset with a machine
   readable reason rather than skipping it silently.
2. `run_vectors.py --interp build/interp_hdr` drives `interp_hdr.c`, which is `ppt_eval.h` given
   `interp.c`'s command line and output format, against that same corpus. Two programs, one corpus, same
   verdicts: this is the whole basis for calling the header the same evaluator.
3. `eval_copies_check.py` walks the firmware sources and reports which of them include `ppt_eval.h` and
   which still carry a local copy of `eval_atom`. A local copy is tolerated only while it is on the
   pending list with a named recertification procedure, because converting a firmware changes the bytes on
   a device and the device has to be recertified before that lands.

The fabric is certified separately, against the same corpus, under cocotb and then on silicon; see
[TABLE_FORMAT.md](TABLE_FORMAT.md) and the hardware records in [hyst-cert/VERIFY.md](hyst-cert/VERIFY.md).
The eBPF target is certified separately again, and its own companion document is
[../prismpath-ebpf/EVALUATOR_WALKTHROUGH.md](../prismpath-ebpf/EVALUATOR_WALKTHROUGH.md).
