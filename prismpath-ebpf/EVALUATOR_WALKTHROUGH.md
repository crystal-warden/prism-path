# Walking the eBPF evaluator

*A companion to [ppt_eval_bpf.h](ppt_eval_bpf.h) and the four XDP programs that include it, for a reader
who knows what a match action table is and what XDP is, but has never opened these files. Read it beside
the code. The vocabulary is [docs/DICTIONARY.md](../docs/DICTIONARY.md); the binary format is
[../prismpath-hw/TABLE_FORMAT.md](../prismpath-hw/TABLE_FORMAT.md); the reference semantics are
[../prismpath-hw/interp.c](../prismpath-hw/interp.c), walked in
[../prismpath-hw/EVALUATOR_WALKTHROUGH.md](../prismpath-hw/EVALUATOR_WALKTHROUGH.md).*

## Why this document exists

The evaluator here decides identically to the C reference, but it does not look like it. Nothing in its
shape was chosen for readability: a `switch` stands in for an array index, two callbacks stand in for two
nested loops, and a map stands in for a local array, each because the alternative did not load. The
verifier, not taste, wrote this code.

That makes it exactly the kind of file the dictionary's rule twelve is about. The programs are certified
behaviorally, by replaying a frozen corpus in kernel, so the text can be reorganized but the decisions
cannot move; and a reader who does not know which limit forced which shape will reasonably try to
"simplify" it back into something that will not load. This document says what each piece computes in
domain terms, shows what the same evaluator would look like with no verifier in the room, and lists the
invariants a change has to preserve.

## One evaluator, four front ends

Since the four XDP programs were folded onto one text, the split is clean. **The evaluator is shared**:
`eval_atom`, the operand stack, both loop callbacks, `evaluate`, the per packet register file and the
payload register fill all live in [ppt_eval_bpf.h](ppt_eval_bpf.h), one copy, included by all four
programs after the table maps they read. **The front end is each program's own**: how a packet becomes a
register file, which node the walk starts from, and what happens to the decision afterwards.

| program | what its front end is | its single delta from the base |
|---|---|---|
| [ppt_xdp.bpf.c](ppt_xdp.bpf.c) | a crafted PPT packet carries the node index and the register file | none; this is the program the in kernel conformance corpus certifies |
| [ppt_net.bpf.c](ppt_net.bpf.c) | a live Ethernet, IPv4, TCP or UDP packet fills a fixed canonical schema | two banks of every table map, so a policy swap commits atomically under traffic |
| [ppt_select.bpf.c](ppt_select.bpf.c) | a crafted PPT packet, but the start node is resident state, not the packet | a generation counter compare and swap commit, plus one audit receipt per committed transition |
| [a6/ppt_xdp.bpf.c](a6/ppt_xdp.bpf.c) | a crafted PPT packet, same as the base | the decision is written back into the packet, and a short payload is refused with a sentinel |

An earlier arrangement kept four hand maintained copies of the evaluator and a comment saying they were
meant to agree. The certifications are behavioral rather than object bytes, so sharing the text left every
score untouched.

## The bounds, and why each one exists

The constants are in [ppt_common.h](ppt_common.h). They fall into three groups, and confusing them is the
usual way a change goes wrong.

**Table capacities**: `MAX_ATOMS` 1024, `MAX_NODES` 256, `MAX_EDGES` 1024, `MAX_PROG_WORDS` 4096. These
size the maps that hold the image. Every one is a power of two, and that is load bearing rather than
tidy: every map key is masked with `& (capacity - 1)` before the lookup, which is what lets the verifier
see the key as being in range without a comparison it would have to prove.

**Loop dimensions**: `MAX_EDGES_PER_NODE` 64, `MAX_PROG_PER_EDGE` 64, `MAX_FIELDS_PER_PKT` 32. The first
two are the iteration caps handed to `bpf_loop`, whose callback is verified once no matter how many times
it runs, so they cost the verifier nothing. The third is the length of the register fill loop, which is
unrolled and verified once. A packet naming more than 32 fields is not refused by the base program: the
fill stops at the cap and the rest of the register file is `TY_NONE`. A policy needing more fields than
that, such as the 128 field vision class table, does not belong on this substrate as built.

**The one real subset limit**: `STACK_MAX` 4, the operand stack depth of an edge's program. This is not an
array size that could simply be raised. It is the number of cases in the `st_get` and `st_put` switches,
so every stack slot is a compile time constant to the verifier. Level M expressions fold left
associatively, so a flat `and` or `or` chain, membership in a literal list included, stays at depth 2, and
4 covers real nesting. A predicate deeper than 4 is outside this target's declared subset. Be honest about
what enforces that: the image's `max_stack` rides in the header and the loader copies it into
`config_map`, but no program compares it against `STACK_MAX`, so the guard today is the compiler and the
corpus, not a refusal at load. A deeper program would silently drop its pushes rather than refuse.

**The 512 byte stack budget** is not a constant anywhere; it is the kernel's limit on a BPF program's
frame, and two decisions exist only to stay under it: the register file lives in a map rather than in
either loop context, and `evaluate` is forced `__noinline` so that it gets its own frame instead of
stacking onto the entry program's.

## What it would look like without the verifier

The same evaluator, written as plain C, is about fifteen lines:

```
function evaluate(node_index, register_file):
    node = nodes[node_index]
    for position in 0 .. node.edge_cnt - 1:
        edge = edges[node.edge_off + position]
        stack = empty
        for word in prog[edge.prog_off .. edge.prog_off + edge.prog_cnt - 1]:
            if word < 0x8000:   push eval_atom(atoms[word], register_file)
            elif word is NOT:   top = not top
            elif word is AND:   right = pop; top = (top and right)
            elif word is OR:    right = pop; top = (top or right)
            elif word is TRUE:  push true
            elif word is FALSE: push false
        if stack[0]:
            return position, edge.target       # first true wins, document order
    return no_match
```

And here is the same thing as it is actually written, with the four substitutions named:

```
function evaluate(node_index, n_fields, bank):          # __noinline: it needs its own 512 byte frame
    node = LOOKUP(nodes_map, bank_base(bank, MAX_NODES) + (node_index & (MAX_NODES - 1)))
    if node is NULL: return no_match                    # every lookup is NULL checked
    edge_state = { edge_off, edge_cnt, n_fields, bank, matched = -1, target = -1 }
    bpf_loop(MAX_EDGES_PER_NODE, edge_loop_cb, edge_state)      # substitution 1: the outer for loop
    return edge_state.matched, edge_state.target

function edge_loop_cb(edge_index, edge_state):
    if edge_index >= edge_state.edge_cnt: return STOP
    edge = LOOKUP(edges_map, bank_base(...) + ((edge_off + edge_index) & (MAX_EDGES - 1)))
    if edge is NULL: return CONTINUE                    # missing edge skipped, as the reference continues
    prog_state = { prog_off, prog_cnt, n_fields, bank, st = [0,0,0,0], sp = 0 }
    bpf_loop(MAX_PROG_PER_EDGE, prog_word_cb, prog_state)       # substitution 2: the inner for loop
    if prog_state.sp > 0 and st_get(prog_state.st, 0):
        edge_state.matched = edge_index ; edge_state.target = edge.target ; return STOP
    return CONTINUE

function prog_word_cb(word_index, prog_state):
    if word_index >= prog_state.prog_cnt: return STOP
    word = LOOKUP(prog_map, bank_base(...) + ((prog_off + word_index) & (MAX_PROG_WORDS - 1)))
    ... the same five operators, but every stack access goes through
        st_get(st, index) / st_put(st, index, value)            # substitution 3: no st[runtime_sp]
        and every push is guarded by  if sp < STACK_MAX

function eval_atom(atom, n_fields):
    register_file = LOOKUP(regs_map, 0)                         # substitution 4: not a local array
    ... then exactly interp.c's totality rules
```

The four substitutions, and what each one bought:

1. **Two `bpf_loop` callbacks instead of two nested `for` loops.** The verifier explores reachable states,
   not instructions, and a nested interpreter multiplies them. Plain loops at 64 by 64 hit the 8192 jump
   limit; at 16 by 16 they processed 1,000,001 instructions against a 1,000,000 limit. `bpf_loop` verifies
   a callback once regardless of iteration count, so both loops became free and the loop bounds went back
   to full size. This needs kernel 5.17 or newer.
2. **A constant indexed operand stack instead of `st[sp]`.** A runtime variable index made the verifier
   explore every possible stack pointer at every access. The `switch` in `st_get` and `st_put` turns every
   access into a compile time constant slot. Necessary but not sufficient on its own: it shrank the
   verifier log from 259k lines to about 10k while the state count still plateaued near 47k.
3. **A per CPU map for the register file instead of a stack array.** XDP runs a packet to completion on one
   CPU, so one per CPU slot is private to the run. Embedding the register file in each loop context
   overran the 512 byte stack budget ("combined stack size ... Too large"), and looking a field up one at
   a time was a helper call per field that re exploded the state count. One lookup of one map value, then
   an unrolled fill, verified once.
4. **`evaluate` forced `__noinline`.** Inlining it stacked its context onto the entry program's frame and
   overran the same budget. As a separate sub program it gets its own.

With all four in place the base program loads at full bounds, processing about 150k of the million
instruction budget.

## The functions, one paragraph each

### `ppt_regs`

The single lookup of the per CPU register file, returning a pointer to the one `struct ppt_regfile` value
or NULL if the map is gone. Every caller checks for NULL, because the verifier requires it and because a
missing register file has to mean "everything is `TY_NONE`" rather than a fault. It exists as its own
function so that the zero key and the map name appear once.

### `eval_atom`

One atom against one register, and the totality rules of
[../prismpath-hw/interp.c](../prismpath-hw/interp.c) line for line: equality numeric when both sides are
numeric and by interned identifier when both are strings, `NONE` equal to `NONE` and nothing else, the four
ordering operators unsatisfied rather than erroring when either side is not numeric, truthiness false for
`NONE` and otherwise "not zero". What is local to this substrate is how it gets the register: it looks the
per CPU register file up itself, and if the lookup fails or the atom's field is at or beyond either
`MAX_FIELDS_PER_PKT` or the packet's declared field count, it substitutes a `TY_NONE` register rather than
refusing. That substitution is not a shortcut; it is the totality rule, which says a field that is not
there is `NONE`, and it is what lets the bounds check double as the semantics.

### `st_get` and `st_put`

Read and write one slot of the operand stack by index. Both are a `switch` over the four legal indices
with a default that reads zero or writes nothing. They exist for exactly one reason, given above: an
index the verifier can fold to a constant. Treat the pair as the stack's whole interface, and note the
default arms are silent, so a bug that walked off the end of the stack would produce a wrong answer rather
than a diagnostic. `STACK_MAX` and the number of cases must be changed together.

### `prog_word_cb`

The program machine, one reverse Polish word per call, carrying its state in a `struct prog_ctx` that
holds the program offset and count, the field count, the bank, the four byte operand stack and the stack
pointer. It stops the loop when the index reaches the program's length, which is how a 64 iteration
`bpf_loop` runs a three word program. Otherwise it masks the word's index into `prog_map`, looks the word
up, and either evaluates the atom it names and pushes the result, or applies one of `NOT`, `AND`, `OR`,
`TRUE`, `FALSE`. Every push is guarded by `sp < STACK_MAX` and every pop by a check that enough operands
are present, so a malformed program mangles its own answer and cannot touch anything else. The choice to
make this a loop of its own rather than inline code is what finally fit the interpreter under the
instruction budget: the stack machine state is mutated across words inside one context that is verified
once.

### `eval_prog`

One edge's predicate. It builds a fresh `prog_ctx`, clamps the program length to `MAX_PROG_PER_EDGE`, runs
the `prog_word_cb` loop, and returns the bottom of the stack, or 0 if nothing was ever pushed. That last
clause is the one visible divergence from the reference, which returns `stack[0]` unconditionally and so
reads an uninitialized slot for an empty program; here an empty program is unsatisfied. The compiler never
emits one, so no vector distinguishes them.

### `edge_loop_cb`

The body of the priority encoder, one edge per call. It stops when the index reaches the node's edge
count, masks the edge's index into `edges_map`, and skips a missing edge by continuing, mirroring what the
reference does when it walks past an edge it cannot use. If the edge's program is satisfied it records the
edge position and the target node in the shared context and stops the loop, which is "first true wins" in
`bpf_loop` terms. The recorded position is a position within the node's edge list, not an index into the
whole edge table, which is the same convention the reference uses.

### `evaluate`

The priority encoder itself, and the only function here that is deliberately not inlined. It masks the
node index into `nodes_map`, returns no match if the node is missing, clamps the node's edge count to
`MAX_EDGES_PER_NODE`, seeds an `eval_loop_ctx` with the edge range and the bank, runs the `edge_loop_cb`
loop, and writes the matched edge position and target node through its two out parameters. It returns 0
when something matched and minus 1 otherwise, so a caller reads the return value for "did we decide" and
the out parameters for "what did we decide".

### `ppt_load_regs_from_payload`

The register fill for the three programs whose front end reads a register file straight out of a crafted
packet's payload. It is an unrolled loop over all `MAX_FIELDS_PER_PKT` slots, writing each field's type
and value from the payload when that field is both within the declared field count and within the packet's
bounds, and `TY_NONE` otherwise. Two details are deliberate. Every slot is written on every packet, so no
value survives from the previous packet on this CPU. And the destination index is masked even though the
loop bound already implies the range, because the mask is what lets the verifier bound the offset into the
map value. `ppt_net` does not use this function; it fills a fixed schema from a real packet instead.

### `ppt_xdp_prog` in [ppt_xdp.bpf.c](ppt_xdp.bpf.c)

The base front end and the conformance program. It looks for the PPT magic twice, first at the very start
of the packet, which is how the corpus harness injects a bare context, and then after an Ethernet, IPv4
and UDP header, which is how a real sender delivers one. A packet with neither is passed through
untouched. It clamps the declared field count, fills the register file from the payload, evaluates the
node the packet names, and writes the matched edge, the target node, a status and a packet counter into
`result_map`. It always returns `XDP_PASS` and changes nothing outside that one map, which is what makes
it safe to attach anywhere and suitable as the thing the corpus judges.

### `ppt_net_prog` in [ppt_net.bpf.c](ppt_net.bpf.c)

The live traffic front end. There is no PPT magic here; the packet is ordinary traffic and the program
parses it. It walks Ethernet, requires IPv4, walks the IP header by its own length field, and reads the
TCP or UDP ports and the TCP flags byte when the protocol has them. It then clears the whole register file
to `TY_NONE` and writes the eight canonical fields, `0 src_ip`, `1 dst_ip`, `2 src_port`, `3 dst_port`,
`4 protocol`, `5 pkt_len`, `6 tcp_flags`, `7 ttl`, all as `TY_INT`, addresses in host order. Those indices
are an interface: the flow is compiled with that schema pre seeded so the field numbers line up, and
changing the order here silently changes what every deployed policy means. It reads the active bank once,
takes the start node from that bank's config, evaluates, counts the decision in a per target histogram,
records the same result fields as the base program, and finally passes the packet unless the decided node
is named in the signed `drop_mask`, in which case it drops it. The default mask is zero, which makes the
program observe only, and it is built for a mirror attach where it cannot back pressure anything.

### `ppt_select_prog` in [ppt_select.bpf.c](ppt_select.bpf.c)

The resident selector. Its packet parsing and register fill are identical to the base program, so the
frozen predicate conformance carries over unchanged; what differs is everything around the decision. The
start node is not in the packet: it is `cur_node` in `sel_state_map`, the posture this policy has already
walked itself into, and the decided target is written back there, so the machine's history is in the
kernel and no userspace process is in the loop. The whole read, decide, commit sequence is described in
the next section. Field 0's value is kept aside before the walk as the driving event, because the receipt
records it.

### `ppt_xdp_prog` in [a6/ppt_xdp.bpf.c](a6/ppt_xdp.bpf.c)

The decode and rewrite variant. Same parsing, same evaluator, but the answer goes back into the packet
rather than only into a map: the `node_idx` word of the PPT header is overwritten with the decided target
node and the UDP checksum is zeroed, which IPv4 permits, so a socket above the stack reads a decision the
kernel made on the receive path with no application involved. Two sentinels are its own vocabulary:
`PPT_A6_REFUSED_SHORT` is written instead of a decision when the packet declares fewer fields than the
policy needs or the payload is shorter than the fields it declares, and `PPT_A6_NO_MATCH` is written when
the walk found no satisfied edge. They are `0xFFFFFFFE` and `0xFFFFFFFF`, values no real node index can
take. `a6_listen.py` reads the rewritten packets and measures agreement between the kernel's decision and
the relay's; the variant is an experiment, not the certified path.

## A worked trace

One packet, one node with three edges, and one edge whose program is `[atom3, atom7, OPC_AND]`, that is,
`field_a > 5 and field_b == "ssh"` in reverse Polish.

| call | state on entry | what happens | stack after |
|---|---|---|---|
| `evaluate(node_index = 4)` | | `nodes_map[4]` gives `edge_off = 9`, `edge_cnt = 3`; clamped to 64; `bpf_loop(64, edge_loop_cb)` starts | |
| `edge_loop_cb(0)` | `edge_cnt = 3` | 0 < 3, so `edges_map[9]` is read and `eval_prog` runs its program | |
| `prog_word_cb(0)` | `sp = 0` | word is `atom3`, below `0x8000`; `eval_atom` says true; `sp < 4` so push | `[1]`, `sp = 1` |
| `prog_word_cb(1)` | `sp = 1` | word is `atom7`; `eval_atom` says false; push | `[1, 0]`, `sp = 2` |
| `prog_word_cb(2)` | `sp = 2` | word is `OPC_AND`; `sp >= 2`, so read the top two, drop to `sp = 1`, write `1 and 0` into slot 0 | `[0]`, `sp = 1` |
| `prog_word_cb(3)` | `sp = 1` | 3 is at the program's length, so return STOP; the remaining 60 iterations never run | `[0]`, `sp = 1` |
| back in `edge_loop_cb(0)` | | `sp > 0` and slot 0 is 0, so the edge is unsatisfied; return CONTINUE | |
| `edge_loop_cb(1)` | | `edges_map[10]`, its program runs the same way and is satisfied | |
| | | record `matched_edge = 1` and `target_node = edge.target`; return STOP | |
| back in `evaluate` | | write both out parameters, return 0 | |

Peak stack depth was 2, which is what a flat `and` reaches. Depth grows only with right nested
parentheses: a program shaped `a b AND c d AND e f AND OR OR` peaks at 4, which is exactly `STACK_MAX`,
and one more level of nesting would peak at 5. At depth 5 the guard `sp < STACK_MAX` makes the fifth push
a no operation and `st_get` returns 0 for the slot, so the predicate quietly decides wrongly rather than
refusing. That is what "outside the declared subset" means here, and it is why the subset is stated rather
than discovered.

## The bank arithmetic, in `ppt_net`

`ppt_net` is the only program that holds two copies of the table, and it holds them so that a policy can
be replaced under live traffic without a packet ever seeing half of each. Every table map is sized for two
banks, and bank `b` occupies the index range `[b * capacity, (b + 1) * capacity)`. One extra map,
`bank_map`, holds a single 32 bit word naming the active bank.

```
index of element i in bank b  =  (b & 1) * capacity  +  (i & (capacity - 1))
```

The reader's side is one sentence: the program loads `bank_map` once, at the top, masks it to one bit, and
then carries that bank through `evaluate`, through `edge_loop_cb` and through `prog_word_cb`, so every
atom, node, edge and program word it touches comes from the one bank it chose. The writer's side is the
other half: the loader fills the entire inactive bank, then flips `bank_map` in one aligned four byte
store, which is atomic on the architectures this runs on. A packet therefore evaluates the old policy
whole or the new policy whole. A failed or partial write is never committed, because the flip is the only
commit point. `loader netstorm` measures it: 200,000 evaluations under about 500,000 concurrent flips,
zero torn reads, on both aarch64 and x86_64.

The three single bank programs pass `PPT_BANK_SINGLE` and four macros erase the arithmetic for them
entirely. That erasure is a budget decision, not tidiness. Carrying an unread bank field in the two loop
contexts costs a single bank program about 25 percent more processed instructions, 109,732 to 137,154 for
`ppt_xdp` on kernel 6.17, because a wider context is a wider verifier state to compare at every pruning
point, and the a6 variant has no room to spend. The bank *parameter* is free, since it is constant folded;
only the context *field* is not, which is why the signatures take a bank that a single bank build then
throws away.

## The compare and swap commit, in `ppt_select`

`ppt_select` keeps one posture for the whole machine, in one map entry, and on a multi queue NIC it runs
on several CPUs at once against that single entry. It cannot simply take a lock for the duration, because
`evaluate` calls map helpers and helpers may not be called while a `bpf_spin_lock` is held. So the read,
modify, write is a generation counter protocol in three phases, retried a bounded number of times:

```
failsafe = config.safe_node if declared else (n_nodes - 1 if any nodes else 0)

for attempt in 0 .. SEL_MAX_RETRY - 1:
    lock:
        current   = state.cur_node if state.inited else failsafe
        snapshot  = state.gen
    unlock

    matched, target = evaluate(current, ...)          # unlocked: helpers are legal here
    if no match:  stop, nothing to commit

    lock:
        if state.gen == snapshot:                     # nobody moved the posture under us
            state.cur_node = target
            state.inited   = 1
            state.gen      = snapshot + 1
            committed      = true
        else:
            posture = state.cur_node                  # report the winner's posture, then retry
    unlock

    if committed:
        emit a receipt {seq = new gen, t_ns, policy_hash, prev = current, event, next = target, cause}
        stop
```

Three things in that protocol carry weight. **The fail safe is the default, not the baseline.** `inited`
being zero means the state was never deliberately set, a fresh map or a crash, and the answer is the most
restrictive posture, the policy's signed `safe_node` if it declares one and the last node otherwise, on
the convention that nodes are ordered least to most restrictive. A forced reload must buy lockdown, not
normal. **A loser retries rather than applying stale state.** If the generation moved between the snapshot
and the commit, this packet's decision was computed from a posture that no longer exists, so it is
discarded and the whole thing is done again from the new posture. Up to `SEL_MAX_RETRY`, which is 4; only
pathological contention drops an event. The posture therefore only ever steps along a real edge of its
actual current value, never a phantom one. **Every committed transition writes a receipt**, into a
ring buffer, carrying the sequence number, the time, the low 64 bits of the loaded image's hash, the
posture before, the driving event, the posture after and a cause byte. Because it carries the *previous*
posture, the whole history is reconstructable from the log alone, and because it carries the policy hash,
a receipt is bound to the exact signed image that produced it. Userspace drains the buffer and Merkle
roots the batch. Strict global ordering across queues is not claimed: that is single receive queue
steering, and what the lock gives is integrity and no stale misapply, which the concurrency harness
measures rather than asserts.

## Invariants a change must preserve

If you touch anything in [ppt_eval_bpf.h](ppt_eval_bpf.h) or in a front end, these are the properties
that make it load and make it correct. Each of them was a failure once.

1. **Every map key is masked to a power of two capacity** before the lookup, `& (MAX_ATOMS - 1)` and its
   siblings, so the verifier's range analysis sees a key in bounds.
2. **Every map lookup is NULL checked**, and the fallback is the totality answer, a `TY_NONE` register or
   a skipped edge, never a refusal or a fault.
3. **No `&i` reaches a helper.** Never pass the address of a loop induction variable; the verifier can
   then no longer prove the variable increments and rejects the program with "infinite loop detected". Use
   a copy.
4. **`evaluate` stays `__noinline`.** It needs its own 512 byte frame.
5. **The register file never lives on the stack** and never inside either loop context. One per CPU map
   value, one lookup, an unrolled fill.
6. **The operand stack is only ever touched through `st_get` and `st_put`**, and `STACK_MAX` and the
   number of switch cases move together.
7. **Both loops stay `bpf_loop` callbacks.** Flattening either back into a `for` loop restores the state
   explosion; clang will not unroll them anyway, because they have a data dependent break and a call
   across a function boundary.
8. **The bank stays a parameter and does not become a context field** for the single bank programs. The
   macros exist to keep it out of their loop contexts.
9. **The eight field canonical schema of `ppt_net` is an interface.** Its indices are compiled into every
   policy built for that program.
10. **Totality is not an optimization.** An out of range field is `TY_NONE`, a non numeric ordering
    comparison is unsatisfied, and neither is an error. Changing that changes decisions on every
    substrate, not just this one.

## What certifies this

The eBPF certifications are behavioral. They replay frozen inputs through the loaded program with
`BPF_PROG_TEST_RUN` and compare the kernel's decisions with the reference's; they do not compare object
bytes, which is why the four programs could be folded onto one text without disturbing a score. Run the
harness that matches what you changed:

| harness | the property it proves |
|---|---|
| `loader <ppt> certify <packets.bin>`, built by [cert_corpus.py](cert_corpus.py) | the predicate corpus decides identically in kernel and in the reference; 124 of 124 of the in fragment subset, on aarch64 and x86_64 |
| `loader <ppt> run` and `runbatch` | whole flows walk to the same terminal in kernel as on the host |
| `loader netstorm <a> <b>` | the bank flip is atomic: no torn read under concurrent swaps |
| [cert_selector.c](cert_selector.c) | the selector's posture trail matches the reference, and the fail safe holds |
| [smoke_selector.c](smoke_selector.c) | no torn or out of range resident state under many CPUs at once |
| [receipts_selector.c](receipts_selector.c) | the receipt stream reproduces the certified trail and binds to the policy hash |
| [migrate_selector.c](migrate_selector.c) | migration receipts join the one Merkle root, by name and reset to both |

The hot swap mechanisms themselves, the bank algebra on the loader's side and the migration decision
table, are the subject of [STATEFUL_SELECTOR.md](STATEFUL_SELECTOR.md) and section 8 of
[README.md](README.md). The reference the whole target is judged against is walked in
[../prismpath-hw/EVALUATOR_WALKTHROUGH.md](../prismpath-hw/EVALUATOR_WALKTHROUGH.md).
