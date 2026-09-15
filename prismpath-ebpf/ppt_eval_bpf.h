// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_eval_bpf.h: the PPT v1 match action evaluator, one copy for every XDP program here.
 *
 * ppt_xdp.bpf.c, ppt_net.bpf.c, ppt_select.bpf.c and a6/ppt_xdp.bpf.c each carried their own
 * eval_atom, eval_prog, evaluate and register fill, so a fix to one had to be carried to the other
 * three by hand and only a comment said they were meant to agree. They are one text now. What a
 * program keeps for itself is its front end: how a packet becomes a register file, and what it does
 * with the decision afterwards. The eBPF certifications are behavioral (BPF_PROG_TEST_RUN verdicts
 * replayed against the frozen corpus), not object bytes, so sharing the text leaves them untouched.
 *
 * The shape of this code is dictated by the verifier, not by taste, and the comments below say which
 * limit forced which shape. Do not flatten any of it without reading them: a constant indexed operand
 * stack instead of st[sp], two bpf_loop callbacks instead of two nested for loops, and a per CPU
 * register file instead of a stack array are each the difference between loading and not loading.
 *
 * The includer must have defined, BEFORE this header:
 *   ppt_common.h, bpf_helpers.h, and the SEC / __always_inline fallbacks
 *   atoms_map, nodes_map, edges_map, prog_map   the table image, keyed by element index
 *   PPT_EVAL_BANKED 1                           ONLY if those four maps hold two banks (ppt_net)
 * The per packet register file (struct ppt_regfile and regs_map) is identical in every program, so
 * this header owns it rather than asking for it.
 *
 * Banking is ppt_net's atomic hot swap: it sizes every table map for two banks, fills the inactive
 * bank in full and flips one aligned word to commit. The evaluator takes the chosen bank as an
 * argument, carries it through both bpf_loop callbacks and offsets every table index by a whole
 * bank, so one packet reads one bank from start to finish. The other three programs hold a single
 * bank and pass PPT_BANK_SINGLE, and for them the four macros below erase the bank entirely.
 *
 * That erasure is not tidiness, it is budget. Carrying an unread bank in the two loop contexts costs
 * a single-bank program 25 percent more processed instructions (109,732 to 137,154 for ppt_xdp on
 * kernel 6.17), because a wider context is a wider verifier state to compare at every pruning point.
 * The a6 variant already sits at the 1M ceiling, so the single-bank programs cannot spend it. The
 * bank PARAMETER is free (it is constant folded), only the context field is not, which is why the
 * signatures below take a bank the unbanked build then throws away. */
#pragma once

#ifndef PPT_EVAL_BANKED
#define PPT_EVAL_BANKED 0
#endif

#define PPT_BANK_SINGLE 0u   /* the only bank a single banked program has */

#if PPT_EVAL_BANKED
#define PPT_BANK_BASE(bank, span)    (((bank) & 1u) * (__u32)(span))
#define PPT_BANK_FIELD               __u32 bank;
#define PPT_BANK_SET(state, chosen)  (state).bank = (chosen) & 1u
#define PPT_BANK_OF(state)           ((state)->bank)
#else
#define PPT_BANK_BASE(bank, span)    0u
#define PPT_BANK_FIELD
#define PPT_BANK_SET(state, chosen)  (void)(chosen)
#define PPT_BANK_OF(state)           PPT_BANK_SINGLE
#endif

/* Per-packet register file lives in a PER-CPU array, not on the stack. XDP runs to completion on one
 * CPU per packet, so a per-CPU slot is private to this run. Keeping regs off the stack is what lets the
 * bpf-to-bpf call chain stay under the 512-byte budget at large MAX_FIELDS_PER_PKT (embedding regs[] in
 * every ctx overran it: "combined stack size ... Too large"). Map-driven, in the spirit of xdp-bfd. */
/* The whole register file is ONE per-CPU map value (not one entry per field). That means a single
 * map lookup, then a call-free fill loop clang can unroll: a per-field lookup was a helper call x N
 * that exploded the verifier's state exploration at large N. */
struct ppt_regfile { struct ppt_reg reg[MAX_FIELDS_PER_PKT]; };

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct ppt_regfile);
    __uint(max_entries, 1);
} regs_map SEC(".maps");

/* The one lookup of the per-CPU register file; NULL if the map is gone, which every caller checks. */
static __always_inline struct ppt_regfile *ppt_regs(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&regs_map, &zero);
}

/* ------------------------------------------------------------------ Core Evaluator Engine */

/* eval_atom: mirrors interp.c:eval_atom totality and comparison rules. One atom is one
 * field OP constant test. Reads the register file from regs_map (per-CPU), not a stack array. */
static __always_inline int eval_atom(const struct ppt_atom *atom, __u32 n_fields)
{
    struct ppt_reg reg;
    struct ppt_regfile *regfile = ppt_regs();
    if (regfile && atom->field < MAX_FIELDS_PER_PKT && atom->field < n_fields) {
        reg = regfile->reg[atom->field & (MAX_FIELDS_PER_PKT - 1)];
    } else {
        reg.ty = TY_NONE;
        reg.val = 0;
    }

    int left_numeric = (reg.ty == TY_BOOL || reg.ty == TY_INT);
    int right_numeric = (atom->ty == TY_BOOL || atom->ty == TY_INT);

    switch (atom->op) {
    case OP_EQ:
    case OP_NE: {
        int equal;
        if (left_numeric && right_numeric)
            equal = (reg.val == atom->val);
        else if (reg.ty == TY_STR && atom->ty == TY_STR)
            equal = (reg.val == atom->val);
        else if (reg.ty == TY_NONE && atom->ty == TY_NONE)
            equal = 1;
        else
            equal = 0;
        return (atom->op == OP_EQ) ? equal : !equal;
    }
    case OP_LT:
    case OP_LE:
    case OP_GT:
    case OP_GE:
        if (!(left_numeric && right_numeric))
            return 0; /* Totality rule: non-numeric -> unsatisfied */
        switch (atom->op) {
        case OP_LT: return reg.val <  atom->val;
        case OP_LE: return reg.val <= atom->val;
        case OP_GT: return reg.val >  atom->val;
        case OP_GE: return reg.val >= atom->val;
        default:    return 0;
        }
    case OP_TRUTHY:
        return (reg.ty == TY_NONE) ? 0 : (reg.val != 0); /* BOOL value; INT!=0; STR id!=0 */
    default:
        return 0;
    }
}

/* Fixed-depth operand stack accessed ONLY through constant indices. Using st[runtime_sp] made the
 * verifier explore every possible sp at every access (state explosion, 1M+ insns); a switch on the
 * index means every st[] reference is a compile-time-constant slot, which the verifier handles
 * precisely. STACK_MAX cases; anything deeper is outside the declared subset (no-op / read 0). */
static __always_inline __u8 st_get(const __u8 *stack, __u32 index)
{
    switch (index) {
    case 0: return stack[0];
    case 1: return stack[1];
    case 2: return stack[2];
    case 3: return stack[3];
    default: return 0;
    }
}

static __always_inline void st_put(__u8 *stack, __u32 index, __u8 value)
{
    switch (index) {
    case 0: stack[0] = value; break;
    case 1: stack[1] = value; break;
    case 2: stack[2] = value; break;
    case 3: stack[3] = value; break;
    default: break;
    }
}

/* The prog machine runs as its OWN bpf_loop: prog_word_cb processes one RPN word and is verified
 * ONCE, so the stack-machine state (st[]/sp, carried in the ctx and mutated across words) no longer
 * multiplies the verifier's exploration. Nested inside the edge bpf_loop, this is what finally fits
 * the interpreter under the 1M-insn budget: both loops are verified once, not per-iteration. */
struct prog_ctx {
    __u32 prog_off;
    __u32 prog_cnt;
    __u32 n_fields;
    PPT_BANK_FIELD
    __u8 st[STACK_MAX];
    __u32 sp;
};

static long prog_word_cb(__u32 word_index, void *ctx_ptr)
{
    struct prog_ctx *state = ctx_ptr;
    if (word_index >= state->prog_cnt)
        return 1;                                  /* past the program -> stop */
    __u32 prog_index = PPT_BANK_BASE(PPT_BANK_OF(state), MAX_PROG_WORDS)
                     + ((state->prog_off + word_index) & (MAX_PROG_WORDS - 1));
    __u16 *word_ptr = bpf_map_lookup_elem(&prog_map, &prog_index);
    if (!word_ptr)
        return 1;
    __u16 word = *word_ptr;

    if (word < 0x8000) {                           /* atom -> push its result */
        __u32 atom_index = PPT_BANK_BASE(PPT_BANK_OF(state), MAX_ATOMS) + (word & (MAX_ATOMS - 1));
        struct ppt_atom *atom = bpf_map_lookup_elem(&atoms_map, &atom_index);
        __u8 result = atom ? (__u8)eval_atom(atom, state->n_fields) : 0;
        if (state->sp < STACK_MAX) {
            st_put(state->st, state->sp, result);
            state->sp++;
        }
    } else {
        switch (word) {
        case OPC_NOT:
            if (state->sp >= 1)
                st_put(state->st, state->sp - 1, !st_get(state->st, state->sp - 1));
            break;
        case OPC_AND:
            if (state->sp >= 2) {
                __u8 rhs = st_get(state->st, state->sp - 1);
                __u8 lhs = st_get(state->st, state->sp - 2);
                state->sp--;
                st_put(state->st, state->sp - 1, (__u8)(lhs && rhs));
            }
            break;
        case OPC_OR:
            if (state->sp >= 2) {
                __u8 rhs = st_get(state->st, state->sp - 1);
                __u8 lhs = st_get(state->st, state->sp - 2);
                state->sp--;
                st_put(state->st, state->sp - 1, (__u8)(lhs || rhs));
            }
            break;
        case OPC_TRUE:
            if (state->sp < STACK_MAX) {
                st_put(state->st, state->sp, 1);
                state->sp++;
            }
            break;
        case OPC_FALSE:
            if (state->sp < STACK_MAX) {
                st_put(state->st, state->sp, 0);
                state->sp++;
            }
            break;
        default:
            break;
        }
    }
    return 0;                                      /* continue */
}

/* eval_prog: SAME RPN semantics as interp.c, evaluated via the prog_word_cb bpf_loop. One prog is the
 * word list of one edge's predicate. Exact for any predicate whose operand-stack depth stays
 * <= STACK_MAX (the eBPF target's declared subset). */
static __always_inline int eval_prog(const struct ppt_edge *edge, __u32 n_fields, __u32 bank)
{
    struct prog_ctx state = {};
    state.prog_off = edge->prog_off;
    state.prog_cnt = edge->prog_cnt;
    if (state.prog_cnt > MAX_PROG_PER_EDGE)
        state.prog_cnt = MAX_PROG_PER_EDGE;
    state.n_fields = n_fields;
    PPT_BANK_SET(state, bank);
    state.sp = 0;

    bpf_loop(MAX_PROG_PER_EDGE, prog_word_cb, &state, 0);

    return (state.sp > 0) ? st_get(state.st, 0) : 0;
}

/* edge iteration via bpf_loop: the callback is verified ONCE, not per-iteration, so the nested
 * evaluate()xeval_prog() work stops multiplying the verifier's state exploration (as plain nested
 * loops, 64x64 overran the jump-sequence limit and 16x16 overran the 1M processed-insn limit). The
 * register file lives in regs_map (per-CPU), not this ctx, so the ctx stays tiny and the bpf-to-bpf
 * call chain fits the 512-byte stack budget at any MAX_FIELDS_PER_PKT. */
struct eval_loop_ctx {
    __u32 edge_off;
    __u32 edge_cnt;
    __u32 n_fields;
    PPT_BANK_FIELD
    __s32 matched_edge;
    __s32 target_node;
};

static long edge_loop_cb(__u32 edge_index, void *ctx_ptr)
{
    struct eval_loop_ctx *state = ctx_ptr;
    if (edge_index >= state->edge_cnt)
        return 1;                              /* past the node's edges -> stop */
    __u32 edge_key = PPT_BANK_BASE(PPT_BANK_OF(state), MAX_EDGES)
                   + ((state->edge_off + edge_index) & (MAX_EDGES - 1));
    struct ppt_edge *edge = bpf_map_lookup_elem(&edges_map, &edge_key);
    if (!edge)
        return 0;                              /* missing edge -> skip (mirror interp.c continue) */
    if (eval_prog(edge, state->n_fields, PPT_BANK_OF(state))) {
        state->matched_edge = (__s32)edge_index;   /* first-true edge wins (priority encoder) */
        state->target_node = (__s32)edge->target;
        return 1;                              /* stop */
    }
    return 0;                                  /* continue to the next edge */
}

/* evaluate: priority encoder, first matching edge of the node wins (edge loop runs via bpf_loop).
 * Forced __noinline: it MUST be a separate sub-program so eval_loop_ctx gets its own 512-byte frame
 * instead of stacking on the entry program's frame (inlining it overran the BPF stack limit). */
static __attribute__((noinline)) int evaluate(__u32 node_idx,
                    __u32 n_fields,
                    __u32 bank,
                    __s32 *out_matched_edge,
                    __s32 *out_target_node)
{
    __u32 node_index = PPT_BANK_BASE(bank, MAX_NODES) + (node_idx & (MAX_NODES - 1));
    struct ppt_node *node = bpf_map_lookup_elem(&nodes_map, &node_index);
    if (!node) {
        *out_matched_edge = -1;
        *out_target_node = -1;
        return -1;
    }

    __u32 edge_cnt = node->edge_cnt;
    if (edge_cnt > MAX_EDGES_PER_NODE)
        edge_cnt = MAX_EDGES_PER_NODE;

    struct eval_loop_ctx state = {};
    state.edge_off = node->edge_off;
    state.edge_cnt = edge_cnt;
    state.n_fields = n_fields;
    PPT_BANK_SET(state, bank);
    state.matched_edge = -1;
    state.target_node = -1;

    bpf_loop(MAX_EDGES_PER_NODE, edge_loop_cb, &state, 0);

    *out_matched_edge = state.matched_edge;
    *out_target_node = state.target_node;
    return (state.matched_edge >= 0) ? 0 : -1;
}

/* The register fill of a crafted PPT packet, shared by the three programs whose front end reads the
 * register file straight out of the payload. ppt_net does NOT use it: it fills a fixed canonical
 * schema from a real packet's header fields instead. The fill goes into regs_map (per-CPU), not the
 * program stack, which is what keeps the bpf-to-bpf call chain under the 512-byte budget regardless
 * of MAX_FIELDS_PER_PKT. Every slot is written: present fields from the payload, the rest TY_NONE. */
static __always_inline void ppt_load_regs_from_payload(struct ppt_regfile *regfile,
                    void *payload_start,
                    void *data_end,
                    __u32 n_fields)
{
    #pragma unroll
    for (__u32 field_index = 0; field_index < MAX_FIELDS_PER_PKT; field_index++) {
        __u32 slot = field_index & (MAX_FIELDS_PER_PKT - 1);   /* mask so the verifier bounds the map-value offset */
        void *reg_ptr = payload_start + field_index * sizeof(struct ppt_reg);
        if (field_index < n_fields && reg_ptr + sizeof(struct ppt_reg) <= data_end) {
            struct ppt_reg *packet_reg = (struct ppt_reg *)reg_ptr;
            regfile->reg[slot].ty = packet_reg->ty;
            regfile->reg[slot].val = packet_reg->val;
        } else {
            regfile->reg[slot].ty = TY_NONE;
            regfile->reg[slot].val = 0;
        }
    }
}
