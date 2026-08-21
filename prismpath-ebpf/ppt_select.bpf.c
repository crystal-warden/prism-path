// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_xdp.bpf.c — PrismPath PPT v1 Match-Action Table Interpreter in XDP/eBPF
 *
 * Reproduces exact interp.c semantics:
 * - eval_atom: totality rules (non-numeric unsatisfied, EQ/NE type matching, TRUTHY rule)
 * - eval_prog: stack machine execution over per-edge program words
 * - evaluate: priority encoder over node edges
 *
 * Verifier-safe design:
 * - All loops statically unrolled (#pragma unroll) with fixed bounds
 * - All map lookups NULL-checked
 * - All array index operations bitwise masked to map capacities
 * - Stack budget bounded to ~350 bytes (under 512-byte eBPF stack limit)
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "ppt_common.h"

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* BPF Maps storing the PPT Table Image */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ppt_atom);
    __uint(max_entries, MAX_ATOMS);
} atoms_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ppt_node);
    __uint(max_entries, MAX_NODES);
} nodes_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ppt_edge);
    __uint(max_entries, MAX_EDGES);
} edges_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u16);
    __uint(max_entries, MAX_PROG_WORDS);
} prog_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ppt_config);
    __uint(max_entries, 1);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ppt_result);
    __uint(max_entries, 1);
} result_map SEC(".maps");

/* The resident selector state: cur_node persists ACROSS packets — this is the whole trick. The start
 * node comes from here (config.start_node the first time), not the packet, and the decided target is
 * written back. A signed policy driving a stateful machine in the kernel, no userspace in the loop. */
/* Resident selector state, shared across all CPUs. The bpf_spin_lock guards a torn-free
 * snapshot/commit; gen is the generation counter for the commit CAS (see the RESIDENT block). */
struct ppt_sel_state {
    struct bpf_spin_lock lock;
    __u32 cur_node;
    __u32 inited;
    __u32 gen;
};

/* Bounded CAS retries before a contended event is dropped (see the RESIDENT block). Small: control
 * events are rare, so contention is near zero under single-queue steering; this just keeps the
 * un-steered worst case from dropping most events. */
#define SEL_MAX_RETRY 4
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ppt_sel_state);
    __uint(max_entries, 1);
} sel_state_map SEC(".maps");

/* Audit receipts: one ppt_receipt per committed transition (see the RESIDENT block). Userspace drains
 * it, checks the trail, and Merkle-anchors the batch — the stateful history the flat result_map drops. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);   /* 64 KiB: ~2000 receipts before a full ringbuf reserves NULL */
} receipt_map SEC(".maps");

/* Per-packet register file lives in a PER-CPU array, not on the stack. XDP runs to completion on one
 * CPU per packet, so a per-CPU slot is private to this run. Keeping regs off the stack is what lets the
 * bpf-to-bpf call chain stay under the 512-byte budget at large MAX_FIELDS_PER_PKT (embedding regs[] in
 * every ctx overran it — "combined stack size ... Too large"). Map-driven, in the spirit of xdp-bfd. */
/* The whole register file is ONE per-CPU map value (not one entry per field). That means a single
 * map lookup, then a call-free fill loop clang can unroll — a per-field lookup was a helper call x N
 * that exploded the verifier's state exploration at large N. */
struct ppt_regfile { struct ppt_reg r[MAX_FIELDS_PER_PKT]; };

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct ppt_regfile);
    __uint(max_entries, 1);
} regs_map SEC(".maps");

/* ------------------------------------------------------------------ Core Evaluator Engine */

/* eval_atom — mirrors interp.c:eval_atom totality & comparison rules. Reads the register file from
 * regs_map (per-CPU) instead of a stack array. */
static __always_inline int eval_atom(const struct ppt_atom *a, __u32 n_fields)
{
    struct ppt_reg r;
    __u32 zero = 0;
    struct ppt_regfile *rf = bpf_map_lookup_elem(&regs_map, &zero);
    if (rf && a->field < MAX_FIELDS_PER_PKT && a->field < n_fields) {
        r = rf->r[a->field & (MAX_FIELDS_PER_PKT - 1)];
    } else {
        r.ty = TY_NONE;
        r.val = 0;
    }

    int lnum = (r.ty == TY_BOOL || r.ty == TY_INT);
    int rnum = (a->ty == TY_BOOL || a->ty == TY_INT);

    switch (a->op) {
    case OP_EQ:
    case OP_NE: {
        int eq;
        if (lnum && rnum)
            eq = (r.val == a->val);
        else if (r.ty == TY_STR && a->ty == TY_STR)
            eq = (r.val == a->val);
        else if (r.ty == TY_NONE && a->ty == TY_NONE)
            eq = 1;
        else
            eq = 0;
        return (a->op == OP_EQ) ? eq : !eq;
    }
    case OP_LT:
    case OP_LE:
    case OP_GT:
    case OP_GE:
        if (!(lnum && rnum))
            return 0; /* Totality rule: non-numeric -> unsatisfied */
        switch (a->op) {
        case OP_LT: return r.val <  a->val;
        case OP_LE: return r.val <= a->val;
        case OP_GT: return r.val >  a->val;
        case OP_GE: return r.val >= a->val;
        default:    return 0;
        }
    case OP_TRUTHY:
        return (r.ty == TY_NONE) ? 0 : (r.val != 0); /* BOOL value; INT!=0; STR id!=0 */
    default:
        return 0;
    }
}

/* Fixed-depth operand stack accessed ONLY through constant indices. Using st[runtime_sp] made the
 * verifier explore every possible sp at every access (state explosion, 1M+ insns); a switch on the
 * index means every st[] reference is a compile-time-constant slot, which the verifier handles
 * precisely. STACK_MAX cases; anything deeper is outside the declared subset (no-op / read 0). */
static __always_inline __u8 st_get(const __u8 *st, __u32 i)
{
    switch (i) {
    case 0: return st[0];
    case 1: return st[1];
    case 2: return st[2];
    case 3: return st[3];
    default: return 0;
    }
}

static __always_inline void st_put(__u8 *st, __u32 i, __u8 v)
{
    switch (i) {
    case 0: st[0] = v; break;
    case 1: st[1] = v; break;
    case 2: st[2] = v; break;
    case 3: st[3] = v; break;
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
    __u8 st[STACK_MAX];
    __u32 sp;
};

static long prog_word_cb(__u32 i, void *ctx_ptr)
{
    struct prog_ctx *c = ctx_ptr;
    if (i >= c->prog_cnt)
        return 1;                                  /* past the program -> stop */
    __u32 p_idx = (c->prog_off + i) & (MAX_PROG_WORDS - 1);
    __u16 *w_ptr = bpf_map_lookup_elem(&prog_map, &p_idx);
    if (!w_ptr)
        return 1;
    __u16 w = *w_ptr;

    if (w < 0x8000) {                              /* atom -> push its result */
        __u32 atom_idx = w & (MAX_ATOMS - 1);
        struct ppt_atom *atom = bpf_map_lookup_elem(&atoms_map, &atom_idx);
        __u8 res = atom ? (__u8)eval_atom(atom, c->n_fields) : 0;
        if (c->sp < STACK_MAX) {
            st_put(c->st, c->sp, res);
            c->sp++;
        }
    } else {
        switch (w) {
        case OPC_NOT:
            if (c->sp >= 1)
                st_put(c->st, c->sp - 1, !st_get(c->st, c->sp - 1));
            break;
        case OPC_AND:
            if (c->sp >= 2) {
                __u8 b = st_get(c->st, c->sp - 1);
                __u8 a = st_get(c->st, c->sp - 2);
                c->sp--;
                st_put(c->st, c->sp - 1, (__u8)(a && b));
            }
            break;
        case OPC_OR:
            if (c->sp >= 2) {
                __u8 b = st_get(c->st, c->sp - 1);
                __u8 a = st_get(c->st, c->sp - 2);
                c->sp--;
                st_put(c->st, c->sp - 1, (__u8)(a || b));
            }
            break;
        case OPC_TRUE:
            if (c->sp < STACK_MAX) { st_put(c->st, c->sp, 1); c->sp++; }
            break;
        case OPC_FALSE:
            if (c->sp < STACK_MAX) { st_put(c->st, c->sp, 0); c->sp++; }
            break;
        default:
            break;
        }
    }
    return 0;                                      /* continue */
}

/* eval_prog — SAME RPN semantics as interp.c, evaluated via the prog_word_cb bpf_loop. Exact for any
 * predicate whose operand-stack depth stays <= STACK_MAX (the eBPF target's declared subset). */
static __always_inline int eval_prog(const struct ppt_edge *e, __u32 n_fields)
{
    struct prog_ctx pc = {};
    pc.prog_off = e->prog_off;
    pc.prog_cnt = e->prog_cnt;
    if (pc.prog_cnt > MAX_PROG_PER_EDGE)
        pc.prog_cnt = MAX_PROG_PER_EDGE;
    pc.n_fields = n_fields;
    pc.sp = 0;

    bpf_loop(MAX_PROG_PER_EDGE, prog_word_cb, &pc, 0);

    return (pc.sp > 0) ? st_get(pc.st, 0) : 0;
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
    __s32 matched_edge;
    __s32 target_node;
};

static long edge_loop_cb(__u32 i, void *ctx_ptr)
{
    struct eval_loop_ctx *c = ctx_ptr;
    if (i >= c->edge_cnt)
        return 1;                              /* past the node's edges -> stop */
    __u32 e_idx = (c->edge_off + i) & (MAX_EDGES - 1);
    struct ppt_edge *e = bpf_map_lookup_elem(&edges_map, &e_idx);
    if (!e)
        return 0;                              /* missing edge -> skip (mirror interp.c continue) */
    if (eval_prog(e, c->n_fields)) {
        c->matched_edge = (__s32)i;            /* first-true edge wins (priority encoder) */
        c->target_node = (__s32)e->target;
        return 1;                              /* stop */
    }
    return 0;                                  /* continue to the next edge */
}

/* evaluate — priority encoder: first matching edge wins (edge loop runs via bpf_loop). Forced
 * __noinline: it MUST be a separate sub-program so eval_loop_ctx gets its own 512-byte frame instead
 * of stacking on main's regs[] (inlining it overran the BPF stack limit). */
static __attribute__((noinline)) int evaluate(__u32 node_idx,
                    __u32 n_fields,
                    __s32 *out_matched_edge,
                    __s32 *out_target_node)
{
    __u32 n_idx = node_idx & (MAX_NODES - 1);
    struct ppt_node *n = bpf_map_lookup_elem(&nodes_map, &n_idx);
    if (!n) {
        *out_matched_edge = -1;
        *out_target_node = -1;
        return -1;
    }

    __u32 edge_cnt = n->edge_cnt;
    if (edge_cnt > MAX_EDGES_PER_NODE)
        edge_cnt = MAX_EDGES_PER_NODE;

    struct eval_loop_ctx c = {};
    c.edge_off = n->edge_off;
    c.edge_cnt = edge_cnt;
    c.n_fields = n_fields;
    c.matched_edge = -1;
    c.target_node = -1;

    bpf_loop(MAX_EDGES_PER_NODE, edge_loop_cb, &c, 0);

    *out_matched_edge = c.matched_edge;
    *out_target_node = c.target_node;
    return (c.matched_edge >= 0) ? 0 : -1;
}

/* ------------------------------------------------------------------ XDP Program Entry Point */

SEC("xdp")
int ppt_select_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ppt_packet_hdr *pkt_hdr = NULL;
    void *payload_start = NULL;

    /* 1. Try parsing raw payload directly at start of packet */
    if (data + sizeof(struct ppt_packet_hdr) <= data_end) {
        struct ppt_packet_hdr *hdr = (struct ppt_packet_hdr *)data;
        if (hdr->magic == PPT_MAGIC) {
            pkt_hdr = hdr;
            payload_start = data + sizeof(struct ppt_packet_hdr);
        }
    }

    /* 2. Try parsing standard Ethernet + IPv4 + UDP packet header */
    if (!pkt_hdr) {
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) <= data_end) {
            if (eth->h_proto == __builtin_bswap16(ETH_P_IP)) {
                struct iphdr *iph = (void *)(eth + 1);
                if ((void *)(iph + 1) <= data_end && iph->protocol == IPPROTO_UDP) {
                    __u32 ip_hlen = iph->ihl * 4;
                    if (ip_hlen >= sizeof(struct iphdr)) {
                        void *udp_ptr = (void *)iph + ip_hlen;
                        struct udphdr *udph = udp_ptr;
                        if ((void *)(udph + 1) <= data_end) {
                            void *app_data = (void *)(udph + 1);
                            if (app_data + sizeof(struct ppt_packet_hdr) <= data_end) {
                                struct ppt_packet_hdr *hdr = app_data;
                                if (hdr->magic == PPT_MAGIC) {
                                    pkt_hdr = hdr;
                                    payload_start = app_data + sizeof(struct ppt_packet_hdr);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (!pkt_hdr) {
        /* Not a PrismPath packet: pass through safely */
        return XDP_PASS;
    }

    __u32 n_fields = pkt_hdr->n_fields;
    if (n_fields > MAX_FIELDS_PER_PKT)
        n_fields = MAX_FIELDS_PER_PKT;

    /* Load the packet's register file into regs_map (per-CPU), not the program stack — that is what
     * keeps the bpf-to-bpf call chain under the 512-byte budget regardless of MAX_FIELDS_PER_PKT.
     * Every slot is written: present fields from the payload, the rest default to TY_NONE. */
    __u32 zero = 0;
    struct ppt_regfile *rf = bpf_map_lookup_elem(&regs_map, &zero);   /* one lookup for all fields */
    if (rf) {
        #pragma unroll
        for (__u32 i = 0; i < MAX_FIELDS_PER_PKT; i++) {
            __u32 slot = i & (MAX_FIELDS_PER_PKT - 1);   /* mask so the verifier bounds the map-value offset */
            void *reg_ptr = payload_start + i * sizeof(struct ppt_reg);
            if (i < n_fields && reg_ptr + sizeof(struct ppt_reg) <= data_end) {
                struct ppt_reg *r = (struct ppt_reg *)reg_ptr;
                rf->r[slot].ty = r->ty;
                rf->r[slot].val = r->val;
            } else {
                rf->r[slot].ty = TY_NONE;
                rf->r[slot].val = 0;
            }
        }
    }

    __s32 ev_value = 0;                               /* the driving event (field 0) for the receipt */
    if (rf && n_fields > 0)
        ev_value = rf->r[0].val;

    /* RESIDENT + SERIALIZED. The start node is the persisted cur_node, not pkt_hdr->node_idx; each
     * control packet is one discrete event and the map holds the state. FAIL-SAFE: inited==0 means the
     * state was NOT deliberately set (crash, fresh/torn map), so fall to the MOST RESTRICTIVE posture
     * (the last, highest-severity node), never the baseline — a forced reload must buy lockdown, not
     * normal. A deliberate clean start is the loader writing {start_node, inited=1}; the program only
     * sees inited==0 when something went wrong. (Nodes ordered least->most restrictive, the severity
     * order the spiral lint enforces; an explicit signed safe_node is the follow-up.)
     *
     * CONCURRENCY: on a multi-queue NIC this program runs on several CPUs at once against the ONE
     * shared sel_state_map. evaluate() calls map helpers, so it cannot run under a bpf_spin_lock;
     * instead the read-modify-write is a generation-counter CAS — snapshot {cur,gen} under the lock,
     * evaluate UNLOCKED, then commit under the lock only if gen is unchanged. A concurrent loser (the
     * state advanced since our snapshot) is DROPPED, never applied from stale state, so the posture
     * only ever steps along a real edge of its actual current value, never a phantom. Strict global
     * ORDER for a multi-queue deployment is single-RX-queue steering (the kernel analog of the fabric
     * clock); this lock gives integrity + no stale-misapply, which the concurrent smoke test measures. */
    __u32 zk = 0;
    struct ppt_sel_state *st = bpf_map_lookup_elem(&sel_state_map, &zk);
    struct ppt_config *scfg = bpf_map_lookup_elem(&config_map, &zk);
    /* most restrictive posture: the policy's SIGNED safe_node if declared (offset-26 high byte, rides
     * the manifest signature); else the last-node convention. 0 = undeclared, hence the fallback. */
    __u32 failsafe = 0;
    if (scfg) {
        failsafe = scfg->safe_node ? scfg->safe_node
                                   : (scfg->n_nodes ? (scfg->n_nodes - 1) : 0);
    }
    /* Bounded-retry CAS: on a lost commit, re-snapshot from the NEW state and re-evaluate, up to
     * SEL_MAX_RETRY times, so a concurrent contender turns a drop into a commit against fresh state
     * rather than losing the event. Every re-evaluation is from the actual current posture, so a
     * committed transition is never stale. Only pathological contention (all attempts lose) drops. */
    __s32 matched_edge = -1;
    int rc = -1;
    __u32 posture = failsafe;
    int done = 0;
    if (st) {
        for (int attempt = 0; attempt < SEL_MAX_RETRY && !done; attempt++) {
            __u32 cur, snap_gen;
            bpf_spin_lock(&st->lock);
            cur = st->inited ? st->cur_node : failsafe;
            snap_gen = st->gen;
            bpf_spin_unlock(&st->lock);

            __s32 target_node = -1;
            matched_edge = -1;
            rc = evaluate(cur, n_fields, &matched_edge, &target_node);
            posture = cur;
            if (rc != 0 || target_node < 0) { done = 1; break; }   /* nothing to commit */

            int committed = 0;
            __u32 new_seq = 0;
            bpf_spin_lock(&st->lock);
            if (st->gen == snap_gen) {                             /* uncontended: commit the advance */
                st->cur_node = (__u32)target_node;
                st->inited = 1;
                st->gen = snap_gen + 1;
                new_seq = st->gen;
                posture = (__u32)target_node;
                committed = 1;
                done = 1;
            } else {
                posture = st->cur_node;                           /* contended: report winner, retry */
            }
            bpf_spin_unlock(&st->lock);

            if (committed) {   /* AUDIT RECEIPT: one per committed transition, emitted lock-free */
                struct ppt_receipt *rcpt = bpf_ringbuf_reserve(&receipt_map, sizeof(*rcpt), 0);
                if (rcpt) {
                    rcpt->seq = new_seq;
                    rcpt->t_ns = bpf_ktime_get_ns();   /* the time axis, inside the tamper-evident record */
                    rcpt->policy_hash = scfg ? scfg->policy_hash : 0;
                    rcpt->prev_node = (__s32)cur;
                    rcpt->event = ev_value;
                    rcpt->next_node = target_node;
                    rcpt->_pad = 0;
                    bpf_ringbuf_submit(rcpt, 0);
                }
                break;
            }
        }
    }

    __u32 key = 0;
    struct ppt_result *res = bpf_map_lookup_elem(&result_map, &key);
    if (res) {
        res->matched_edge = matched_edge;
        res->target_node = (__s32)posture;            /* the NEW resident posture after this event */
        res->eval_status = (rc == 0) ? 1 : 0;
        __sync_fetch_and_add(&res->pkt_count, 1);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
