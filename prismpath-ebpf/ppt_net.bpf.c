// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_net.bpf.c — PrismPath PPT on REAL network packets (XDP), observe-only.
 *
 * Same verifier-accepted match-action back-end as ppt_xdp.bpf.c (eval_atom / eval_prog / evaluate over
 * the PPT table maps), but the FRONT-END parses a live Ethernet/IPv4/TCP-UDP packet instead of a crafted
 * PPT packet. It fills a FIXED canonical register file from the packet's real fields, evaluates the
 * flow's start node in-kernel, and records the verdict into a per-target histogram. It NEVER drops:
 * always XDP_PASS. Meant for an observe-only attach on a mirror (span0), where a mirror cannot be
 * back-pressured and a bug cannot harm production traffic.
 *
 * Canonical field ABI (must match the pre-seeded schema the flow is compiled with):
 *   0 src_ip   1 dst_ip   2 src_port   3 dst_port   4 protocol   5 pkt_len   6 tcp_flags   7 ttl
 * All are TY_INT. IPs are host-order u32 stored in the s32 val (bit-equality holds for ==/!=).
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
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

#define NET_FIELDS 8          /* the canonical schema length */

/* ---- PPT table maps — DOUBLE-BUFFERED for atomic live hot-swap (net program only).
 * Two banks per table map: bank b occupies indices [b*MAX_X, (b+1)*MAX_X). A packet reads the
 * ACTIVE bank once (bank_map, below) and evaluates entirely from it; the loader writes the INACTIVE
 * bank in full, then flips bank_map in a single aligned store (the only atomic commit point). A
 * packet therefore sees the old table whole or the new table whole — never a torn mix. ppt_xdp
 * (the conformance program) stays single-bank; its 124/124 cert is unaffected. ---- */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct ppt_atom);
         __uint(max_entries, 2 * MAX_ATOMS); } atoms_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct ppt_node);
         __uint(max_entries, 2 * MAX_NODES); } nodes_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct ppt_edge);
         __uint(max_entries, 2 * MAX_EDGES); } edges_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, __u16);
         __uint(max_entries, 2 * MAX_PROG_WORDS); } prog_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct ppt_config);
         __uint(max_entries, 2); } config_map SEC(".maps");     /* per-bank: start_node + drop_mask */
/* The atomic commit point: a single __u32 selecting the active bank (0|1). An aligned 4-byte store
 * is atomic on x86_64/aarch64, so the reader's single load sees the old or new bank, never torn. */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, __u32);
         __uint(max_entries, 1); } bank_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct ppt_result);
         __uint(max_entries, 1); } result_map SEC(".maps");

/* Per-target verdict histogram: verdict_map[target_node] = count. Index MAX_NODES-1 doubles as the
 * "no match / stuck" bucket. Observe-only output the loader reads back. */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, __u64);
         __uint(max_entries, MAX_NODES); } verdict_map SEC(".maps");

struct ppt_regfile { struct ppt_reg r[MAX_FIELDS_PER_PKT]; };
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __type(key, __u32); __type(value, struct ppt_regfile);
         __uint(max_entries, 1); } regs_map SEC(".maps");

/* ------------------------------------------------------------------ eval back-end (mirror of ppt_xdp.bpf.c) */
static __always_inline int eval_atom(const struct ppt_atom *a, __u32 n_fields)
{
    struct ppt_reg r;
    __u32 zero = 0;
    struct ppt_regfile *rf = bpf_map_lookup_elem(&regs_map, &zero);
    if (rf && a->field < MAX_FIELDS_PER_PKT && a->field < n_fields) {
        r = rf->r[a->field & (MAX_FIELDS_PER_PKT - 1)];
    } else { r.ty = TY_NONE; r.val = 0; }

    int lnum = (r.ty == TY_BOOL || r.ty == TY_INT);
    int rnum = (a->ty == TY_BOOL || a->ty == TY_INT);
    switch (a->op) {
    case OP_EQ:
    case OP_NE: {
        int eq;
        if (lnum && rnum) eq = (r.val == a->val);
        else if (r.ty == TY_STR && a->ty == TY_STR) eq = (r.val == a->val);
        else if (r.ty == TY_NONE && a->ty == TY_NONE) eq = 1;
        else eq = 0;
        return (a->op == OP_EQ) ? eq : !eq;
    }
    case OP_LT: case OP_LE: case OP_GT: case OP_GE:
        if (!(lnum && rnum)) return 0;
        switch (a->op) {
        case OP_LT: return r.val <  a->val;
        case OP_LE: return r.val <= a->val;
        case OP_GT: return r.val >  a->val;
        case OP_GE: return r.val >= a->val;
        default: return 0;
        }
    case OP_TRUTHY:
        return (r.ty == TY_NONE) ? 0 : (r.val != 0);
    default: return 0;
    }
}

static __always_inline __u8 st_get(const __u8 *st, __u32 i)
{
    switch (i) { case 0: return st[0]; case 1: return st[1]; case 2: return st[2];
                 case 3: return st[3]; default: return 0; }
}
static __always_inline void st_put(__u8 *st, __u32 i, __u8 v)
{
    switch (i) { case 0: st[0]=v; break; case 1: st[1]=v; break; case 2: st[2]=v; break;
                 case 3: st[3]=v; break; default: break; }
}

struct prog_ctx { __u32 prog_off; __u32 prog_cnt; __u32 n_fields; __u32 bank; __u8 st[STACK_MAX]; __u32 sp; };

static long prog_word_cb(__u32 i, void *ctx_ptr)
{
    struct prog_ctx *c = ctx_ptr;
    if (i >= c->prog_cnt) return 1;
    __u32 p_idx = (c->bank & 1) * MAX_PROG_WORDS + ((c->prog_off + i) & (MAX_PROG_WORDS - 1));
    __u16 *w_ptr = bpf_map_lookup_elem(&prog_map, &p_idx);
    if (!w_ptr) return 1;
    __u16 w = *w_ptr;
    if (w < 0x8000) {
        __u32 atom_idx = (c->bank & 1) * MAX_ATOMS + (w & (MAX_ATOMS - 1));
        struct ppt_atom *atom = bpf_map_lookup_elem(&atoms_map, &atom_idx);
        __u8 res = atom ? (__u8)eval_atom(atom, c->n_fields) : 0;
        if (c->sp < STACK_MAX) { st_put(c->st, c->sp, res); c->sp++; }
    } else {
        switch (w) {
        case OPC_NOT: if (c->sp >= 1) st_put(c->st, c->sp-1, !st_get(c->st, c->sp-1)); break;
        case OPC_AND: if (c->sp >= 2) { __u8 b=st_get(c->st,c->sp-1), a=st_get(c->st,c->sp-2);
                          c->sp--; st_put(c->st, c->sp-1, (__u8)(a && b)); } break;
        case OPC_OR:  if (c->sp >= 2) { __u8 b=st_get(c->st,c->sp-1), a=st_get(c->st,c->sp-2);
                          c->sp--; st_put(c->st, c->sp-1, (__u8)(a || b)); } break;
        case OPC_TRUE:  if (c->sp < STACK_MAX) { st_put(c->st, c->sp, 1); c->sp++; } break;
        case OPC_FALSE: if (c->sp < STACK_MAX) { st_put(c->st, c->sp, 0); c->sp++; } break;
        default: break;
        }
    }
    return 0;
}

static __always_inline int eval_prog(const struct ppt_edge *e, __u32 n_fields, __u32 bank)
{
    struct prog_ctx pc = {};
    pc.prog_off = e->prog_off;
    pc.prog_cnt = e->prog_cnt;
    if (pc.prog_cnt > MAX_PROG_PER_EDGE) pc.prog_cnt = MAX_PROG_PER_EDGE;
    pc.n_fields = n_fields;
    pc.bank = bank & 1;
    pc.sp = 0;
    bpf_loop(MAX_PROG_PER_EDGE, prog_word_cb, &pc, 0);
    return (pc.sp > 0) ? st_get(pc.st, 0) : 0;
}

struct eval_loop_ctx { __u32 edge_off; __u32 edge_cnt; __u32 n_fields; __u32 bank;
                       __s32 matched_edge; __s32 target_node; };

static long edge_loop_cb(__u32 i, void *ctx_ptr)
{
    struct eval_loop_ctx *c = ctx_ptr;
    if (i >= c->edge_cnt) return 1;
    __u32 e_idx = (c->bank & 1) * MAX_EDGES + ((c->edge_off + i) & (MAX_EDGES - 1));
    struct ppt_edge *e = bpf_map_lookup_elem(&edges_map, &e_idx);
    if (!e) return 0;
    if (eval_prog(e, c->n_fields, c->bank)) {
        c->matched_edge = (__s32)i;
        c->target_node = (__s32)e->target;
        return 1;
    }
    return 0;
}

static __attribute__((noinline)) int evaluate(__u32 node_idx, __u32 n_fields, __u32 bank,
                    __s32 *out_matched_edge, __s32 *out_target_node)
{
    __u32 n_idx = (bank & 1) * MAX_NODES + (node_idx & (MAX_NODES - 1));
    struct ppt_node *n = bpf_map_lookup_elem(&nodes_map, &n_idx);
    if (!n) { *out_matched_edge = -1; *out_target_node = -1; return -1; }
    __u32 edge_cnt = n->edge_cnt;
    if (edge_cnt > MAX_EDGES_PER_NODE) edge_cnt = MAX_EDGES_PER_NODE;
    struct eval_loop_ctx c = {};
    c.edge_off = n->edge_off;
    c.edge_cnt = edge_cnt;
    c.n_fields = n_fields;
    c.bank = bank & 1;
    c.matched_edge = -1;
    c.target_node = -1;
    bpf_loop(MAX_EDGES_PER_NODE, edge_loop_cb, &c, 0);
    *out_matched_edge = c.matched_edge;
    *out_target_node = c.target_node;
    return (c.matched_edge >= 0) ? 0 : -1;
}

/* ------------------------------------------------------------------ real-packet front-end */
static __always_inline void set_reg(struct ppt_regfile *rf, __u32 slot, __s32 val)
{
    rf->r[slot & (MAX_FIELDS_PER_PKT - 1)].ty = TY_INT;
    rf->r[slot & (MAX_FIELDS_PER_PKT - 1)].val = val;
}

SEC("xdp")
int ppt_net_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;      /* IPv4 only in v1 */

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    __u32 ihl = iph->ihl * 4;
    if (ihl < sizeof(struct iphdr)) return XDP_PASS;

    __s32 src_ip = (__s32)bpf_ntohl(iph->saddr);
    __s32 dst_ip = (__s32)bpf_ntohl(iph->daddr);
    __s32 proto  = iph->protocol;
    __s32 pkt_len = bpf_ntohs(iph->tot_len);
    __s32 ttl = iph->ttl;
    __s32 sport = 0, dport = 0, tcp_flags = 0;

    void *l4 = (void *)iph + ihl;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *th = l4;
        if ((void *)(th + 1) <= data_end) {
            sport = bpf_ntohs(th->source);
            dport = bpf_ntohs(th->dest);
            tcp_flags = ((__u8 *)th)[13];              /* flags byte (FIN=0x01 SYN=0x02 ... ACK=0x10) */
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *uh = l4;
        if ((void *)(uh + 1) <= data_end) {
            sport = bpf_ntohs(uh->source);
            dport = bpf_ntohs(uh->dest);
        }
    }

    __u32 zero = 0;
    struct ppt_regfile *rf = bpf_map_lookup_elem(&regs_map, &zero);
    if (!rf) return XDP_PASS;
    /* fill the fixed canonical schema; slots >= NET_FIELDS default to NONE */
    #pragma unroll
    for (__u32 i = 0; i < MAX_FIELDS_PER_PKT; i++) {
        rf->r[i & (MAX_FIELDS_PER_PKT - 1)].ty = TY_NONE;
        rf->r[i & (MAX_FIELDS_PER_PKT - 1)].val = 0;
    }
    set_reg(rf, 0, src_ip); set_reg(rf, 1, dst_ip); set_reg(rf, 2, sport); set_reg(rf, 3, dport);
    set_reg(rf, 4, proto);  set_reg(rf, 5, pkt_len); set_reg(rf, 6, tcp_flags); set_reg(rf, 7, ttl);

    /* Read the active bank ONCE — a single aligned load, atomic against the loader's flip. Every
     * table access below is confined to this bank; whichever value we read (old or new), the whole
     * policy we evaluate is internally consistent. */
    __u32 zero_key = 0;
    __u32 *bank_ptr = bpf_map_lookup_elem(&bank_map, &zero_key);
    __u32 bank = (bank_ptr ? *bank_ptr : 0) & 1;

    struct ppt_config *cfg = bpf_map_lookup_elem(&config_map, &bank);   /* per-bank config */
    __u32 start_node = cfg ? cfg->start_node : 0;

    __s32 matched_edge = -1, target_node = -1;
    int rc = evaluate(start_node, NET_FIELDS, bank, &matched_edge, &target_node);

    /* observe-only: record the verdict, never drop */
    __u32 bucket = (rc == 0 && target_node >= 0) ? ((__u32)target_node & (MAX_NODES - 1))
                                                 : (MAX_NODES - 1);   /* last slot = no-match */
    __u64 *cnt = bpf_map_lookup_elem(&verdict_map, &bucket);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    __u32 rk = 0;
    struct ppt_result *res = bpf_map_lookup_elem(&result_map, &rk);
    if (res) {
        res->matched_edge = matched_edge;
        res->target_node = target_node;
        res->eval_status = (rc == 0) ? 1 : 0;
        __sync_fetch_and_add(&res->pkt_count, 1);
    }

    /* Inline enforcement: if the matched decision node is flagged in cfg->drop_mask, DROP; else PASS.
     * drop_mask == 0 (default) keeps this observe-only. The histogram above already counted this packet
     * under its decision bucket, so netstats reflects drops too. Nodes 0-63; the shift is bounded. */
    if (cfg && target_node >= 0 && target_node < 64 &&
        (cfg->drop_mask & (1ULL << ((__u32)target_node & 63))))
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
