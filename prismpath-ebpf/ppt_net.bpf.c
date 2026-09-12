// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_net.bpf.c: PrismPath PPT on REAL network packets (XDP), observe-only by default.
 *
 * The evaluator it runs (eval_atom, eval_prog, evaluate over the PPT table maps) is the shared
 * ppt_eval_bpf.h, the same text ppt_xdp.bpf.c certifies. What is this program's own is the FRONT-END,
 * which parses a live Ethernet/IPv4/TCP-UDP packet instead of a crafted PPT packet: it fills a FIXED
 * canonical register file from the packet's real fields, evaluates the flow's start node in-kernel,
 * and records the verdict into a per-target histogram. It is also the only program here that holds
 * TWO banks of the table, which is how a policy swap commits atomically under live traffic. Its
 * default verdict is XDP_PASS and only a decision node named in the signed drop_mask turns into an
 * XDP_DROP. Meant for an attach on a mirror (span0), where a mirror cannot be back-pressured and a
 * bug cannot harm production traffic.
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

/* Two banks of every table map above, so the evaluator must offset each index by a whole bank; the
 * other three programs hold one bank and this switch compiles that arithmetic away for them. */
#define PPT_EVAL_BANKED 1

/* The evaluator, the per-packet register file and the verifier rationale behind their shape: one
 * text for all four XDP programs here. Include it AFTER the table maps it reads. */
#include "ppt_eval_bpf.h"

/* ------------------------------------------------------------------ real-packet front-end */
static __always_inline void set_reg(struct ppt_regfile *regfile, __u32 slot, __s32 val)
{
    regfile->reg[slot & (MAX_FIELDS_PER_PKT - 1)].ty = TY_INT;
    regfile->reg[slot & (MAX_FIELDS_PER_PKT - 1)].val = val;
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

    struct ppt_regfile *regfile = ppt_regs();
    if (!regfile) return XDP_PASS;
    /* fill the fixed canonical schema; slots >= NET_FIELDS default to NONE */
    #pragma unroll
    for (__u32 field_index = 0; field_index < MAX_FIELDS_PER_PKT; field_index++) {
        regfile->reg[field_index & (MAX_FIELDS_PER_PKT - 1)].ty = TY_NONE;
        regfile->reg[field_index & (MAX_FIELDS_PER_PKT - 1)].val = 0;
    }
    set_reg(regfile, 0, src_ip);
    set_reg(regfile, 1, dst_ip);
    set_reg(regfile, 2, sport);
    set_reg(regfile, 3, dport);
    set_reg(regfile, 4, proto);
    set_reg(regfile, 5, pkt_len);
    set_reg(regfile, 6, tcp_flags);
    set_reg(regfile, 7, ttl);

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
