// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_xdp.bpf.c: PrismPath PPT reference conformance program in XDP/eBPF
 *
 * The evaluator it runs (eval_atom, eval_prog, evaluate and the payload register fill, exact against
 * interp.c semantics) is shared with the other three XDP programs here and lives in ppt_eval_bpf.h,
 * which also records which verifier limit forced which part of its shape. What stays here is the
 * front end: parse a crafted PPT packet, evaluate the node the packet names, record the verdict in
 * result_map. This is the program the in-kernel conformance corpus certifies. It holds ONE bank of
 * the table, and it changes neither the packet nor anything outside result_map.
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

/* The evaluator, the per-packet register file and the verifier rationale behind their shape: one
 * text for all four XDP programs here. Include it AFTER the table maps it reads. */
#include "ppt_eval_bpf.h"

/* ------------------------------------------------------------------ XDP Program Entry Point */

SEC("xdp")
int ppt_xdp_prog(struct xdp_md *ctx)
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

    /* One lookup of the per-CPU register file, then the shared payload fill (ppt_eval_bpf.h). */
    struct ppt_regfile *regfile = ppt_regs();
    if (regfile)
        ppt_load_regs_from_payload(regfile, payload_start, data_end, n_fields);

    __s32 matched_edge = -1;
    __s32 target_node = -1;

    int rc = evaluate(pkt_hdr->node_idx, n_fields, PPT_BANK_SINGLE, &matched_edge, &target_node);

    /* Record classification outcome into result BPF map */
    __u32 key = 0;
    struct ppt_result *res = bpf_map_lookup_elem(&result_map, &key);
    if (res) {
        res->matched_edge = matched_edge;
        res->target_node = target_node;
        res->eval_status = (rc == 0) ? 1 : 0;
        __sync_fetch_and_add(&res->pkt_count, 1);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
