// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_xdp.bpf.c (A6 decode and rewrite variant): PrismPath PPT v1 Match-Action Table Interpreter in XDP/eBPF.
 * This variant writes the verdict INTO the packet (node_idx becomes the decided node, the UDP checksum is
 * cleared, which IPv4 permits) and passes it up, so a socket above the stack reads a decision the kernel
 * made on the NIC path and no application took part in.
 *
 * The evaluator it runs (eval_atom, eval_prog, evaluate and the payload register fill, exact against
 * interp.c semantics) is the shared ppt_eval_bpf.h, the same text ppt_xdp.bpf.c certifies; that header
 * also records which verifier limit forced which part of its shape. What is genuinely this variant's
 * own is the rewrite and the refusal: a packet whose register payload is short of the policy's field
 * count is sent up carrying PPT_A6_REFUSED_SHORT rather than a decision, and a decided packet carries
 * the target node, or PPT_A6_NO_MATCH when no edge matched. It holds ONE bank of the table.
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
    struct udphdr *udph_found = 0;
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
                                    udph_found = udph;
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
    /* Incomplete register payloads pass up undecided so upstream listeners reject truncated packets. */
    {
        __u32 ck = 0; struct ppt_config *cfg = bpf_map_lookup_elem(&config_map, &ck);
        __u32 need = n_fields > MAX_FIELDS_PER_PKT ? MAX_FIELDS_PER_PKT : n_fields;
        if ((cfg && n_fields < cfg->n_fields) || payload_start + need * sizeof(struct ppt_reg) > data_end) {
            if ((void *)(pkt_hdr + 1) <= data_end) pkt_hdr->node_idx = PPT_A6_REFUSED_SHORT;
            if (udph_found && (void *)(udph_found + 1) <= data_end) udph_found->check = 0;
            return XDP_PASS;
        }
    }

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
    /* Decided node or no-match sentinel is written into packet to inform upstream socket. */
    if ((void *)(pkt_hdr + 1) <= data_end) pkt_hdr->node_idx = target_node >= 0 ? (__u32)target_node : PPT_A6_NO_MATCH;
    if (udph_found && (void *)(udph_found + 1) <= data_end) udph_found->check = 0;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
