// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_select.bpf.c: PrismPath PPT resident stateful selector in eBPF (ppt_select)
 *
 * The evaluator it runs (eval_atom, eval_prog, evaluate and the payload register fill, exact against
 * interp.c semantics) is the shared ppt_eval_bpf.h, the same text ppt_xdp.bpf.c certifies, which is
 * why the frozen predicate conformance carries to this program unchanged; that header also records
 * which verifier limit forced which part of its shape. What is this program's own is the resident
 * layer: the start node is the resident node persisted in sel_state_map rather than anything the packet
 * says, the decided target is committed back under a generation-counter CAS, and every committed
 * transition emits an audit receipt. It holds ONE bank of the table.
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

/* The evaluator, the per-packet register file and the verifier rationale behind their shape: one
 * text for all four XDP programs here. Include it AFTER the table maps it reads. */
#include "ppt_eval_bpf.h"

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

    /* One lookup of the per-CPU register file, then the shared payload fill (ppt_eval_bpf.h). */
    struct ppt_regfile *regfile = ppt_regs();
    if (regfile)
        ppt_load_regs_from_payload(regfile, payload_start, data_end, n_fields);

    __s32 ev_value = 0;                               /* the driving event (field 0) for the receipt */
    if (regfile && n_fields > 0)
        ev_value = regfile->reg[0].val;

    /* RESIDENT + SERIALIZED. The start node is the persisted cur_node, not pkt_hdr->node_idx; each
     * control packet is one discrete event and the map holds the state. FAIL-SAFE: inited==0 means the
     * state was NOT deliberately set (crash, fresh/torn map), so fall to the MOST RESTRICTIVE node
     * (the last, highest-severity node), never the baseline — a forced reload must buy lockdown, not
     * normal. A deliberate clean start is the loader writing {start_node, inited=1}; the program only
     * sees inited==0 when something went wrong. (Nodes ordered least->most restrictive, the severity
     * order the spiral lint enforces; an explicit signed safe_node is the follow-up.)
     *
     * CONCURRENCY: on a multi-queue NIC this program runs on several CPUs at once against the ONE
     * shared sel_state_map. evaluate() calls map helpers, so it cannot run under a bpf_spin_lock;
     * instead the read-modify-write is a generation-counter CAS — snapshot {cur,gen} under the lock,
     * evaluate UNLOCKED, then commit under the lock only if gen is unchanged. A concurrent loser (the
     * state advanced since our snapshot) is DROPPED, never applied from stale state, so the resident node
     * only ever steps along a real edge of its actual current value, never a phantom. Strict global
     * ORDER for a multi-queue deployment is single-RX-queue steering (the kernel analog of the fabric
     * clock); this lock gives integrity + no stale-misapply, which the concurrent smoke test measures. */
    __u32 zk = 0;
    struct ppt_sel_state *st = bpf_map_lookup_elem(&sel_state_map, &zk);
    struct ppt_config *scfg = bpf_map_lookup_elem(&config_map, &zk);
    /* most restrictive node: the policy's SIGNED safe_node if declared (offset-26 high byte, rides
     * the manifest signature); else the last-node convention. 0 = undeclared, hence the fallback. */
    __u32 failsafe = 0;
    if (scfg) {
        failsafe = scfg->safe_node ? scfg->safe_node
                                   : (scfg->n_nodes ? (scfg->n_nodes - 1) : 0);
    }
    /* Bounded-retry CAS: on a lost commit, re-snapshot from the NEW state and re-evaluate, up to
     * SEL_MAX_RETRY times, so a concurrent contender turns a drop into a commit against fresh state
     * rather than losing the event. Every re-evaluation is from the actual current resident node, so a
     * committed transition is never stale. Only pathological contention (all attempts lose) drops. */
    __s32 matched_edge = -1;
    int rc = -1;
    __u32 resident_node = failsafe;
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
            rc = evaluate(cur, n_fields, PPT_BANK_SINGLE, &matched_edge, &target_node);
            resident_node = cur;
            if (rc != 0 || target_node < 0) { done = 1; break; }   /* nothing to commit */

            int committed = 0;
            __u32 new_seq = 0;
            bpf_spin_lock(&st->lock);
            if (st->gen == snap_gen) {                             /* uncontended: commit the advance */
                st->cur_node = (__u32)target_node;
                st->inited = 1;
                st->gen = snap_gen + 1;
                new_seq = st->gen;
                resident_node = (__u32)target_node;
                committed = 1;
                done = 1;
            } else {
                resident_node = st->cur_node;                           /* contended: report winner, retry */
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
                    rcpt->cause = PPT_CAUSE_NONE;   /* ordinary committed transition */
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
        res->target_node = (__s32)resident_node;            /* the NEW resident node after this event */
        res->eval_status = (rc == 0) ? 1 : 0;
        __sync_fetch_and_add(&res->pkt_count, 1);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
