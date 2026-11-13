// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* gn_xdp.bpf.c: the governed net enforcement point. Every UDP datagram to the agent protocol's port is
 * read strictly, decided against the signed policy's table by the shared evaluator (../ppt_eval_bpf.h),
 * reported to the receipt logger through a ring buffer, and passed to the tool server only when the
 * policy allows it. A refusal, an escalation, a malformed request, a request with no policy loaded and an
 * allowed request whose record could not be written are XDP_DROPped. Everything that is not the agent
 * protocol is XDP_PASSed before its payload is read (gn_xdp.h says how), so the interface's other traffic,
 * SSH and management among it, is excluded from the policy by construction.
 *
 * The tables start empty, and empty tables fail closed: gn_config_map.loaded is 0 until gn_loader has
 * written the whole table, and until then every request to the port is dropped while all other traffic
 * passes. That makes `ip link set dev IF xdp obj gn_xdp.bpf.o sec xdp` a harmless first attach that
 * shows the verifier accepts the program (integrations/governed_net/SETUP.md).
 *
 * The program cannot sign. The ring buffer carries each decision (request id, image index, matched rule,
 * cause and the decided fields) to integrations/governed_net/receipt_logger.py, which writes the canon/2
 * core receipt and the signed root in userspace. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "../ppt_common.h"

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* the table image, single bank, as ppt_xdp.bpf.c declares it */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct ppt_atom);
         __uint(max_entries, MAX_ATOMS); } atoms_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct ppt_node);
         __uint(max_entries, MAX_NODES); } nodes_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct ppt_edge);
         __uint(max_entries, MAX_EDGES); } edges_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, __u16);
         __uint(max_entries, MAX_PROG_WORDS); } prog_map SEC(".maps");

#include "../ppt_eval_bpf.h"
#include "gn_maps.h"

struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } gn_events SEC(".maps");

#define GN_EMIT(ev) bpf_ringbuf_output(&gn_events, (ev), sizeof(struct gn_event), 0)

#include "gn_xdp.h"

SEC("xdp")
int gn_xdp_prog(struct xdp_md *ctx)
{
    const __u8 *data = (const __u8 *)(long)ctx->data;
    const void *data_end = (const void *)(long)ctx->data_end;
    struct gn_event ev = {};
    ev.t_ns = bpf_ktime_get_ns();
    __u32 outcome = gn_decide(data, data_end, &ev);
    return (outcome == GN_OTHER || outcome == GN_ALLOW) ? XDP_PASS : XDP_DROP;
}

char _license[] SEC("license") = "GPL";
