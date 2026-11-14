// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* gn_batch.c: the governed net XDP program's decision, on its userspace path.
 *
 * Loading an XDP program needs CAP_BPF and this host has unprivileged BPF disabled, so, as
 * formal/diff/ebpf_batch.c does for the core differential, this runs the program's own text natively:
 * gn_xdp.h (the frame parse, the strict reading of the request, the register fill and the action) and
 * ../ppt_eval_bpf.h (the evaluator every XDP program here shares), over a shim of the BPF facilities they
 * use, each with the kernel's semantics: an array map lookup past max_entries is NULL and a fresh map is
 * zeros, bpf_loop stops when its callback returns 1, and the ring buffer is a slot this driver reads after
 * each frame. The table is admitted by the loader's own parser (../ppt_image.c, parse_image_buf with
 * check_evaluator_limits) and written into the maps as a load does, then `loaded` is set last.
 * Not covered here: the verifier and the JIT (SETUP.md has the in-kernel run that covers them).
 *
 *   cc -O2 -std=gnu11 -I prismpath-ebpf -o gn_batch prismpath-ebpf/gnet/gn_batch.c prismpath-ebpf/ppt_image.c
 *   gn_batch TABLE.ppt ACTIONS --server-ip A.B.C.D --port N [--empty] [--ring-full] [--image-index N]  < frames  > decisions
 *
 * --server-ip and --port are the match target: a frame is the agent protocol only when its IPv4
 * destination and UDP destination port are these (gn_xdp.h). They default to 0, which no real frame
 * matches, so they must be set for the policy to see any traffic. Input: frames, each a 4 byte little
 * endian length and the frame (Ethernet onwards). Output: one line per frame, written and flushed as it is
 * decided (so the userspace gate can stream through it):
 *   <outcome> <reason> <edge> <cause> <emitted> <request_id> <cmd> <hclass> <arg0> <arg1> <name_len>
 *   <data_len> <handle> <image_index> <src_port> <src_ip>
 * `emitted` is 1 when the frame produced a ring buffer event, and `edge` is -1 when it did not, as gn_loader
 * test-run prints it. At the end it prints the per-verdict counters
 * to stderr as `counters <other> <allow> <drop> <malformed>` (GN_CNT_*). */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>
#include "ppt_common.h"
#include "ppt_image.h"

/* ------------------------------------------------------------------ the BPF shim (as ebpf_batch.c) */
#define SEC(NAME)
#define __uint(name, val) int (*name)[val]
#define __type(name, val) __typeof__(val) *name
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

struct shim_map { const void *map; uint8_t *data; };
static struct shim_map shim_maps[16];

static void *shim_lookup(const void *map, size_t elem, size_t entries, uint32_t key)
{
    if (key >= entries) return NULL;
    for (size_t slot = 0; slot < sizeof shim_maps / sizeof shim_maps[0]; slot++) {
        if (shim_maps[slot].map == map) return shim_maps[slot].data + (size_t)key * elem;
        if (!shim_maps[slot].map) {
            shim_maps[slot].map = map;
            shim_maps[slot].data = calloc(entries, elem);
            if (!shim_maps[slot].data) { fprintf(stderr, "gn_batch: out of memory\n"); exit(3); }
            return shim_maps[slot].data + (size_t)key * elem;
        }
    }
    fprintf(stderr, "gn_batch: too many maps\n");
    exit(3);
}

#define bpf_map_lookup_elem(map, keyp) \
    shim_lookup((map), sizeof(*(map)->value), sizeof(*(map)->max_entries) / sizeof(int), *(const __u32 *)(keyp))

static long bpf_loop(__u32 nr, long (*callback)(__u32, void *), void *ctx, __u64 flags)
{
    (void)flags;
    for (__u32 index = 0; index < nr; index++)
        if (callback(index, ctx)) return (long)index + 1;
    return (long)nr;
}

/* ------------------------------------------------------------------ the maps, as gn_xdp.bpf.c declares them */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct ppt_atom);
         __uint(max_entries, MAX_ATOMS); } atoms_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct ppt_node);
         __uint(max_entries, MAX_NODES); } nodes_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct ppt_edge);
         __uint(max_entries, MAX_EDGES); } edges_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, __u16);
         __uint(max_entries, MAX_PROG_WORDS); } prog_map SEC(".maps");

#include "ppt_eval_bpf.h"
#include "gnet/gn_maps.h"

/* the ring buffer: one slot, read after every frame; `ring_fail` makes every output fail (a full ring) */
static struct gn_event ring_slot;
static int ring_used, ring_fail;
static long shim_ring_output(const struct gn_event *ev)
{
    if (ring_fail) return -1;
    ring_slot = *ev;
    ring_used = 1;
    return 0;
}
#define GN_EMIT(ev) shim_ring_output(ev)

#include "gnet/gn_xdp.h"

/* ------------------------------------------------------------------ the driver */
static void populate(const Image *im)
{
    for (__u32 index = 0; index < MAX_ATOMS; index++) {
        struct ppt_atom *slot = bpf_map_lookup_elem(&atoms_map, &index);
        if (index < im->n_atoms) *slot = im->atoms[index]; else memset(slot, 0, sizeof *slot);
    }
    for (__u32 index = 0; index < MAX_NODES; index++) {
        struct ppt_node *slot = bpf_map_lookup_elem(&nodes_map, &index);
        if (index < im->n_nodes) *slot = im->nodes[index]; else memset(slot, 0, sizeof *slot);
    }
    for (__u32 index = 0; index < MAX_EDGES; index++) {
        struct ppt_edge *slot = bpf_map_lookup_elem(&edges_map, &index);
        if (index < im->n_edges) *slot = im->edges[index]; else memset(slot, 0, sizeof *slot);
    }
    for (__u32 index = 0; index < MAX_PROG_WORDS; index++) {
        __u16 *slot = bpf_map_lookup_elem(&prog_map, &index);
        *slot = index < im->prog_len ? im->prog[index] : 0;
    }
}

/* The action file (integrations/governed_net/policy.py, NetPolicy.actions): "GNAC", the rule count, the
 * image's sha256, then per rule pass, kind and cause. Returns the rule count, or -1. */
static int load_actions(const uint8_t *bytes, long len)
{
    if (len < 40 || (uint32_t)rd32(bytes) != 0x474E4143u) return -1;
    uint32_t rules = (uint32_t)rd32(bytes + 4);
    if (rules > GN_MAX_RULES || len != 40 + 4 * (long)rules) return -1;
    for (__u32 rule = 0; rule < rules; rule++) {
        struct gn_action *slot = bpf_map_lookup_elem(&gn_action_map, &rule);
        slot->pass = bytes[40 + 4 * rule];
        slot->kind = bytes[41 + 4 * rule];
        slot->cause = rd16(bytes + 42 + 4 * rule);
    }
    return (int)rules;
}

/* "A.B.C.D" -> host-order u32, as gn_be32 reads it from the wire; 0 on a malformed address. */
static __u32 parse_ipv4(const char *text)
{
    unsigned a, b, c, d;
    if (sscanf(text, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 || (a | b | c | d) > 255) return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: gn_batch TABLE.ppt ACTIONS --server-ip A.B.C.D --port N "
                                     "[--empty] [--ring-full] [--image-index N]\n"); return 2; }
    int empty = 0;
    __u32 image_index = 1, match_dst_ip = 0, match_port = 0;
    for (int arg = 3; arg < argc; arg++) {
        if (!strcmp(argv[arg], "--empty")) empty = 1;
        else if (!strcmp(argv[arg], "--ring-full")) ring_fail = 1;
        else if (!strcmp(argv[arg], "--image-index") && arg + 1 < argc) image_index = (__u32)strtoul(argv[++arg], NULL, 10);
        else if (!strcmp(argv[arg], "--server-ip") && arg + 1 < argc) match_dst_ip = parse_ipv4(argv[++arg]);
        else if (!strcmp(argv[arg], "--port") && arg + 1 < argc) match_port = (__u32)strtoul(argv[++arg], NULL, 10);
        else { fprintf(stderr, "gn_batch: unknown argument %s\n", argv[arg]); return 2; }
    }
    long table_len, actions_len;
    uint8_t *table = read_file(argv[1], &table_len);
    uint8_t *actions = read_file(argv[2], &actions_len);
    Image im; memset(&im, 0, sizeof im);
    if (parse_image_buf(table, table_len, &im) != 0) { fprintf(stderr, "gn_batch: the loader refuses the table\n"); return 3; }
    /* the match target is always set (even --empty, so the fail-closed case is a configured target with no
     * policy); the table and loaded flag are set only when not --empty */
    __u32 zero = 0;
    struct gn_config *cfg = bpf_map_lookup_elem(&gn_config_map, &zero);
    cfg->match_dst_ip = match_dst_ip;
    cfg->match_port = match_port;
    if (!empty) {
        populate(&im);
        int rules = load_actions(actions, actions_len);
        if (rules < 0) { fprintf(stderr, "gn_batch: bad action file\n"); return 3; }
        cfg->start_node = im.start;
        cfg->image_index = image_index;
        cfg->n_rules = (__u32)rules;
        cfg->loaded = 1;                                   /* last, as the loader does */
    }
    static uint8_t frame[65536];
    for (;;) {
        uint8_t prefix[4];
        if (fread(prefix, 1, 4, stdin) != 4) break;
        uint32_t len = (uint32_t)rd32(prefix);
        if (len > sizeof frame || fread(frame, 1, len, stdin) != len) { fprintf(stderr, "gn_batch: truncated frame\n"); return 3; }
        struct gn_event ev; memset(&ev, 0, sizeof ev);
        ring_used = 0;
        __u32 outcome = gn_decide(frame, frame + len, &ev);
        const struct gn_event *out = ring_used ? &ring_slot : &ev;
        printf("%u %u %d %u %d %llu %u %u %u %u %u %u %u %u %u %u\n", outcome, out->reason, ring_used ? out->edge : -1, out->cause,
               ring_used, (unsigned long long)out->request_id, out->cmd, out->hclass, out->arg0, out->arg1,
               out->name_len, out->data_len, out->handle, out->image_index, out->src_port, out->src_ip);
        fflush(stdout);
    }
    __u64 counts[GN_CNT_N] = {0};
    for (__u32 i = 0; i < GN_CNT_N; i++) {
        __u64 *slot = bpf_map_lookup_elem(&gn_counts_map, &i);
        if (slot) counts[i] = *slot;
    }
    fprintf(stderr, "counters %llu %llu %llu %llu\n", (unsigned long long)counts[GN_CNT_OTHER],
            (unsigned long long)counts[GN_CNT_ALLOW], (unsigned long long)counts[GN_CNT_DROP],
            (unsigned long long)counts[GN_CNT_MALFORMED]);
    free_image(&im);
    free(table); free(actions);
    return 0;
}
