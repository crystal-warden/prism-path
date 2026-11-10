// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ebpf_batch.c: the eBPF table target's leg of the verified core's differential harness
 * (formal/diff/core_diff.py), on its userspace path.
 *
 * Loading an XDP program and running it with BPF_PROG_TEST_RUN needs CAP_BPF (the kernel here has
 * unprivileged BPF disabled), so this leg runs the in-kernel evaluator's own text on the host instead:
 * prismpath-ebpf/ppt_eval_bpf.h, the one eval_atom, eval_prog and evaluate every XDP program there
 * includes, compiled natively against a shim of the three BPF facilities it uses (array maps,
 * bpf_map_lookup_elem and bpf_loop, each with the kernel's semantics: a lookup past max_entries is NULL,
 * a loop stops when its callback returns 1). The table is admitted by the loader's own parser
 * (prismpath-ebpf/ppt_image.c, parse_image_buf with its capacity and check_evaluator_limits, the eBPF
 * target's declared subset: an operand stack of 4, 64 edges per node, 64 words per edge, 32 fields) and
 * written into the maps as ppt_maps.c writes them. What this does not cover is the verifier and the JIT;
 * the kernel certification (`ebpf_kernel` in CI, facet_decode_cert.py, cert_selector) covers those.
 *
 *   cc -O2 -std=gnu11 -I prismpath-ebpf -o ebpf_batch formal/diff/ebpf_batch.c prismpath-ebpf/ppt_image.c
 *
 * Input and output are ppt_batch.c's: `case <id> <n>`, the .ppt image and n register files framed as
 * `<byte length>\n<bytes>\n`; per case one line, the id, then per reading `m <edge> <target>`, `n`, `-`
 * (no register file) or `e <why>`, separated by `;`. `e limits` is a table the loader refuses. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>
#include "ppt_common.h"
#include "ppt_image.h"

/* ------------------------------------------------------------------ the BPF shim */
#define SEC(NAME)
#define __uint(name, val) int (*name)[val]
#define __type(name, val) __typeof__(val) *name
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

struct shim_map { const void *map; uint8_t *data; };
static struct shim_map shim_maps[8];

/* An array map's element `key`, or NULL past max_entries, as the kernel's array map answers. */
static void *shim_lookup(const void *map, size_t elem, size_t entries, uint32_t key)
{
    if (key >= entries) return NULL;
    for (size_t slot = 0; slot < sizeof shim_maps / sizeof shim_maps[0]; slot++) {
        if (shim_maps[slot].map == map) return shim_maps[slot].data + (size_t)key * elem;
        if (!shim_maps[slot].map) {
            shim_maps[slot].map = map;
            shim_maps[slot].data = calloc(entries, elem);
            if (!shim_maps[slot].data) { fprintf(stderr, "ebpf_batch: out of memory\n"); exit(3); }
            return shim_maps[slot].data + (size_t)key * elem;
        }
    }
    fprintf(stderr, "ebpf_batch: too many maps\n");
    exit(3);
}

#define bpf_map_lookup_elem(map, keyp) \
    shim_lookup((map), sizeof(*(map)->value), sizeof(*(map)->max_entries) / sizeof(int), *(const __u32 *)(keyp))

/* bpf_loop: the callback for 0, 1, ... nr - 1 until it returns 1; the number of iterations made. */
static long bpf_loop(__u32 nr, long (*callback)(__u32, void *), void *ctx, __u64 flags)
{
    (void)flags;
    for (__u32 index = 0; index < nr; index++)
        if (callback(index, ctx)) return (long)index + 1;
    return (long)nr;
}

/* ------------------------------------------------------------------ the maps, as ppt_xdp.bpf.c declares them */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct ppt_atom);
         __uint(max_entries, MAX_ATOMS); } atoms_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct ppt_node);
         __uint(max_entries, MAX_NODES); } nodes_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct ppt_edge);
         __uint(max_entries, MAX_EDGES); } edges_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, __u16);
         __uint(max_entries, MAX_PROG_WORDS); } prog_map SEC(".maps");

#include "ppt_eval_bpf.h"

/* ------------------------------------------------------------------ the driver */
static uint8_t *input; static size_t input_len, pos;

static int read_line(char *out, size_t cap) {
    size_t start = pos;
    while (pos < input_len && input[pos] != '\n') pos++;
    if (pos >= input_len || pos - start >= cap) return 0;
    memcpy(out, input + start, pos - start); out[pos - start] = 0; pos++;
    return 1;
}

static const uint8_t *read_frame(size_t *len) {
    char line[64];
    if (!read_line(line, sizeof line)) { fprintf(stderr, "ebpf_batch: truncated frame\n"); exit(3); }
    *len = (size_t)strtoul(line, NULL, 10);
    if (pos + *len + 1 > input_len) { fprintf(stderr, "ebpf_batch: truncated frame body\n"); exit(3); }
    const uint8_t *frame = input + pos; pos += *len + 1;
    return frame;
}

static int32_t le32(const uint8_t *bytes) { int32_t value; memcpy(&value, bytes, 4); return value; }

/* The table into the maps, every slot: the image's elements, then zeros (a fresh map), as a load does. */
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

int main(void) {
    size_t cap = 1 << 20; input = malloc(cap);
    for (size_t got; (got = fread(input + input_len, 1, cap - input_len, stdin)) > 0;) {
        input_len += got;
        if (input_len == cap) { cap *= 2; input = realloc(input, cap); }
    }
    char header[256];
    while (pos < input_len) {
        if (!read_line(header, sizeof header)) { fprintf(stderr, "ebpf_batch: bad header\n"); return 3; }
        char ident[200]; unsigned count;
        if (sscanf(header, "case %199s %u", ident, &count) != 2) { fprintf(stderr, "ebpf_batch: bad header %s\n", header); return 3; }
        size_t image_len; const uint8_t *image = read_frame(&image_len);
        printf("%s", ident);
        Image im; memset(&im, 0, sizeof im);
        /* the loader's parser names why it refuses on stderr, which the harness keeps apart */
        int admitted = parse_image_buf(image, (long)image_len, &im) == 0;
        if (admitted) populate(&im);
        for (unsigned index = 0; index < count; index++) {
            size_t regs_len; const uint8_t *frame = read_frame(&regs_len);
            printf(index ? ";" : " ");
            if (regs_len == 0) { printf("-"); continue; }
            if (!admitted) { printf("e limits"); continue; }
            if (regs_len != 4 + 8u * im.n_fields) { printf("e regs"); continue; }
            __u32 zero = 0;
            struct ppt_regfile *regfile = bpf_map_lookup_elem(&regs_map, &zero);
            for (__u32 field = 0; field < MAX_FIELDS_PER_PKT; field++) {
                regfile->reg[field].ty = field < im.n_fields ? le32(frame + 4 + 8 * field) : TY_NONE;
                regfile->reg[field].val = field < im.n_fields ? le32(frame + 8 + 8 * field) : 0;
            }
            __u32 node = (__u32)le32(frame);
            if (node >= im.n_nodes) { printf("e node"); continue; }
            __s32 matched = -1, target = -1;
            evaluate(node, im.n_fields, PPT_BANK_SINGLE, &matched, &target);
            if (matched < 0) printf("n");
            else printf("m %d %d", matched, target);
        }
        if (admitted) free_image(&im);
        printf("\n");
    }
    return 0;
}
