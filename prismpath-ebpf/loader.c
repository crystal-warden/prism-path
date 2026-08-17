// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* loader.c — PrismPath PPT v1 eBPF/XDP Userspace Loader
 *
 * Reads a PPT table image (.ppt binary format), populates BPF maps,
 * attaches the XDP program to a network interface (e.g. veth),
 * feeds input register files, and reads back classification verdicts.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <pthread.h>

#ifndef NO_LIBBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>   /* XDP_FLAGS_SKB_MODE */
#endif

#include "ppt_common.h"

#define PIN_PATH "/sys/fs/bpf/ppt_result"   /* result_map pin: read back the in-kernel verdict */
#define NET_VERDICT_PIN "/sys/fs/bpf/ppt_net_verdict"  /* real-packet per-target histogram */
#define NET_RESULT_PIN  "/sys/fs/bpf/ppt_net_result"   /* real-packet last-verdict + pkt_count */

typedef struct {
    uint16_t n_fields, n_interns, n_atoms, n_nodes, n_edges, prog_len,
             start, visits_idx, max_steps, max_stack;
    struct ppt_atom *atoms;
    struct ppt_node *nodes;
    struct ppt_edge *edges;
    uint16_t *prog;
} Image;

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static int32_t rd32(const uint8_t *p) {
    return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                     ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static uint8_t *read_file(const char *path, long *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "error: cannot open %s\n", path); exit(2); }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)n);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fprintf(stderr, "error: cannot read %s\n", path); exit(2);
    }
    fclose(f); *out_len = n; return buf;
}

/* Build an eth+ip+udp+ppt frame for evaluating `node_idx` with `regs` (matches smoke.sh / cert_*.py
 * framing: network-order L2/L3/L4 headers, little-endian PPT payload). Returns the frame length. */
static int build_frame(uint8_t *out, uint16_t node_idx, uint16_t n_fields, const struct ppt_reg *regs) {
    int ppt_len = 12 + 8 * n_fields;
    int udp_len = 8 + ppt_len;
    int ip_len = 20 + udp_len;
    uint8_t *p = out;
    memset(p, 0xff, 6); p += 6; memset(p, 0x02, 6); p += 6; *p++ = 0x08; *p++ = 0x00;   /* eth */
    *p++ = 0x45; *p++ = 0x00; *p++ = (uint8_t)(ip_len >> 8); *p++ = (uint8_t)ip_len;     /* ip  */
    *p++ = 0x12; *p++ = 0x34; *p++ = 0x00; *p++ = 0x00; *p++ = 64; *p++ = 17; *p++ = 0; *p++ = 0;
    *p++ = 192; *p++ = 168; *p++ = 1; *p++ = 1;  *p++ = 192; *p++ = 168; *p++ = 1; *p++ = 2;
    *p++ = 0x30; *p++ = 0x39; *p++ = 0x27; *p++ = 0x0f;                                  /* udp 12345->9999 */
    *p++ = (uint8_t)(udp_len >> 8); *p++ = (uint8_t)udp_len; *p++ = 0; *p++ = 0;
    uint32_t magic = PPT_MAGIC, ni = node_idx, nf = n_fields;
    memcpy(p, &magic, 4); p += 4; memcpy(p, &ni, 4); p += 4; memcpy(p, &nf, 4); p += 4;  /* ppt_hdr (LE) */
    for (int i = 0; i < n_fields; i++) {
        memcpy(p, &regs[i].ty, 4); p += 4; memcpy(p, &regs[i].val, 4); p += 4;
    }
    return (int)(p - out);
}

/* Parse a PPT image already resident in memory. Mallocs im->atoms/nodes/edges/prog (free_image frees
 * them). Returns 0 on success, -1 on a malformed image (used by the certify loop, which must not exit). */
static int parse_image_buf(const uint8_t *b, long len, Image *im) {
    if (len < 28 || rd32(b) != (int32_t)PPT_MAGIC || rd16(b + 4) != 1) {
        return -1;
    }
    im->n_fields = rd16(b + 6);   im->n_interns = rd16(b + 8);
    im->n_atoms = rd16(b + 10);   im->n_nodes = rd16(b + 12);
    im->n_edges = rd16(b + 14);   im->prog_len = rd16(b + 16);
    im->start = rd16(b + 18);     im->visits_idx = rd16(b + 20);
    im->max_steps = rd16(b + 22);  im->max_stack = rd16(b + 24);
    long need = 28 + 8L * im->n_atoms + 4L * im->n_nodes + 6L * im->n_edges + 2L * im->prog_len;
    if (len < need) return -1;
    /* Capacity bounds: the kernel maps are sized to these MAX_* — an image over any of them would
     * partially populate (higher indices silently dropped) and route wrong. Reject up front. */
    if (im->n_atoms > MAX_ATOMS || im->n_nodes > MAX_NODES || im->n_edges > MAX_EDGES ||
        im->prog_len > MAX_PROG_WORDS || im->n_fields > MAX_FIELDS_PER_PKT) {
        fprintf(stderr, "parse_image: table exceeds a MAX_* capacity "
                "(atoms=%u/%d nodes=%u/%d edges=%u/%d prog=%u/%d fields=%u/%d)\n",
                im->n_atoms, MAX_ATOMS, im->n_nodes, MAX_NODES, im->n_edges, MAX_EDGES,
                im->prog_len, MAX_PROG_WORDS, im->n_fields, MAX_FIELDS_PER_PKT);
        return -1;
    }
    const uint8_t *p = b + 28;
    im->atoms = malloc(sizeof(struct ppt_atom) * (im->n_atoms ? im->n_atoms : 1));
    for (int i = 0; i < im->n_atoms; i++, p += 8) {
        im->atoms[i].field = rd16(p); im->atoms[i].op = p[2]; im->atoms[i].ty = p[3];
        im->atoms[i].val = rd32(p + 4);
    }
    im->nodes = malloc(sizeof(struct ppt_node) * (im->n_nodes ? im->n_nodes : 1));
    for (int i = 0; i < im->n_nodes; i++, p += 4) {
        im->nodes[i].edge_off = rd16(p); im->nodes[i].edge_cnt = rd16(p + 2);
    }
    im->edges = malloc(sizeof(struct ppt_edge) * (im->n_edges ? im->n_edges : 1));
    for (int i = 0; i < im->n_edges; i++, p += 6) {
        im->edges[i].target = rd16(p); im->edges[i].prog_off = rd16(p + 2);
        im->edges[i].prog_cnt = rd16(p + 4);
    }
    im->prog = malloc(sizeof(uint16_t) * (im->prog_len ? im->prog_len : 1));
    for (int i = 0; i < im->prog_len; i++, p += 2) im->prog[i] = rd16(p);
    return 0;
}

static void free_image(Image *im) {
    free(im->atoms); free(im->nodes); free(im->edges); free(im->prog);
    im->atoms = NULL; im->nodes = NULL; im->edges = NULL; im->prog = NULL;
}

static void load_image(const char *path, Image *im) {
    long len; uint8_t *b = read_file(path, &len);
    if (parse_image_buf(b, len, im) != 0) {
        fprintf(stderr, "error: bad/truncated image %s\n", path); exit(2);
    }
    free(b);
}

/* Host reference evaluator (matches interp.c) */
static int eval_atom_host(const struct ppt_atom *a, const struct ppt_reg *regs, uint32_t n_fields) {
    struct ppt_reg r = (a->field < n_fields) ? regs[a->field] : (struct ppt_reg){TY_NONE, 0};
    int lnum = (r.ty == TY_BOOL || r.ty == TY_INT);
    int rnum = (a->ty == TY_BOOL || a->ty == TY_INT);
    switch (a->op) {
    case OP_EQ: case OP_NE: {
        int eq;
        if (lnum && rnum) eq = (r.val == a->val);
        else if (r.ty == TY_STR && a->ty == TY_STR) eq = (r.val == a->val);
        else if (r.ty == TY_NONE && a->ty == TY_NONE) eq = 1;
        else eq = 0;
        return a->op == OP_EQ ? eq : !eq;
    }
    case OP_LT: case OP_LE: case OP_GT: case OP_GE:
        if (!(lnum && rnum)) return 0;
        switch (a->op) {
        case OP_LT: return r.val <  a->val;
        case OP_LE: return r.val <= a->val;
        case OP_GT: return r.val >  a->val;
        default:    return r.val >= a->val;
        }
    case OP_TRUTHY:
        return r.ty == TY_NONE ? 0 : (r.val != 0);
    }
    return 0;
}

static int eval_prog_host(const Image *im, const struct ppt_edge *e, const struct ppt_reg *regs) {
    uint8_t stack[STACK_MAX]; int sp = 0;
    for (int i = 0; i < e->prog_cnt; i++) {
        uint16_t w = im->prog[e->prog_off + i];
        if (w < 0x8000) stack[sp++] = (uint8_t)eval_atom_host(&im->atoms[w], regs, im->n_fields);
        else switch (w) {
        case OPC_NOT:   stack[sp - 1] = !stack[sp - 1]; break;
        case OPC_AND:   sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] && stack[sp]); break;
        case OPC_OR:    sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] || stack[sp]); break;
        case OPC_TRUE:  stack[sp++] = 1; break;
        case OPC_FALSE: stack[sp++] = 0; break;
        default: break;
        }
    }
    return sp > 0 ? stack[0] : 0;
}

static int evaluate_host(const Image *im, uint16_t node, const struct ppt_reg *regs, int *out_target) {
    const struct ppt_node *n = &im->nodes[node];
    for (int i = 0; i < n->edge_cnt; i++) {
        if (eval_prog_host(im, &im->edges[n->edge_off + i], regs)) {
            if (out_target) *out_target = im->edges[n->edge_off + i].target;
            return i;
        }
    }
    return -1;
}

#ifndef NO_LIBBPF
/* Populate the five table maps from a PPT image. Shared by the attach path and the certify path. */
static int populate_maps(struct bpf_object *obj, const Image *im) {
    /* 1. config_map */
    struct bpf_map *config_map = bpf_object__find_map_by_name(obj, "config_map");
    if (config_map) {
        struct ppt_config cfg = {
            .n_fields = im->n_fields, .n_interns = im->n_interns,
            .n_atoms = im->n_atoms,   .n_nodes = im->n_nodes,
            .n_edges = im->n_edges,   .prog_len = im->prog_len,
            .start_node = im->start,  .visits_idx = im->visits_idx,
            .max_steps = im->max_steps, .max_stack = im->max_stack,
        };
        uint32_t key = 0;
        bpf_map_update_elem(bpf_map__fd(config_map), &key, &cfg, BPF_ANY);
    }

    /* 2. atoms_map */
    struct bpf_map *atoms_map = bpf_object__find_map_by_name(obj, "atoms_map");
    if (atoms_map) {
        for (uint32_t i = 0; i < im->n_atoms; i++) {
            bpf_map_update_elem(bpf_map__fd(atoms_map), &i, &im->atoms[i], BPF_ANY);
        }
    }

    /* 3. nodes_map */
    struct bpf_map *nodes_map = bpf_object__find_map_by_name(obj, "nodes_map");
    if (nodes_map) {
        for (uint32_t i = 0; i < im->n_nodes; i++) {
            bpf_map_update_elem(bpf_map__fd(nodes_map), &i, &im->nodes[i], BPF_ANY);
        }
    }

    /* 4. edges_map */
    struct bpf_map *edges_map = bpf_object__find_map_by_name(obj, "edges_map");
    if (edges_map) {
        for (uint32_t i = 0; i < im->n_edges; i++) {
            bpf_map_update_elem(bpf_map__fd(edges_map), &i, &im->edges[i], BPF_ANY);
        }
    }

    /* 5. prog_map */
    struct bpf_map *prog_map = bpf_object__find_map_by_name(obj, "prog_map");
    if (prog_map) {
        for (uint32_t i = 0; i < im->prog_len; i++) {
            bpf_map_update_elem(bpf_map__fd(prog_map), &i, &im->prog[i], BPF_ANY);
        }
    }

    /* 6. bank_map (net program only): a fresh load populates bank 0 above, so select bank 0. */
    struct bpf_map *bank_map = bpf_object__find_map_by_name(obj, "bank_map");
    if (bank_map) {
        uint32_t key = 0, bank0 = 0;
        bpf_map_update_elem(bpf_map__fd(bank_map), &key, &bank0, BPF_ANY);
    }

    return 0;
}

static int populate_and_attach_bpf(const Image *im, const char *ifname) {
    struct bpf_object *obj = bpf_object__open_file("ppt_xdp.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "error: failed to open ppt_xdp.bpf.o. Ensure 'make' compiled the BPF object.\n");
        return -1;
    }

    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "error: failed to load bpf object (err=%d). Root / CAP_BPF required for kernel load.\n", err);
        bpf_object__close(obj);
        return -1;
    }

    populate_maps(obj, im);

    /* Pin result_map so it outlives this process: the smoke test injects a packet (the attached XDP
     * program writes its verdict here) and then reads it back to compare against the host reference. */
    struct bpf_map *result_map = bpf_object__find_map_by_name(obj, "result_map");
    if (result_map) {
        unlink(PIN_PATH);                         /* clear any stale pin from a prior run */
        if (bpf_map__pin(result_map, PIN_PATH) == 0)
            printf("[loader] pinned result_map at %s\n", PIN_PATH);
        else
            fprintf(stderr, "warning: failed to pin result_map at %s\n", PIN_PATH);
    }

    if (ifname) {
        unsigned int ifindex = if_nametoindex(ifname);
        if (ifindex == 0) {
            fprintf(stderr, "error: invalid network interface %s\n", ifname);
            bpf_object__close(obj);
            return -1;
        }
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ppt_xdp_prog");
        if (!prog) {
            fprintf(stderr, "error: program ppt_xdp_prog not found\n");
            bpf_object__close(obj);
            return -1;
        }
        int prog_fd = bpf_program__fd(prog);
        err = bpf_xdp_attach((int)ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (err) {
            fprintf(stderr, "error: bpf_xdp_attach failed on %s (err=%d). Requires root.\n", ifname, err);
            bpf_object__close(obj);
            return -1;
        }
        printf("[loader] Attached XDP program to interface %s (SKB/generic mode).\n", ifname);
    }

    bpf_object__close(obj);
    return 0;
}

/* Read the pinned result_map back (populated by the in-kernel XDP run) so the smoke test can compare
 * the kernel's verdict to the host reference for the same packet. */
static int read_pinned_result(void)
{
    int fd = bpf_obj_get(PIN_PATH);
    if (fd < 0) {
        fprintf(stderr, "error: cannot open pinned result map at %s\n", PIN_PATH);
        return 2;
    }
    __u32 key = 0;
    struct ppt_result r = {0};
    if (bpf_map_lookup_elem(fd, &key, &r) != 0) {
        fprintf(stderr, "error: result map lookup failed\n");
        return 2;
    }
    printf("KERNEL RESULT: matched_edge=%d target_node=%d eval_status=%u pkt_count=%llu\n",
           r.matched_edge, r.target_node, r.eval_status, (unsigned long long)r.pkt_count);
    return 0;
}

/* Certify the eBPF target against a frozen conformance vector set, IN-KERNEL, without a NIC: load the
 * PPT image into the maps, then run each crafted packet through the actual XDP program via
 * BPF_PROG_TEST_RUN and compare the in-kernel target_node to the recorded reference. Requires CAP_BPF.
 * Packet file format (little-endian, repeated): <s32 expected_target><u32 pkt_len><pkt_len bytes>. */
/* Drive a whole flow through the XDP program IN-KERNEL, hop by hop: start at the flow's start node,
 * evaluate it via BPF_PROG_TEST_RUN, follow the matched target, repeat to a terminal. Compares the
 * in-kernel routing path against the host reference (evaluate_host, == interp.c). `names[]` (optional,
 * one node name per line) makes the path human-readable. regs_path is encode_regs format. Root/CAP_BPF. */
static int run_flow(const char *ppt_path, const char *regs_path, char **names, int n_names) {
    Image im; load_image(ppt_path, &im);
    long len; uint8_t *b = read_file(regs_path, &len);
    int nf = im.n_fields;
    struct ppt_reg *regs = calloc(nf ? nf : 1, sizeof(struct ppt_reg));
    for (int i = 0; i < nf; i++) { regs[i].ty = rd32(b + 4 + 8 * i); regs[i].val = rd32(b + 8 + 8 * i); }
    free(b);
    int cap = im.max_steps ? im.max_steps : 64;

    #define NAME(ix) ((names && (ix) >= 0 && (ix) < n_names) ? names[ix] : NULL)
    #define PRINTPATH(arr, cnt) do { for (int i = 0; i < (cnt); i++) { \
            if (NAME(arr[i])) printf("%s%s", NAME(arr[i]), i + 1 < (cnt) ? " -> " : "\n"); \
            else printf("%d%s", arr[i], i + 1 < (cnt) ? " -> " : "\n"); } } while (0)

    /* host reference path */
    int hp[256], hn = 0, cur = im.start; hp[hn++] = cur;
    for (int s = 0; s < cap && im.nodes[cur].edge_cnt; s++) {
        int tgt = -1;
        if (evaluate_host(&im, cur, regs, &tgt) < 0) { printf("  [host stuck]\n"); break; }
        cur = tgt; if (hn < 256) hp[hn++] = cur;
    }

    struct bpf_object *obj = bpf_object__open_file("ppt_xdp.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "error: bpf open/load failed (verifier / CAP_BPF).\n");
        if (obj) bpf_object__close(obj);
        return -1;
    }
    populate_maps(obj, &im);
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ppt_xdp_prog");
    struct bpf_map *result_map = bpf_object__find_map_by_name(obj, "result_map");
    int prog_fd = bpf_program__fd(prog), res_fd = bpf_map__fd(result_map);

    /* in-kernel path */
    int kp[256], kn = 0; cur = im.start; kp[kn++] = cur;
    uint8_t frame[2048], out_buf[2048];
    for (int s = 0; s < cap && im.nodes[cur].edge_cnt; s++) {
        int flen = build_frame(frame, (uint16_t)cur, im.n_fields, regs);
        struct bpf_test_run_opts opts; memset(&opts, 0, sizeof(opts));
        opts.sz = sizeof(opts); opts.data_in = frame; opts.data_size_in = flen;
        opts.data_out = out_buf; opts.data_size_out = sizeof(out_buf); opts.repeat = 1;
        struct ppt_result r = {0}; __u32 key = 0;
        if (bpf_prog_test_run_opts(prog_fd, &opts) != 0 ||
            bpf_map_lookup_elem(res_fd, &key, &r) != 0 || r.eval_status != 1) {
            printf("  [in-kernel stuck]\n"); break;
        }
        cur = r.target_node; if (kn < 256) kp[kn++] = cur;
    }

    printf("\n[Host reference path (evaluate_host == interp.c)]\n  "); PRINTPATH(hp, hn);
    printf("[In-kernel path (XDP program, hop-by-hop BPF_PROG_TEST_RUN)]\n  "); PRINTPATH(kp, kn);
    int same = (hn == kn); for (int i = 0; i < hn && same; i++) same = (hp[i] == kp[i]);
    printf("\n%s: the flow routed IN-KERNEL along the same path as the reference.\n",
           same ? "PASS" : "FAIL");
    free(regs); bpf_object__close(obj);
    return same ? 0 : 1;
}

/* Trace a flow to a terminal using the host reference evaluator (== interp.c). Fills out[] with the
 * node-index path, returns its length. */
static int host_trace(const Image *im, const struct ppt_reg *regs, int *out, int cap) {
    int n = 0, cur = im->start; out[n++] = cur;
    int lim = im->max_steps ? im->max_steps : 64;
    for (int s = 0; s < lim && im->nodes[cur].edge_cnt; s++) {
        int tgt = -1;
        if (evaluate_host(im, cur, regs, &tgt) < 0) break;
        cur = tgt; if (n < cap) out[n++] = cur;
    }
    return n;
}

/* Trace a flow to a terminal IN-KERNEL: evaluate each node via BPF_PROG_TEST_RUN, follow the target. */
static int kernel_trace(const Image *im, const struct ppt_reg *regs, int prog_fd, int res_fd,
                        int *out, int cap) {
    int n = 0, cur = im->start; out[n++] = cur;
    int lim = im->max_steps ? im->max_steps : 64;
    uint8_t frame[2048], ob[2048];
    for (int s = 0; s < lim && im->nodes[cur].edge_cnt; s++) {
        int flen = build_frame(frame, (uint16_t)cur, im->n_fields, regs);
        struct bpf_test_run_opts o; memset(&o, 0, sizeof(o)); o.sz = sizeof(o);
        o.data_in = frame; o.data_size_in = flen; o.data_out = ob; o.data_size_out = sizeof(ob);
        o.repeat = 1;
        struct ppt_result r = {0}; __u32 k = 0;
        if (bpf_prog_test_run_opts(prog_fd, &o) != 0 ||
            bpf_map_lookup_elem(res_fd, &k, &r) != 0 || r.eval_status != 1) break;
        cur = r.target_node; if (n < cap) out[n++] = cur;
    }
    return n;
}

/* Batch: route MANY register files (one per REAL alert) through the SAME flow table in-kernel, each
 * hop-by-hop, and confirm each path matches the host reference. One BPF load for the whole batch.
 * Record format (LE): <u32 reg_len><reg_len bytes of ppt_reg[]>  (reg_len = n_fields * 8). */
static int runbatch_flow(const char *ppt_path, const char *records_path, char **names, int n_names) {
    Image im; load_image(ppt_path, &im);
    struct bpf_object *obj = bpf_object__open_file("ppt_xdp.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "error: bpf open/load failed (verifier / CAP_BPF).\n");
        if (obj) bpf_object__close(obj);
        return -1;
    }
    populate_maps(obj, &im);
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ppt_xdp_prog");
    struct bpf_map *rm = bpf_object__find_map_by_name(obj, "result_map");
    int prog_fd = bpf_program__fd(prog), res_fd = bpf_map__fd(rm);

    long flen; uint8_t *buf = read_file(records_path, &flen);
    int nf = im.n_fields;
    struct ppt_reg *regs = calloc(nf ? nf : 1, sizeof(struct ppt_reg));
    long off = 0; int total = 0, passed = 0;

    printf("\n[Real alerts -> eBPF router IN-KERNEL, hop-by-hop, vs host reference]\n");
    while (off + 4 <= flen) {
        uint32_t rlen = rd32(buf + off); off += 4;
        if (off + (long)rlen > flen) break;
        int cnt = (int)(rlen / 8);
        for (int i = 0; i < nf; i++) {
            if (i < cnt) { regs[i].ty = rd32(buf + off + 8 * i); regs[i].val = rd32(buf + off + 8 * i + 4); }
            else { regs[i].ty = 0; regs[i].val = 0; }
        }
        off += rlen;
        total++;
        int hp[256], kp[256];
        int hn = host_trace(&im, regs, hp, 256);
        int kn = kernel_trace(&im, regs, prog_fd, res_fd, kp, 256);
        int same = (hn == kn); for (int i = 0; i < hn && same; i++) same = (hp[i] == kp[i]);
        passed += same;
        printf("  alert %3d [%s]  ", total, same ? "PASS" : "FAIL");
        for (int i = 0; i < kn; i++) {
            const char *nm = (names && kp[i] >= 0 && kp[i] < n_names) ? names[kp[i]] : NULL;
            if (nm) printf("%s%s", nm, i + 1 < kn ? " -> " : "\n");
            else printf("%d%s", kp[i], i + 1 < kn ? " -> " : "\n");
        }
    }
    free(regs); free(buf); bpf_object__close(obj);
    printf("\neBPF vs reference: %d/%d REAL alerts routed identically in-kernel.\n", passed, total);
    return (total > 0 && passed == total) ? 0 : 1;
}

static int certify_bpf(const char *packets_path) {
    struct bpf_object *obj = bpf_object__open_file("ppt_xdp.bpf.o", NULL);
    if (!obj) { fprintf(stderr, "error: failed to open ppt_xdp.bpf.o (run 'make').\n"); return -1; }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "error: bpf load failed (verifier / CAP_BPF).\n");
        bpf_object__close(obj); return -1;
    }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ppt_xdp_prog");
    struct bpf_map *result_map = bpf_object__find_map_by_name(obj, "result_map");
    if (!prog || !result_map) {
        fprintf(stderr, "error: ppt_xdp_prog / result_map not found in object.\n");
        bpf_object__close(obj); return -1;
    }
    int prog_fd = bpf_program__fd(prog);
    int res_fd = bpf_map__fd(result_map);

    long flen = 0; uint8_t *buf = read_file(packets_path, &flen);

    /* Each vector carries its OWN compiled table (predicates each compile to a distinct PPT), so the
     * maps are repopulated per vector before the in-kernel run. The BPF program bounds every access by
     * config_map's counts, so stale higher-index map entries from a larger prior table are never read.
     * Record format (LE): <s32 expected_target><u32 tbl_len><tbl><u32 pkt_len><pkt>. */
    printf("\n[eBPF in-kernel conformance — BPF_PROG_TEST_RUN, table-per-vector]\n");
    long off = 0; int total = 0, passed = 0, first_fail = -1;
    uint8_t out_buf[2048];
    while (off + 4 <= flen) {
        int32_t expected = (int32_t)rd32(buf + off); off += 4;
        if (off + 4 > flen) break;
        uint32_t tbl_len = rd32(buf + off); off += 4;
        if (off + (long)tbl_len > flen) break;
        const uint8_t *tbl = buf + off; off += tbl_len;
        if (off + 4 > flen) break;
        uint32_t pkt_len = rd32(buf + off); off += 4;
        if (off + (long)pkt_len > flen) break;
        uint8_t *pkt = buf + off; off += pkt_len;
        total++;

        Image im; memset(&im, 0, sizeof(im));
        if (parse_image_buf(tbl, tbl_len, &im) != 0) {
            printf("  vector %3d: BAD TABLE (%u B)\n", total, tbl_len);
            if (first_fail < 0) first_fail = total;
            continue;
        }
        populate_maps(obj, &im);

        struct bpf_test_run_opts opts;
        memset(&opts, 0, sizeof(opts));
        opts.sz = sizeof(opts);
        opts.data_in = pkt; opts.data_size_in = pkt_len;
        opts.data_out = out_buf; opts.data_size_out = sizeof(out_buf);
        opts.repeat = 1;
        int err = bpf_prog_test_run_opts(prog_fd, &opts);
        struct ppt_result r = {0}; __u32 key = 0;
        if (err == 0) bpf_map_lookup_elem(res_fd, &key, &r);
        int got = (err == 0) ? r.target_node : -2;
        int ok = (got == expected);
        passed += ok;
        if (!ok) {
            printf("  vector %3d: FAIL  expected target=%d  in-kernel=%d (edge=%d status=%u ret=%u err=%d)\n",
                   total, expected, got, r.matched_edge, r.eval_status, opts.retval, err);
            if (first_fail < 0) first_fail = total;
        }
        free_image(&im);
    }
    free(buf);
    bpf_object__close(obj);
    if (total == 0) { fprintf(stderr, "error: no vectors read from %s\n", packets_path); return 2; }
    printf("\neBPF in-kernel conformance: %d/%d vectors match the reference.\n", passed, total);
    if (first_fail >= 0) printf("  (first mismatch at vector %d)\n", first_fail);
    else printf("  ALL PASS — every in-fragment vector routed identically in-kernel and by the reference.\n");
    return (passed == total) ? 0 : 1;
}

/* Attach the REAL-packet program (ppt_net.bpf.o) to a live interface, observe-only (it only ever
 * returns XDP_PASS). Populates the PPT table from <ppt>, pins the verdict + result maps so `netstats`
 * can read them after this process exits, and attaches in SKB/generic mode (works on veth/gretap). */
/* Derive the drop-node bitmask from the node-name sidecar (a node named "drop" or "block" => XDP_DROP)
 * and write it into config_map[0].drop_mask. names_path may be NULL => observe-only (mask stays 0).
 * Covers node indices 0-63 (the net program bounds the shift). */
static void config_set_drop_mask(struct bpf_object *obj, const char *names_path) {
    if (!names_path) { printf("[loader] observe-only (no names sidecar given)\n"); return; }
    long nlen; uint8_t *nb = read_file(names_path, &nlen);
    if (!nb) { printf("[loader] observe-only (names sidecar unreadable)\n"); return; }
    __u64 mask = 0; __u32 idx = 0;
    for (char *tok = strtok((char *)nb, "\r\n"); tok; tok = strtok(NULL, "\r\n")) {
        if (idx < 64 && (strcmp(tok, "drop") == 0 || strcmp(tok, "block") == 0)) mask |= (1ULL << idx);
        idx++;
    }
    free(nb);
    struct bpf_map *cm = bpf_object__find_map_by_name(obj, "config_map");
    __u32 key = 0; struct ppt_config cfg;
    if (cm && bpf_map_lookup_elem(bpf_map__fd(cm), &key, &cfg) == 0) {
        cfg.drop_mask = mask;
        bpf_map_update_elem(bpf_map__fd(cm), &key, &cfg, BPF_ANY);
    }
    if (mask) printf("[loader] INLINE ENFORCEMENT on: drop_mask=0x%llx (drop/block decision nodes)\n",
                     (unsigned long long)mask);
    else printf("[loader] observe-only (no drop/block node in this flow)\n");
}

static int net_attach(const char *ppt_path, const char *ifname, const char *names_path) {
    Image im; load_image(ppt_path, &im);
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) { fprintf(stderr, "error: no such interface %s\n", ifname); return 2; }

    struct bpf_object *obj = bpf_object__open_file("ppt_net.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "error: open/load ppt_net.bpf.o failed (verifier / CAP_BPF).\n");
        if (obj) bpf_object__close(obj);
        return -1;
    }
    populate_maps(obj, &im);
    config_set_drop_mask(obj, names_path);

    struct bpf_map *vmap = bpf_object__find_map_by_name(obj, "verdict_map");
    struct bpf_map *rmap = bpf_object__find_map_by_name(obj, "result_map");
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ppt_net_prog");
    if (!vmap || !rmap || !prog) {
        fprintf(stderr, "error: ppt_net program/maps not found.\n");
        bpf_object__close(obj); return -1;
    }
    unlink(NET_VERDICT_PIN); unlink(NET_RESULT_PIN);
    if (bpf_map__pin(vmap, NET_VERDICT_PIN) || bpf_map__pin(rmap, NET_RESULT_PIN)) {
        fprintf(stderr, "warning: could not pin net maps (netstats may not find them)\n");
    }
    /* zero the histogram so counts reflect this attach only */
    int vfd = bpf_map__fd(vmap);
    for (__u32 k = 0; k < MAX_NODES; k++) { __u64 z = 0; bpf_map_update_elem(vfd, &k, &z, BPF_ANY); }

    int err = bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "error: bpf_xdp_attach on %s failed (err=%d)\n", ifname, err);
        bpf_object__close(obj); return -1;
    }
    /* The attach holds a ref on the iface; the pinned maps keep the histogram readable after we exit. */
    bpf_object__close(obj);
    printf("OK: ppt_net attached to %s (SKB mode). Read counts with:\n", ifname);
    printf("     sudo ./loader netstats %s <names>\n", ifname);
    return 0;
}

/* Read the pinned per-target histogram + total. Observe-only output over whatever real traffic the
 * attached program has classified so far. */
static int net_stats(char **names, int n_names) {
    int vfd = bpf_obj_get(NET_VERDICT_PIN);
    int rfd = bpf_obj_get(NET_RESULT_PIN);
    if (vfd < 0 || rfd < 0) {
        fprintf(stderr, "error: net maps not pinned — attach first (loader netattach <ppt> <iface>)\n");
        return 2;
    }
    __u32 zero = 0; struct ppt_result res = {0};
    bpf_map_lookup_elem(rfd, &zero, &res);
    printf("\n[ppt_net — real-traffic classification histogram]\n");
    __u64 total = 0;
    for (__u32 k = 0; k < MAX_NODES; k++) {
        __u64 c = 0;
        if (bpf_map_lookup_elem(vfd, &k, &c) != 0 || c == 0) continue;
        const char *nm = (names && k < (unsigned)n_names) ? names[k]
                        : (k == MAX_NODES - 1 ? "(no-match)" : NULL);
        if (nm) printf("  %-14s %llu\n", nm, (unsigned long long)c);
        else    printf("  node[%u]        %llu\n", k, (unsigned long long)c);
        total += c;
    }
    printf("  ----\n  total classified: %llu packets  (result_map pkt_count=%llu)\n",
           (unsigned long long)total, (unsigned long long)res.pkt_count);
    return 0;
}

/* Build a real (non-PPT) Ethernet+IPv4+L4 frame for benchmarking the parser+eval path. */
static int build_ip_frame(uint8_t *out, uint8_t proto, uint16_t dport, int app_bytes) {
    int l4 = (proto == 6) ? 20 : (proto == 17) ? 8 : 8;   /* tcp / udp / icmp header */
    int tot = 20 + l4 + app_bytes;
    uint8_t *p = out;
    memset(p, 0xff, 6); p += 6; memset(p, 0x02, 6); p += 6; *p++ = 0x08; *p++ = 0x00;   /* eth ipv4 */
    *p++ = 0x45; *p++ = 0; *p++ = (uint8_t)(tot >> 8); *p++ = (uint8_t)tot;              /* ip */
    *p++ = 0x00; *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 64; *p++ = proto; *p++ = 0; *p++ = 0;
    *p++ = 192; *p++ = 168; *p++ = 1; *p++ = 50;  *p++ = 192; *p++ = 168; *p++ = 1; *p++ = 60;
    if (proto == 6) {                                    /* tcp */
        *p++ = 0x30; *p++ = 0x39; *p++ = (uint8_t)(dport >> 8); *p++ = (uint8_t)dport;
        memset(p, 0, 8); p += 8;                          /* seq + ack */
        *p++ = 0x50; *p++ = 0x18;                         /* data offset 5, flags PSH|ACK */
        *p++ = 0xff; *p++ = 0xff; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
    } else if (proto == 17) {                            /* udp */
        int ul = 8 + app_bytes;
        *p++ = 0x30; *p++ = 0x39; *p++ = (uint8_t)(dport >> 8); *p++ = (uint8_t)dport;
        *p++ = (uint8_t)(ul >> 8); *p++ = (uint8_t)ul; *p++ = 0; *p++ = 0;
    } else {                                             /* icmp echo */
        *p++ = 8; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
    }
    for (int i = 0; i < app_bytes; i++) *p++ = 0x41;
    return (int)(p - out);
}

/* Benchmark the real-packet path: for representative classes, BPF_PROG_TEST_RUN with a large repeat and
 * report the kernel-measured average ns/packet (parse + Level M eval) and the implied packet rate. */
static int net_bench(const char *ppt_path) {
    Image im; load_image(ppt_path, &im);
    struct bpf_object *obj = bpf_object__open_file("ppt_net.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "error: open/load ppt_net.bpf.o failed (verifier / CAP_BPF).\n");
        if (obj) bpf_object__close(obj);
        return -1;
    }
    populate_maps(obj, &im);
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ppt_net_prog");
    if (!prog) { fprintf(stderr, "error: ppt_net_prog not found\n"); bpf_object__close(obj); return -1; }
    int prog_fd = bpf_program__fd(prog);

    struct { const char *name; uint8_t proto; uint16_t dport; int app; } cases[] = {
        {"https (tcp/443)", 6, 443, 100},
        {"dns   (udp/53)",  17, 53, 60},
        {"icmp  (proto 1)", 1, 0, 56},
        {"jumbo (tcp/443)", 6, 443, 1400},
        {"other (tcp/9999)",6, 9999, 100},
    };
    const int REPEAT = 1000000;
    uint8_t frame[2048], out_buf[2048];
    printf("\n[ppt_net per-packet latency — BPF_PROG_TEST_RUN x %d, kernel-measured]\n", REPEAT);
    for (unsigned c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        int flen = build_ip_frame(frame, cases[c].proto, cases[c].dport, cases[c].app);
        struct bpf_test_run_opts opts; memset(&opts, 0, sizeof(opts));
        opts.sz = sizeof(opts);
        opts.data_in = frame; opts.data_size_in = flen;
        opts.data_out = out_buf; opts.data_size_out = sizeof(out_buf);
        opts.repeat = REPEAT;
        int err = bpf_prog_test_run_opts(prog_fd, &opts);
        if (err) { printf("  %-16s ERROR err=%d\n", cases[c].name, err); continue; }
        double ns = (double)opts.duration;                /* kernel returns avg ns per run */
        double mpps = ns > 0 ? 1000.0 / ns : 0;           /* million packets/sec on one core */
        printf("  %-16s %7.1f ns/pkt   ~%.2f Mpps/core   (xdp_ret=%u, %d B)\n",
               cases[c].name, ns, mpps, opts.retval, flen);
    }
    bpf_object__close(obj);
    return 0;
}

/* ---- double-buffered live hot-swap ------------------------------------------------------------
 * The old element-wise repopulate rewrote the ACTIVE table in place, so a packet mid-swap could
 * read a torn mix of old and new rows. Now the swap writes the INACTIVE bank in full and commits
 * with a single atomic store to bank_map — a packet sees the old table whole or the new table
 * whole. `nfd` collects the map fds of the live program by name so we can address each by bank. */
struct net_maps { int atoms, nodes, edges, prog, config, bank, verdict; };

#define BANK_UPD(fd, base, i, val_ptr, mapname)                                                 \
    do { __u32 _k = (base) + (i);                                                               \
         if (bpf_map_update_elem((fd), &_k, (val_ptr), BPF_ANY) != 0) {                         \
             fprintf(stderr, "netupdate: %s bank write failed at %u: %s\n",                     \
                     (mapname), _k, strerror(errno)); return -1; }                              \
    } while (0)

/* Write the whole image into `bank` of the live maps. Returns 0 on success, -1 on any write error
 * (a partial inactive-bank write is safe — it is never committed — but we still abort loudly). */
static int write_bank(const struct net_maps *m, __u32 bank, const Image *im) {
    __u32 ba = bank * MAX_ATOMS, bn = bank * MAX_NODES,
          be = bank * MAX_EDGES, bp = bank * MAX_PROG_WORDS;
    for (__u32 i = 0; i < im->n_atoms; i++) BANK_UPD(m->atoms, ba, i, &im->atoms[i], "atoms_map");
    for (__u32 i = 0; i < im->n_nodes; i++) BANK_UPD(m->nodes, bn, i, &im->nodes[i], "nodes_map");
    for (__u32 i = 0; i < im->n_edges; i++) BANK_UPD(m->edges, be, i, &im->edges[i], "edges_map");
    for (__u32 i = 0; i < im->prog_len; i++) BANK_UPD(m->prog, bp, i, &im->prog[i], "prog_map");

    /* per-bank config: full struct into config_map[bank], carrying drop_mask from the active bank */
    struct ppt_config cfg = {
        .n_fields = im->n_fields, .n_interns = im->n_interns, .n_atoms = im->n_atoms,
        .n_nodes = im->n_nodes, .n_edges = im->n_edges, .prog_len = im->prog_len,
        .start_node = im->start, .visits_idx = im->visits_idx,
        .max_steps = im->max_steps, .max_stack = im->max_stack };
    __u32 active = bank ^ 1u;
    struct ppt_config old;
    if (bpf_map_lookup_elem(m->config, &active, &old) == 0) cfg.drop_mask = old.drop_mask;
    if (bpf_map_update_elem(m->config, &bank, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "netupdate: config_map[%u] write failed: %s\n", bank, strerror(errno));
        return -1;
    }
    return 0;
}

/* Hot-swap the policy of the LIVE program attached to <iface> with a fresh compiled table
 * (<new.ppt>) — NO detach, NO reload. Writes the inactive bank in full, then flips bank_map in a
 * single atomic store: the packet after the flip routes by the new policy, and no packet ever
 * observes a torn table. */
static int net_update(const char *new_ppt, const char *ifname) {
    unsigned int ifindex = if_nametoindex(ifname);
    if (!ifindex) { fprintf(stderr, "error: no such interface %s\n", ifname); return 2; }
    __u32 prog_id = 0;
    if (bpf_xdp_query_id(ifindex, XDP_FLAGS_SKB_MODE, &prog_id) || !prog_id) {
        fprintf(stderr, "error: no XDP program attached to %s — netattach first.\n", ifname);
        return 2;
    }
    int prog_fd = bpf_prog_get_fd_by_id(prog_id);
    if (prog_fd < 0) { fprintf(stderr, "error: cannot open prog id %u\n", prog_id); return -1; }

    __u32 map_ids[32] = {0};
    struct bpf_prog_info pinfo; memset(&pinfo, 0, sizeof(pinfo));
    pinfo.nr_map_ids = 32; pinfo.map_ids = (__u64)(unsigned long)map_ids;
    __u32 len = sizeof(pinfo);
    if (bpf_obj_get_info_by_fd(prog_fd, &pinfo, &len)) {
        fprintf(stderr, "error: cannot read prog info\n"); close(prog_fd); return -1;
    }

    /* collect the live map fds by name */
    struct net_maps m = { -1, -1, -1, -1, -1, -1, -1 };
    for (__u32 i = 0; i < pinfo.nr_map_ids; i++) {
        int mfd = bpf_map_get_fd_by_id(map_ids[i]);
        if (mfd < 0) continue;
        struct bpf_map_info mi; memset(&mi, 0, sizeof(mi)); __u32 ml = sizeof(mi);
        if (bpf_obj_get_info_by_fd(mfd, &mi, &ml)) { close(mfd); continue; }
        if      (!strcmp(mi.name, "atoms_map"))   m.atoms = mfd;
        else if (!strcmp(mi.name, "nodes_map"))   m.nodes = mfd;
        else if (!strcmp(mi.name, "edges_map"))   m.edges = mfd;
        else if (!strcmp(mi.name, "prog_map"))    m.prog = mfd;
        else if (!strcmp(mi.name, "config_map"))  m.config = mfd;
        else if (!strcmp(mi.name, "bank_map"))    m.bank = mfd;
        else if (!strcmp(mi.name, "verdict_map")) m.verdict = mfd;
        else close(mfd);
    }
    close(prog_fd);
    if (m.atoms < 0 || m.nodes < 0 || m.edges < 0 || m.prog < 0 || m.config < 0 || m.bank < 0) {
        fprintf(stderr, "error: attached program is missing a double-buffer map — rebuild + reattach\n");
        return -1;
    }

    Image im; load_image(new_ppt, &im);

    /* which bank is live now? default 0 if unreadable. Write the OTHER one. */
    __u32 zero = 0, active = 0;
    bpf_map_lookup_elem(m.bank, &zero, &active);
    active &= 1;
    __u32 target = active ^ 1u;

    if (write_bank(&m, target, &im) != 0) {
        /* the inactive bank is never read; abort without touching bank_map — active policy intact */
        fprintf(stderr, "netupdate: aborting — active bank %u still live, no flip performed\n", active);
        free_image(&im);
        return 1;
    }

    /* THE COMMIT: one aligned store flips the active bank atomically. */
    if (bpf_map_update_elem(m.bank, &zero, &target, BPF_ANY) != 0) {
        fprintf(stderr, "netupdate: bank flip failed: %s (active bank %u still live)\n",
                strerror(errno), active);
        free_image(&im);
        return 1;
    }

    /* histogram reset happens AFTER the flip (post-swap counts start clean; a couple of in-flight
     * packets may land in the old bank's buckets, which is honest, not torn). */
    if (m.verdict >= 0)
        for (__u32 i = 0; i < MAX_NODES; i++) { __u64 z = 0; bpf_map_update_elem(m.verdict, &i, &z, BPF_ANY); }

    printf("OK: hot-swapped the LIVE %s policy from %s — bank %u -> %u, NO detach.\n",
           ifname, new_ppt, active, target);
    printf("     table now: %u nodes, %u edges, %u atoms, %u prog-words (atomic double-buffer flip)\n",
           im.n_nodes, im.n_edges, im.n_atoms, im.prog_len);
    free_image(&im);
    return 0;
}

/* ---- swap-storm concurrency proof ------------------------------------------------------------
 * The atomicity claim, tested under adversarial concurrency: preload bank 0 = policy A and
 * bank 1 = policy B (both fully written), spin a thread flipping bank_map 0<->1 as fast as it can,
 * and on the main thread hammer BPF_PROG_TEST_RUN with one probe packet whose verdict differs
 * between A and B. Every observed verdict must be EXACTLY policy A's tuple or policy B's tuple —
 * a torn read (an edge from one bank with a target from the other, or an out-of-range node) would
 * show up as a third value. Zero torn over the storm is the proof the flip is atomic. */
struct storm_flip_arg { int bank_fd; volatile int *stop; unsigned long flips; };

static void *storm_flipper(void *p) {
    struct storm_flip_arg *a = p;
    __u32 zero = 0, b = 0;
    while (!*a->stop) {
        b ^= 1u;
        bpf_map_update_elem(a->bank_fd, &zero, &b, BPF_ANY);
        a->flips++;
    }
    return NULL;
}

static int net_storm(const char *ppt_a, const char *ppt_b) {
    struct bpf_object *obj = bpf_object__open_file("ppt_net.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "error: open/load ppt_net.bpf.o failed (verifier / CAP_BPF).\n");
        if (obj) bpf_object__close(obj);
        return -1;
    }
    /* bank 0 = A (via populate_maps), bank 1 = B (manual) */
    Image a, b; load_image(ppt_a, &a); load_image(ppt_b, &b);
    populate_maps(obj, &a);                 /* writes bank 0 + bank_map=0 */
    struct net_maps m = {
        bpf_map__fd(bpf_object__find_map_by_name(obj, "atoms_map")),
        bpf_map__fd(bpf_object__find_map_by_name(obj, "nodes_map")),
        bpf_map__fd(bpf_object__find_map_by_name(obj, "edges_map")),
        bpf_map__fd(bpf_object__find_map_by_name(obj, "prog_map")),
        bpf_map__fd(bpf_object__find_map_by_name(obj, "config_map")),
        bpf_map__fd(bpf_object__find_map_by_name(obj, "bank_map")),
        bpf_map__fd(bpf_object__find_map_by_name(obj, "verdict_map")),
    };
    if (write_bank(&m, 1, &b) != 0) { bpf_object__close(obj); return -1; }

    /* the probe packet + the two expected verdicts. Run once in each bank (flipper idle) to learn
     * A's and B's ground-truth tuples, so the test is self-calibrating for any A/B pair. */
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ppt_net_prog");
    int prog_fd = bpf_program__fd(prog);
    __u32 zero = 0;
    uint8_t frame[2048], out[2048];
    int flen = build_ip_frame(frame, 6, 443, 64);      /* tcp/443 */
    struct ppt_result rA, rB;
    __u32 zerob = 0, oneb = 1;
    struct bpf_test_run_opts o;
    #define RUN() do { memset(&o,0,sizeof(o)); o.sz=sizeof(o); o.data_in=frame; o.data_size_in=flen; \
                       o.data_out=out; o.data_size_out=sizeof(out); o.repeat=1; \
                       bpf_prog_test_run_opts(prog_fd,&o); } while(0)
    int result_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "result_map"));
    __u32 rk = 0;
    bpf_map_update_elem(m.bank, &zero, &zerob, BPF_ANY); RUN();
    bpf_map_lookup_elem(result_fd, &rk, &rA);
    bpf_map_update_elem(m.bank, &zero, &oneb, BPF_ANY); RUN();
    bpf_map_lookup_elem(result_fd, &rk, &rB);
    printf("[swap-storm] probe tcp/443 -> A(edge=%d,node=%d)  B(edge=%d,node=%d)\n",
           rA.matched_edge, rA.target_node, rB.matched_edge, rB.target_node);
    if (rA.matched_edge == rB.matched_edge && rA.target_node == rB.target_node) {
        fprintf(stderr, "storm: A and B give the same verdict — pick policies that differ on the probe\n");
        bpf_object__close(obj); return 2;
    }

    /* storm */
    volatile int stop = 0;
    struct storm_flip_arg fa = { m.bank, &stop, 0 };
    pthread_t th; pthread_create(&th, NULL, storm_flipper, &fa);

    const int N = 200000;
    long nA = 0, nB = 0, torn = 0;
    for (int i = 0; i < N; i++) {
        RUN();
        struct ppt_result r; __u32 rk = 0;
        bpf_map_lookup_elem(result_fd, &rk, &r);
        if (r.matched_edge == rA.matched_edge && r.target_node == rA.target_node) nA++;
        else if (r.matched_edge == rB.matched_edge && r.target_node == rB.target_node) nB++;
        else { torn++; if (torn <= 5) fprintf(stderr, "  TORN: edge=%d node=%d\n", r.matched_edge, r.target_node); }
    }
    stop = 1; pthread_join(th, NULL);
    #undef RUN

    printf("[swap-storm] %d evaluations under %lu concurrent bank flips: A=%ld B=%ld TORN=%ld\n",
           N, fa.flips, nA, nB, torn);
    printf("%s\n", torn == 0
        ? "\xE2\x9C\x85 ATOMIC: every verdict was a consistent policy; zero torn reads under the storm"
        : "\xE2\x9C\x97 TORN READS OBSERVED — the swap is NOT atomic");
    bpf_object__close(obj); free_image(&a); free_image(&b);
    return torn == 0 ? 0 : 1;
}

static int net_detach(const char *ifname) {
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) { fprintf(stderr, "error: no such interface %s\n", ifname); return 2; }
    int err = bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    unlink(NET_VERDICT_PIN); unlink(NET_RESULT_PIN);
    if (err) fprintf(stderr, "warning: detach returned %d\n", err);
    else printf("OK: ppt_net detached from %s, pins removed.\n", ifname);
    return err ? 1 : 0;
}
#endif

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <image.ppt> [ifname] [input_regs.bin]\n", argv[0]);
        printf("       %s <image.ppt> readresult\n", argv[0]);
        printf("       %s <image.ppt> certify <packets.bin>   (in-kernel conformance; root)\n", argv[0]);
        return 2;
    }

    const char *ppt_path = argv[1];
    const char *ifname = (argc >= 3 && strlen(argv[2]) > 0) ? argv[2] : NULL;
    const char *regs_path = (argc >= 4) ? argv[3] : NULL;

#ifndef NO_LIBBPF
    if (argc >= 3 && strcmp(argv[2], "readresult") == 0)
        return read_pinned_result();

    if (argc >= 4 && strcmp(argv[2], "certify") == 0) {
        if (getuid() != 0) {
            fprintf(stderr, "error: 'certify' loads the program into the kernel — run as root / CAP_BPF.\n");
            return 2;
        }
        /* Each vector in the corpus file carries its own compiled table; argv[1] (ppt) is unused here. */
        return certify_bpf(argv[3]);
    }

    if (argc >= 4 && strcmp(argv[2], "run") == 0) {
        if (getuid() != 0) {
            fprintf(stderr, "error: 'run' loads the program into the kernel — run as root / CAP_BPF.\n");
            return 2;
        }
        char **names = NULL; int n_names = 0;
        if (argc >= 5) {                                  /* optional: one node name per line, index order */
            long nlen; uint8_t *nb = read_file(argv[4], &nlen);
            names = malloc(sizeof(char *) * 512);
            for (char *tok = strtok((char *)nb, "\r\n"); tok && n_names < 512;
                 tok = strtok(NULL, "\r\n"))
                names[n_names++] = strdup(tok);
            free(nb);
        }
        return run_flow(ppt_path, argv[3], names, n_names);
    }

    if (argc >= 4 && strcmp(argv[2], "runbatch") == 0) {
        if (getuid() != 0) {
            fprintf(stderr, "error: 'runbatch' loads the program into the kernel — run as root / CAP_BPF.\n");
            return 2;
        }
        char **names = NULL; int n_names = 0;
        if (argc >= 5) {
            long nlen; uint8_t *nb = read_file(argv[4], &nlen);
            names = malloc(sizeof(char *) * 512);
            for (char *tok = strtok((char *)nb, "\r\n"); tok && n_names < 512;
                 tok = strtok(NULL, "\r\n"))
                names[n_names++] = strdup(tok);
            free(nb);
        }
        return runbatch_flow(ppt_path, argv[3], names, n_names);
    }

    if (argc >= 4 && strcmp(argv[2], "netattach") == 0) {
        if (getuid() != 0) { fprintf(stderr, "error: 'netattach' needs root / CAP_BPF.\n"); return 2; }
        return net_attach(ppt_path, argv[3], argc >= 5 ? argv[4] : NULL);  /* loader <ppt> netattach <iface> [names] */
    }
    if (argc >= 3 && strcmp(argv[2], "netstats") == 0) {
        if (getuid() != 0) { fprintf(stderr, "error: 'netstats' needs root / CAP_BPF.\n"); return 2; }
        char **names = NULL; int n_names = 0;
        if (argc >= 4) {                                 /* loader <x> netstats <names> */
            long nlen; uint8_t *nb = read_file(argv[3], &nlen);
            names = malloc(sizeof(char *) * 512);
            for (char *tok = strtok((char *)nb, "\r\n"); tok && n_names < 512; tok = strtok(NULL, "\r\n"))
                names[n_names++] = strdup(tok);
            free(nb);
        }
        return net_stats(names, n_names);
    }
    if (argc >= 4 && strcmp(argv[2], "netdetach") == 0) {
        if (getuid() != 0) { fprintf(stderr, "error: 'netdetach' needs root / CAP_BPF.\n"); return 2; }
        return net_detach(argv[3]);                      /* loader <x> netdetach <iface> */
    }
    if (argc >= 3 && strcmp(argv[2], "netbench") == 0) {
        if (getuid() != 0) { fprintf(stderr, "error: 'netbench' needs root / CAP_BPF.\n"); return 2; }
        return net_bench(ppt_path);                      /* loader <ppt> netbench */
    }
    if (argc >= 4 && strcmp(argv[2], "netupdate") == 0) {
        if (getuid() != 0) { fprintf(stderr, "error: 'netupdate' needs root / CAP_BPF.\n"); return 2; }
        return net_update(ppt_path, argv[3]);            /* loader <new.ppt> netupdate <iface> */
    }
    if (argc >= 4 && strcmp(argv[2], "netstorm") == 0) {  /* loader <a.ppt> netstorm <b.ppt> */
        if (getuid() != 0) { fprintf(stderr, "error: 'netstorm' needs root / CAP_BPF.\n"); return 2; }
        return net_storm(ppt_path, argv[3]);
    }
#endif

    Image im;
    load_image(ppt_path, &im);

    printf("=====================================================\n");
    printf("  PrismPath PPT v1 Table Loader & Semantics Checker  \n");
    printf("=====================================================\n");
    printf("Image File : %s\n", ppt_path);
    printf("Atoms      : %u\n", im.n_atoms);
    printf("Nodes      : %u\n", im.n_nodes);
    printf("Edges      : %u\n", im.n_edges);
    printf("Prog Length: %u words\n", im.prog_len);
    printf("Fields     : %u\n", im.n_fields);
    printf("Start Node : %u\n", im.start);

    if (regs_path) {
        long len; uint8_t *b = read_file(regs_path, &len);
        if (len == 4 + 8L * im.n_fields) {
            uint16_t node = (uint16_t)rd32(b);
            struct ppt_reg *regs = malloc(sizeof(struct ppt_reg) * (im.n_fields ? im.n_fields : 1));
            for (int i = 0; i < im.n_fields; i++) {
                regs[i].ty = rd32(b + 4 + 8 * i);
                regs[i].val = rd32(b + 8 + 8 * i);
            }
            int target = -1;
            int matched_edge = evaluate_host(&im, node, regs, &target);
            printf("\n[Host Semantics Reference Match]\n");
            if (matched_edge >= 0) {
                printf("  Matched Edge Index : %d\n", matched_edge);
                printf("  Target Node Index  : %d\n", target);
            } else {
                printf("  Matched Edge Index : none (stuck)\n");
            }
            free(regs);
        }
        free(b);
    }

    int load_rc = 0;
#ifndef NO_LIBBPF
    printf("\n[BPF Kernel Load Path]\n");
    if (getuid() != 0) {
        printf("NOTICE: Running as non-root user (uid=%d).\n", getuid());
        printf("        Loading eBPF maps/programs into kernel requires root / CAP_BPF.\n");
        printf("        Host-side validation completed successfully.\n");
    } else {
        /* Propagate the real load/attach result as the process exit code so callers (smoke.sh, CI)
         * get an honest pass/fail without parsing the verifier log. */
        load_rc = populate_and_attach_bpf(&im, ifname);
        if (load_rc == 0 && ifname && ifname[0])
            printf("OK: XDP program loaded (verifier passed) and attached to %s.\n", ifname);
    }
#else
    (void)ifname;
    printf("\n[BPF Kernel Load Path]\n");
    printf("NOTICE: Compiled without libbpf (-DNO_LIBBPF).\n");
    printf("        Host-side validation completed successfully.\n");
    printf("        When libbpf-dev is installed, re-run 'make' to enable kernel map loading & XDP attachment.\n");
#endif

    printf("=====================================================\n");
    return load_rc ? 1 : 0;
}
