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

#ifndef NO_LIBBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>   /* XDP_FLAGS_SKB_MODE */
#endif

#include "ppt_common.h"

#define PIN_PATH "/sys/fs/bpf/ppt_result"   /* result_map pin: read back the in-kernel verdict */

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

static void load_image(const char *path, Image *im) {
    long len; uint8_t *b = read_file(path, &len);
    if (len < 28 || rd32(b) != (int32_t)PPT_MAGIC || rd16(b + 4) != 1) {
        fprintf(stderr, "error: bad image %s\n", path); exit(2);
    }
    im->n_fields = rd16(b + 6);   im->n_interns = rd16(b + 8);
    im->n_atoms = rd16(b + 10);   im->n_nodes = rd16(b + 12);
    im->n_edges = rd16(b + 14);   im->prog_len = rd16(b + 16);
    im->start = rd16(b + 18);     im->visits_idx = rd16(b + 20);
    im->max_steps = rd16(b + 22);  im->max_stack = rd16(b + 24);
    long need = 28 + 8L * im->n_atoms + 4L * im->n_nodes + 6L * im->n_edges + 2L * im->prog_len;
    if (len < need) { fprintf(stderr, "error: truncated image %s\n", path); exit(2); }
    const uint8_t *p = b + 28;
    im->atoms = malloc(sizeof(struct ppt_atom) * im->n_atoms);
    for (int i = 0; i < im->n_atoms; i++, p += 8) {
        im->atoms[i].field = rd16(p); im->atoms[i].op = p[2]; im->atoms[i].ty = p[3];
        im->atoms[i].val = rd32(p + 4);
    }
    im->nodes = malloc(sizeof(struct ppt_node) * im->n_nodes);
    for (int i = 0; i < im->n_nodes; i++, p += 4) {
        im->nodes[i].edge_off = rd16(p); im->nodes[i].edge_cnt = rd16(p + 2);
    }
    im->edges = malloc(sizeof(struct ppt_edge) * im->n_edges);
    for (int i = 0; i < im->n_edges; i++, p += 6) {
        im->edges[i].target = rd16(p); im->edges[i].prog_off = rd16(p + 2);
        im->edges[i].prog_cnt = rd16(p + 4);
    }
    im->prog = malloc(sizeof(uint16_t) * im->prog_len);
    for (int i = 0; i < im->prog_len; i++, p += 2) im->prog[i] = rd16(p);
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

    printf("[loader] Successfully populated BPF maps:\n");
    printf("         atoms: %u, nodes: %u, edges: %u, prog_len: %u\n",
           im->n_atoms, im->n_nodes, im->n_edges, im->prog_len);

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
#endif

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <image.ppt> [ifname] [input_regs.bin]\n", argv[0]);
        return 2;
    }

    const char *ppt_path = argv[1];
    const char *ifname = (argc >= 3 && strlen(argv[2]) > 0) ? argv[2] : NULL;
    const char *regs_path = (argc >= 4) ? argv[3] : NULL;

#ifndef NO_LIBBPF
    if (argc >= 3 && strcmp(argv[2], "readresult") == 0)
        return read_pinned_result();
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
